# fastly-blocklist CLI design

Date: 2026-08-08
Status: implemented

## Problem

Blocking an IP in front of Adobe Commerce means clicking through the Magento admin's Fastly Blocking page. That is slow for incident response and impossible to script, cron, or drive from Ansible.

## Approach

A single-file Python 3 CLI that edits the Fastly Edge ACL directly through `api.fastly.com`.

Fastly ACL entries are versionless. Adding or removing one takes effect within seconds with no version clone, no activate, and no purge. The `fastly/fastly-magento2` module reads the same ACL from its VCL snippet, so the CLI and the Magento admin UI stay in sync in both directions with no extra work.

Rejected alternatives:

- **Through the Magento admin REST API.** The module's blocking endpoints are admin-controller-only in most versions, awkward to script, and add a dependency on Magento being up during an incident, which is exactly when it may not be.
- **Editing the VCL snippet directly.** Requires clone plus activate on every change, is slower, and fights with the module.

## Stack

Python 3.7+, stdlib only. Matches the existing `cc_linear.py` pattern: drop the file on a host and run it, no pip install, no node_modules, nothing to build.

## Components

Single module, `fastly_blocklist.py`, four separable pieces:

| Piece | Responsibility | Depends on |
|-------|----------------|------------|
| `Settings` / `resolve_settings` | Merge flags, env vars, and ini file into one credentials object | `configparser`, `os.environ` |
| `FastlyClient` | HTTP transport, auth, pagination, error translation | `urllib` |
| Address helpers | Parse, normalize, compare, and safety-check IPs and CIDRs | `ipaddress` |
| Commands | `list` / `add` / `remove` / `acls`, formatting, exit codes | the three above |

Commands take a client as an argument rather than constructing one, so they test against a fake with no network and no credentials.

## Config resolution

First hit wins: CLI flags, then `FASTLY_API_TOKEN` / `FASTLY_SERVICE_ID` / `FASTLY_ACL_NAME`, then the `--env NAME` config section, then the config `[defaults]` section.

Config file search order: `$FASTLY_BLOCKLIST_CONFIG`, `~/.config/fastly-blocklist/config.ini`, `./config.ini`.

Named sections support prod and staging service IDs side by side.

## Commands

```
fastly-blocklist list [--format table|json|csv] [--grep TEXT]
fastly-blocklist add IP|CIDR --label TEXT [--update] [--force] [--dry-run]
fastly-blocklist remove IP|CIDR [--dry-run]
fastly-blocklist acls
```

The label is stored in the ACL entry's `comment` field, the same field the Magento admin displays.

`remove` and `acls` were added beyond the original list-plus-add request. A blocklist you cannot un-block generates support tickets, and `acls` lets an operator verify the ACL name on a real service before trusting the default.

## API flow

1. `GET /service/{sid}/version` → the version with `active: true`, falling back to the highest number
2. `GET /service/{sid}/version/{v}/acl/{name}` → the ACL id
3. `GET /service/{sid}/acl/{acl_id}/entries?page=N&per_page=100` → paginate until a short page
4. `POST /service/{sid}/acl/{acl_id}/entry` with `{ip, subnet, negated, comment}`
5. `PATCH .../entry/{id}` to relabel, `DELETE .../entry/{id}` to remove

Auth is the `Fastly-Key` header. Steps 3 through 5 are versionless.

`subnet` is sent only for a CIDR. A bare IP omits the field.

## Safety

`add` refuses without `--force` when the target is a catch-all (`/0`) or overlaps any `protected_ips` range from config. Those two cases cover the realistic disaster: a fat-fingered CIDR that locks the business out of its own storefront. Operators put office egress, VPN exits, monitoring probes, and load balancer IPs in `protected_ips`.

Anything broader than `/16` (v4) or `/48` (v6) warns with an address count but proceeds.

`add` is idempotent. An already-blocked IP is a no-op with a message, not an error and not a duplicate. `--update` replaces the label instead.

Entry matching is exact. Blocking `203.0.113.0/24` does not let `remove 203.0.113.7` succeed, because Fastly stores those as different entries and pretending otherwise would silently do the wrong thing.

The API token is never printed, logged, or included in error output. Error bodies from Fastly are parsed for a message field rather than dumped raw.

## Error handling and exit codes

| Code | Meaning |
|------|---------|
| 0 | success, including no-op cases |
| 1 | bad input, safety refusal, removing an IP that is not blocked |
| 2 | Fastly API error |
| 3 | token rejected or insufficient scope |

A 404 on the ACL lookup produces a message naming the ACL and pointing at `acls`, rather than a bare HTTP 404.

## Testing

`test_fastly_blocklist.py`, 62 tests, `unittest`, no network and no credentials.

Unit coverage: address parsing including IPv6 and host-bit normalization, safety checks, exact-match entry lookup, all four commands against a fake client, every output format, config precedence, and exit-code mapping.

Transport coverage: the `Fastly-Key` header, 401 to `AuthError` with an assertion that the token does not appear in the message, 404 status propagation, network failure, active-version selection, pagination across a page boundary, and the presence or absence of `subnet` in the request body.

Verified separately end to end by running the real CLI against a stub HTTP server implementing the Fastly endpoints, exercising every command, the 401 path, and the wrong-ACL path.

## Out of scope

Bulk import from file, country blocking, rate limiting, and the module's other Blocking features. Add them when there is a real need.
