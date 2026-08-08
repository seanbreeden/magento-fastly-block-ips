# fastly-blocklist

Command-line management of the Fastly blocklist ACL that sits in front of Adobe Commerce / Magento.

Python 3.7+, standard library only. No pip install, no dependencies, one file.

## Why this exists

The `fastly/fastly-magento2` module's Blocking page writes blocked IPs into a Fastly Edge ACL named `blocklist` and reads it from a VCL snippet. Clicking through the Magento admin to block one scraper is slow, and it does not script.

This CLI talks to the Fastly API directly and edits the same ACL. Entries added here appear in the Magento admin Blocking page, and entries added there appear here. Fastly ACL entries are versionless: a change takes effect within seconds with no version clone, no activate, and no purge.

## Setup

```bash
mkdir -p ~/.config/fastly-blocklist
cp config.ini.example ~/.config/fastly-blocklist/config.ini
chmod 600 ~/.config/fastly-blocklist/config.ini
$EDITOR ~/.config/fastly-blocklist/config.ini    # add token + service IDs

ln -s "$(pwd)/fastly-blocklist" ~/.local/bin/fastly-blocklist   # optional
```

Confirm it can see the service, and that the ACL name is right:

```bash
fastly-blocklist --env prod acls
```

```
Service 7i6HxdX...  active version 42:

  allowlist  1a2b3c...
  blocklist  4d5e6f...  <- configured blocklist
```

If `blocklist` is missing, your install names it something else. Set `acl_name` in the config or pass `--acl`.

## Usage

```bash
fastly-blocklist list
fastly-blocklist list --format json
fastly-blocklist list --grep "card testing"

fastly-blocklist add 203.0.113.7 --label "scraper, ticket INF-412"
fastly-blocklist add 203.0.113.0/24 --label "bad ASN block"
fastly-blocklist add 203.0.113.7 --label "confirmed bot" --update

fastly-blocklist remove 203.0.113.7
```

Every mutating command takes `--dry-run`.

The label is stored in the ACL entry's `comment` field, which is the same column the Magento admin shows. Put the ticket number in it. Six months from now nobody remembers why `203.0.113.7` is blocked.

## Credentials

Resolved first-hit-wins:

1. Flags: `--token`, `--service-id`, `--acl`
2. Environment: `FASTLY_API_TOKEN`, `FASTLY_SERVICE_ID`, `FASTLY_ACL_NAME`
3. Config file section chosen by `--env NAME`
4. Config file `[defaults]` section

Config file is looked for at `$FASTLY_BLOCKLIST_CONFIG`, then `~/.config/fastly-blocklist/config.ini`, then `./config.ini`.

The token needs write access to the service. It is never printed, logged, or included in error output.

## Guardrails

`add` refuses, and tells you to pass `--force`, when the range is:

- a catch-all (`0.0.0.0/0`, `::/0`), which would block every visitor to the store
- overlapping any range in `protected_ips` in your config

Put your office egress, VPN exit, monitoring probes, and load balancer IPs in `protected_ips`. That list is what stands between a fat-fingered CIDR and locking the business out of its own storefront.

Anything broader than a `/16` prints a warning with the address count but still goes through.

`add` is idempotent. An IP that is already blocked is a no-op with a message, not an error and not a duplicate entry.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | success, including no-op cases |
| 1 | bad input, safety refusal, or removing an IP that is not blocked |
| 2 | Fastly API error |
| 3 | token rejected or lacks scope |

Suitable for cron and Ansible.

## Tests

```bash
python3 -m unittest test_fastly_blocklist -v
```

62 tests, no network and no credentials required.

## Notes

- IPv4 and IPv6 both work, bare addresses and CIDR.
- `add 203.0.113.7/24` is normalized to `203.0.113.0/24`.
- Blocking `203.0.113.0/24` does not make `remove 203.0.113.7` work. Removal matches the exact entry, the same way Fastly stores it.
- `list` sorts numerically, so `.9` comes before `.100`.
