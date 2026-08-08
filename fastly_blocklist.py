#!/usr/bin/env python3
"""
fastly-blocklist -- manage the Fastly blocklist ACL used by Adobe Commerce / Magento.

The fastly/fastly-magento2 module's "Blocking" feature stores blocked IPs in a
Fastly Edge ACL (named "blocklist" by default) and reads it from a VCL snippet.
Fastly ACL entries are versionless: adding or removing one takes effect within
seconds with no version clone, no activate, and no purge. Anything this CLI
writes shows up in the Magento admin Blocking page, and vice versa.

Config resolution, first hit wins:
  1. CLI flags            --token / --service-id / --acl
  2. Environment          FASTLY_API_TOKEN / FASTLY_SERVICE_ID / FASTLY_ACL_NAME
  3. Config file section  --env NAME  ->  [NAME] in the ini file
  4. Config file default  [defaults] in the ini file

The API token is never printed, logged, or included in error output.
"""

import argparse
import configparser
import csv
import ipaddress
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

__version__ = "1.0.0"

API_BASE = os.environ.get("FASTLY_API_BASE", "https://api.fastly.com")
DEFAULT_ACL = "blocklist"
USER_AGENT = "fastly-blocklist/%s" % __version__
PER_PAGE = 100
MAX_PAGES = 500

EXIT_OK = 0
EXIT_USAGE = 1
EXIT_API = 2
EXIT_AUTH = 3

CONFIG_CANDIDATES = [
    os.environ.get("FASTLY_BLOCKLIST_CONFIG"),
    os.path.expanduser("~/.config/fastly-blocklist/config.ini"),
    os.path.join(os.getcwd(), "config.ini"),
]


# --------------------------------------------------------------------------
# errors
# --------------------------------------------------------------------------

class UsageError(Exception):
    """Bad input from the operator. Exits 1."""


class FastlyError(Exception):
    """The Fastly API said no. Exits 2."""

    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


class AuthError(FastlyError):
    """Token rejected or lacks scope. Exits 3."""


# --------------------------------------------------------------------------
# settings
# --------------------------------------------------------------------------

class Settings:
    def __init__(self, token, service_id, acl, protected):
        self.token = token
        self.service_id = service_id
        self.acl = acl
        self.protected = protected


def _read_config():
    parser = configparser.ConfigParser()
    for path in CONFIG_CANDIDATES:
        if path and os.path.isfile(path):
            parser.read(path)
            return parser, path
    return parser, None


def _split_list(raw):
    if not raw:
        return []
    return [item.strip() for item in raw.replace("\n", ",").split(",") if item.strip()]


def resolve_settings(args):
    """Merge flags, environment, and config file into one Settings object."""
    parser, path = _read_config()
    section = {}
    defaults = dict(parser["defaults"]) if parser.has_section("defaults") else {}

    if args.env:
        if not parser.has_section(args.env):
            where = path or "no config file found"
            raise UsageError(
                "no [%s] section in config (%s). Sections available: %s"
                % (args.env, where, ", ".join(parser.sections()) or "none")
            )
        section = dict(parser[args.env])

    def pick(flag, env_key, config_key, fallback=None):
        if flag:
            return flag
        if os.environ.get(env_key):
            return os.environ[env_key]
        if section.get(config_key):
            return section[config_key]
        if defaults.get(config_key):
            return defaults[config_key]
        return fallback

    token = pick(args.token, "FASTLY_API_TOKEN", "api_token")
    service_id = pick(args.service_id, "FASTLY_SERVICE_ID", "service_id")
    acl = pick(args.acl, "FASTLY_ACL_NAME", "acl_name", DEFAULT_ACL)

    protected = _split_list(section.get("protected_ips") or defaults.get("protected_ips"))
    protected += _split_list(os.environ.get("FASTLY_PROTECTED_IPS"))

    if not token:
        raise UsageError(
            "no Fastly API token. Set FASTLY_API_TOKEN, pass --token, or put "
            "api_token in the config file."
        )
    if not service_id:
        raise UsageError(
            "no Fastly service ID. Set FASTLY_SERVICE_ID, pass --service-id, or "
            "put service_id in the config file."
        )
    return Settings(token, service_id, acl, protected)


# --------------------------------------------------------------------------
# API client
# --------------------------------------------------------------------------

def _error_message(raw):
    """Pull a human message out of a Fastly error body without leaking internals."""
    try:
        payload = json.loads(raw.decode("utf-8", "replace"))
    except (ValueError, AttributeError):
        return raw.decode("utf-8", "replace").strip()[:300] if raw else ""
    if isinstance(payload, dict):
        for key in ("detail", "msg", "message", "title"):
            if payload.get(key):
                return str(payload[key])
    return json.dumps(payload)[:300]


class FastlyClient:
    def __init__(self, token, service_id, timeout=30, opener=None):
        self._token = token
        self.service_id = service_id
        self.timeout = timeout
        self._opener = opener or urllib.request.urlopen
        self._active_version = None

    # -- transport ---------------------------------------------------------

    def request(self, method, path, body=None, params=None):
        url = API_BASE + path
        if params:
            url += "?" + urllib.parse.urlencode(params)

        headers = {
            "Fastly-Key": self._token,
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
        }
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"

        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with self._opener(req, timeout=self.timeout) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            detail = _error_message(raw)
            if exc.code in (401, 403):
                raise AuthError(
                    "Fastly rejected the API token (HTTP %s)%s. Check that the token "
                    "is valid and has write access to service %s."
                    % (exc.code, ": " + detail if detail else "", self.service_id),
                    status=exc.code,
                )
            raise FastlyError(
                "Fastly API %s %s failed (HTTP %s)%s"
                % (method, path, exc.code, ": " + detail if detail else ""),
                status=exc.code,
            )
        except urllib.error.URLError as exc:
            raise FastlyError("could not reach %s: %s" % (API_BASE, exc.reason))

        if not raw:
            return None
        try:
            return json.loads(raw.decode("utf-8"))
        except ValueError:
            raise FastlyError("Fastly returned a non-JSON response to %s %s" % (method, path))

    # -- service / version -------------------------------------------------

    def active_version(self):
        if self._active_version is not None:
            return self._active_version
        versions = self.request("GET", "/service/%s/version" % self.service_id) or []
        for version in versions:
            if version.get("active"):
                self._active_version = version["number"]
                return self._active_version
        if versions:
            self._active_version = max(v["number"] for v in versions)
            return self._active_version
        raise FastlyError("service %s has no versions" % self.service_id)

    # -- ACLs --------------------------------------------------------------

    def list_acls(self, version=None):
        version = version or self.active_version()
        return self.request(
            "GET", "/service/%s/version/%s/acl" % (self.service_id, version)
        ) or []

    def get_acl(self, name, version=None):
        version = version or self.active_version()
        try:
            return self.request(
                "GET",
                "/service/%s/version/%s/acl/%s"
                % (self.service_id, version, urllib.parse.quote(name, safe="")),
            )
        except FastlyError as exc:
            if exc.status == 404:
                raise FastlyError(
                    "no ACL named %r on service %s (version %s). Run "
                    "`fastly-blocklist acls` to see what exists."
                    % (name, self.service_id, version),
                    status=404,
                )
            raise

    # -- ACL entries (versionless) ----------------------------------------

    def entries(self, acl_id):
        collected = []
        for page in range(1, MAX_PAGES + 1):
            batch = self.request(
                "GET",
                "/service/%s/acl/%s/entries" % (self.service_id, acl_id),
                params={
                    "page": page,
                    "per_page": PER_PAGE,
                    "sort": "created",
                    "direction": "ascend",
                },
            ) or []
            collected.extend(batch)
            if len(batch) < PER_PAGE:
                break
        return collected

    def add_entry(self, acl_id, ip, subnet, comment):
        body = {"ip": ip, "negated": "0", "comment": comment or ""}
        if subnet is not None:
            body["subnet"] = subnet
        return self.request(
            "POST", "/service/%s/acl/%s/entry" % (self.service_id, acl_id), body=body
        )

    def update_entry(self, acl_id, entry_id, comment):
        return self.request(
            "PATCH",
            "/service/%s/acl/%s/entry/%s" % (self.service_id, acl_id, entry_id),
            body={"comment": comment or ""},
        )

    def delete_entry(self, acl_id, entry_id):
        return self.request(
            "DELETE", "/service/%s/acl/%s/entry/%s" % (self.service_id, acl_id, entry_id)
        )


# --------------------------------------------------------------------------
# address handling
# --------------------------------------------------------------------------

def parse_target(value):
    """'203.0.113.7' -> ('203.0.113.7', None);  '203.0.113.0/24' -> ('203.0.113.0', 24)."""
    text = (value or "").strip()
    if not text:
        raise UsageError("empty IP address")
    try:
        if "/" in text:
            network = ipaddress.ip_network(text, strict=False)
            return str(network.network_address), network.prefixlen
        return str(ipaddress.ip_address(text)), None
    except ValueError:
        raise UsageError("%r is not a valid IP address or CIDR range" % value)


def as_network(ip, subnet):
    host_bits = 32 if ipaddress.ip_address(ip).version == 4 else 128
    prefix = host_bits if subnet is None else subnet
    return ipaddress.ip_network("%s/%s" % (ip, prefix), strict=False)


def render_target(ip, subnet):
    return ip if subnet is None else "%s/%s" % (ip, subnet)


def entry_network(entry):
    """Normalize an ACL entry from the API into an ip_network, or None if unparseable."""
    ip = entry.get("ip")
    if not ip:
        return None
    subnet = entry.get("subnet")
    try:
        return as_network(ip, int(subnet) if subnet not in (None, "") else None)
    except (ValueError, TypeError):
        return None


def find_entry(entries, ip, subnet):
    """Return the entry covering exactly this ip/subnet, or None."""
    target = as_network(ip, subnet)
    for entry in entries:
        network = entry_network(entry)
        if network is not None and network == target:
            return entry
    return None


def safety_check(ip, subnet, protected):
    """Return (blocking_reasons, warnings) for a proposed block."""
    target = as_network(ip, subnet)
    blocking = []
    warnings = []

    if target.prefixlen == 0:
        blocking.append(
            "%s is a catch-all range and would block every visitor to the store"
            % target.with_prefixlen
        )

    for candidate in protected:
        try:
            guarded = ipaddress.ip_network(candidate.strip(), strict=False)
        except ValueError:
            warnings.append("skipping unparseable protected_ips entry %r" % candidate)
            continue
        if guarded.version == target.version and target.overlaps(guarded):
            blocking.append(
                "%s overlaps protected range %s from your config"
                % (target.with_prefixlen, guarded.with_prefixlen)
            )

    broad = (target.version == 4 and target.prefixlen < 16) or (
        target.version == 6 and target.prefixlen < 48
    )
    if broad and target.prefixlen != 0:
        warnings.append(
            "%s covers %s addresses, which is a wide net"
            % (target.with_prefixlen, format(target.num_addresses, ","))
        )
    return blocking, warnings


# --------------------------------------------------------------------------
# output
# --------------------------------------------------------------------------

def sort_key(entry):
    network = entry_network(entry)
    if network is None:
        return (2, 0, 0, str(entry.get("ip", "")))
    return (0, network.version, int(network.network_address), network.prefixlen)


def print_table(entries, stream):
    if not entries:
        stream.write("No entries in this ACL.\n")
        return
    rows = [
        (
            render_target(e.get("ip", ""), e.get("subnet")),
            (e.get("comment") or "").replace("\n", " "),
            e.get("id", ""),
            (e.get("created_at") or "")[:19],
        )
        for e in entries
    ]
    headers = ("IP / CIDR", "LABEL", "ENTRY ID", "ADDED")
    widths = [
        max(len(headers[i]), max(len(row[i]) for row in rows)) for i in range(len(headers))
    ]
    line = "  ".join(h.ljust(widths[i]) for i, h in enumerate(headers))
    stream.write(line.rstrip() + "\n")
    stream.write("  ".join("-" * widths[i] for i in range(len(headers))) + "\n")
    for row in rows:
        stream.write("  ".join(row[i].ljust(widths[i]) for i in range(len(row))).rstrip() + "\n")
    stream.write("\n%d entr%s\n" % (len(rows), "y" if len(rows) == 1 else "ies"))


def print_csv(entries, stream):
    writer = csv.writer(stream, lineterminator="\n")
    writer.writerow(["ip", "subnet", "cidr", "label", "entry_id", "created_at", "updated_at"])
    for e in entries:
        writer.writerow(
            [
                e.get("ip", ""),
                e.get("subnet", "") if e.get("subnet") is not None else "",
                render_target(e.get("ip", ""), e.get("subnet")),
                e.get("comment", "") or "",
                e.get("id", ""),
                e.get("created_at", "") or "",
                e.get("updated_at", "") or "",
            ]
        )


def print_json(entries, stream):
    payload = [
        {
            "ip": e.get("ip"),
            "subnet": e.get("subnet"),
            "cidr": render_target(e.get("ip", ""), e.get("subnet")),
            "label": e.get("comment") or "",
            "entry_id": e.get("id"),
            "created_at": e.get("created_at"),
            "updated_at": e.get("updated_at"),
        }
        for e in entries
    ]
    json.dump(payload, stream, indent=2)
    stream.write("\n")


FORMATTERS = {"table": print_table, "csv": print_csv, "json": print_json}


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------

def cmd_list(client, settings, args, out, err):
    acl = client.get_acl(settings.acl)
    entries = client.entries(acl["id"])
    entries.sort(key=sort_key)
    if args.grep:
        needle = args.grep.lower()
        entries = [
            e
            for e in entries
            if needle in (e.get("comment") or "").lower()
            or needle in render_target(e.get("ip", ""), e.get("subnet")).lower()
        ]
    FORMATTERS[args.format](entries, out)
    return EXIT_OK


def cmd_add(client, settings, args, out, err):
    ip, subnet = parse_target(args.ip)
    target = render_target(ip, subnet)

    blocking, warnings = safety_check(ip, subnet, settings.protected)
    for warning in warnings:
        err.write("warning: %s\n" % warning)
    if blocking and not args.force:
        for reason in blocking:
            err.write("refusing: %s\n" % reason)
        err.write("Pass --force if you really mean it.\n")
        return EXIT_USAGE
    for reason in blocking:
        err.write("warning: overriding safety check -- %s\n" % reason)

    acl = client.get_acl(settings.acl)
    existing = find_entry(client.entries(acl["id"]), ip, subnet)

    if existing:
        current_label = existing.get("comment") or ""
        if not args.update:
            out.write(
                "%s is already in %s (label: %s). Nothing to do; use --update to "
                "change the label.\n" % (target, settings.acl, current_label or "<none>")
            )
            return EXIT_OK
        if current_label == args.label:
            out.write("%s already has that label. Nothing to do.\n" % target)
            return EXIT_OK
        if args.dry_run:
            out.write(
                "dry run: would relabel %s in %s from %r to %r\n"
                % (target, settings.acl, current_label, args.label)
            )
            return EXIT_OK
        client.update_entry(acl["id"], existing["id"], args.label)
        out.write(
            "Relabeled %s in %s: %r -> %r\n"
            % (target, settings.acl, current_label, args.label)
        )
        return EXIT_OK

    if args.dry_run:
        out.write(
            "dry run: would add %s to %s with label %r\n" % (target, settings.acl, args.label)
        )
        return EXIT_OK

    created = client.add_entry(acl["id"], ip, subnet, args.label) or {}
    out.write(
        "Blocked %s in %s (label: %s, entry %s)\n"
        % (target, settings.acl, args.label or "<none>", created.get("id", "?"))
    )
    return EXIT_OK


def cmd_remove(client, settings, args, out, err):
    ip, subnet = parse_target(args.ip)
    target = render_target(ip, subnet)

    acl = client.get_acl(settings.acl)
    existing = find_entry(client.entries(acl["id"]), ip, subnet)
    if not existing:
        err.write("%s is not in %s. Nothing to remove.\n" % (target, settings.acl))
        return EXIT_USAGE

    label = existing.get("comment") or "<none>"
    if args.dry_run:
        out.write("dry run: would remove %s from %s (label: %s)\n" % (target, settings.acl, label))
        return EXIT_OK

    client.delete_entry(acl["id"], existing["id"])
    out.write("Unblocked %s from %s (was labeled: %s)\n" % (target, settings.acl, label))
    return EXIT_OK


def cmd_acls(client, settings, args, out, err):
    version = client.active_version()
    acls = client.list_acls(version)
    if not acls:
        out.write("Service %s (version %s) has no ACLs.\n" % (client.service_id, version))
        return EXIT_OK
    out.write("Service %s, active version %s:\n\n" % (client.service_id, version))
    width = max(len(a.get("name", "")) for a in acls)
    for acl in sorted(acls, key=lambda a: a.get("name", "")):
        marker = " <- configured blocklist" if acl.get("name") == settings.acl else ""
        out.write("  %s  %s%s\n" % (acl.get("name", "").ljust(width), acl.get("id", ""), marker))
    if not any(a.get("name") == settings.acl for a in acls):
        out.write(
            "\nNote: configured ACL name %r is not in this list. Set acl_name in your "
            "config or pass --acl.\n" % settings.acl
        )
    return EXIT_OK


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def build_parser():
    parser = argparse.ArgumentParser(
        prog="fastly-blocklist",
        description="Manage the Fastly blocklist ACL behind Adobe Commerce / Magento.",
        epilog="Credentials come from --token/--service-id, then FASTLY_API_TOKEN/"
        "FASTLY_SERVICE_ID, then the config file.",
    )
    parser.add_argument("--version", action="version", version=USER_AGENT)
    parser.add_argument("--env", help="config file section to use, e.g. prod or staging")
    parser.add_argument("--token", help="Fastly API token (prefer FASTLY_API_TOKEN)")
    parser.add_argument("--service-id", help="Fastly service ID")
    parser.add_argument("--acl", help="ACL name (default: %s)" % DEFAULT_ACL)
    parser.add_argument("--timeout", type=int, default=30, help="HTTP timeout in seconds")

    sub = parser.add_subparsers(dest="command", required=True)

    p_list = sub.add_parser("list", help="show every IP in the blocklist")
    p_list.add_argument(
        "--format", choices=sorted(FORMATTERS), default="table", help="output format"
    )
    p_list.add_argument("--grep", help="only show entries whose IP or label contains this text")
    p_list.set_defaults(func=cmd_list)

    p_add = sub.add_parser("add", help="block an IP or CIDR range")
    p_add.add_argument("ip", help="IP address or CIDR range, e.g. 203.0.113.7 or 203.0.113.0/24")
    p_add.add_argument("--label", "-l", default="", help="why this is blocked (stored as the ACL comment)")
    p_add.add_argument("--update", action="store_true", help="if already blocked, replace the label")
    p_add.add_argument("--force", action="store_true", help="override safety refusals")
    p_add.add_argument("--dry-run", action="store_true", help="show what would happen, change nothing")
    p_add.set_defaults(func=cmd_add)

    p_remove = sub.add_parser("remove", help="unblock an IP or CIDR range")
    p_remove.add_argument("ip", help="IP address or CIDR range to remove")
    p_remove.add_argument("--dry-run", action="store_true", help="show what would happen, change nothing")
    p_remove.set_defaults(func=cmd_remove)

    p_acls = sub.add_parser("acls", help="list the ACLs on the service")
    p_acls.set_defaults(func=cmd_acls)

    return parser


def main(argv=None, out=None, err=None):
    out = out or sys.stdout
    err = err or sys.stderr
    args = build_parser().parse_args(argv)

    try:
        settings = resolve_settings(args)
        client = FastlyClient(settings.token, settings.service_id, timeout=args.timeout)
        return args.func(client, settings, args, out, err)
    except UsageError as exc:
        err.write("error: %s\n" % exc)
        return EXIT_USAGE
    except AuthError as exc:
        err.write("error: %s\n" % exc)
        return EXIT_AUTH
    except FastlyError as exc:
        err.write("error: %s\n" % exc)
        return EXIT_API
    except KeyboardInterrupt:
        err.write("\ninterrupted\n")
        return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())
