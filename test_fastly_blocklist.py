#!/usr/bin/env python3
"""Tests for fastly_blocklist. No network, no credentials, stdlib only."""

import io
import json
import unittest
import urllib.error
from unittest import mock

import fastly_blocklist as fb


def entry(ip, subnet=None, comment="", entry_id="e1", created="2026-08-01T14:22:09Z"):
    return {
        "id": entry_id,
        "ip": ip,
        "subnet": subnet,
        "comment": comment,
        "negated": "0",
        "created_at": created,
        "updated_at": created,
    }


class FakeClient:
    """Stands in for FastlyClient, records what the commands tried to do."""

    def __init__(self, entries=None, acl_name="blocklist", acls=None):
        self.service_id = "SVC123"
        self._entries = list(entries or [])
        self._acl = {"id": "ACL1", "name": acl_name}
        self._acls = acls if acls is not None else [self._acl]
        self.added = []
        self.updated = []
        self.deleted = []

    def active_version(self):
        return 7

    def list_acls(self, version=None):
        return self._acls

    def get_acl(self, name, version=None):
        for acl in self._acls:
            if acl["name"] == name:
                return acl
        raise fb.FastlyError("no ACL named %r" % name, status=404)

    def entries(self, acl_id):
        return list(self._entries)

    def add_entry(self, acl_id, ip, subnet, comment):
        self.added.append((ip, subnet, comment))
        return {"id": "new1", "ip": ip, "subnet": subnet, "comment": comment}

    def update_entry(self, acl_id, entry_id, comment):
        self.updated.append((entry_id, comment))
        return {"id": entry_id, "comment": comment}

    def delete_entry(self, acl_id, entry_id):
        self.deleted.append(entry_id)
        return {"status": "ok"}


class Args:
    """Minimal argparse.Namespace stand-in with sane defaults."""

    def __init__(self, **kwargs):
        self.format = "table"
        self.grep = None
        self.label = ""
        self.update = False
        self.force = False
        self.dry_run = False
        self.ip = None
        for key, value in kwargs.items():
            setattr(self, key, value)


def settings(protected=()):
    return fb.Settings("tok", "SVC123", "blocklist", list(protected))


def run(command, client, args, settings_obj=None):
    out, err = io.StringIO(), io.StringIO()
    code = command(client, settings_obj or settings(), args, out, err)
    return code, out.getvalue(), err.getvalue()


# --------------------------------------------------------------------------


class TestParseTarget(unittest.TestCase):
    def test_bare_ipv4(self):
        self.assertEqual(fb.parse_target("203.0.113.7"), ("203.0.113.7", None))

    def test_cidr_ipv4(self):
        self.assertEqual(fb.parse_target("203.0.113.0/24"), ("203.0.113.0", 24))

    def test_cidr_with_host_bits_is_normalized(self):
        self.assertEqual(fb.parse_target("203.0.113.7/24"), ("203.0.113.0", 24))

    def test_ipv6(self):
        self.assertEqual(fb.parse_target("2001:db8::1"), ("2001:db8::1", None))

    def test_ipv6_cidr(self):
        self.assertEqual(fb.parse_target("2001:db8::/32"), ("2001:db8::", 32))

    def test_whitespace_tolerated(self):
        self.assertEqual(fb.parse_target("  203.0.113.7 "), ("203.0.113.7", None))

    def test_garbage_rejected(self):
        for bad in ["", "not-an-ip", "203.0.113.999", "203.0.113.0/99", "example.com"]:
            with self.assertRaises(fb.UsageError):
                fb.parse_target(bad)


class TestSafetyCheck(unittest.TestCase):
    def test_catch_all_ipv4_blocked(self):
        blocking, _ = fb.safety_check("0.0.0.0", 0, [])
        self.assertTrue(blocking)

    def test_catch_all_ipv6_blocked(self):
        blocking, _ = fb.safety_check("::", 0, [])
        self.assertTrue(blocking)

    def test_protected_exact_match_blocked(self):
        blocking, _ = fb.safety_check("198.51.100.4", None, ["198.51.100.4"])
        self.assertTrue(blocking)

    def test_protected_range_overlap_blocked(self):
        blocking, _ = fb.safety_check("198.51.100.0", 24, ["198.51.100.4"])
        self.assertTrue(blocking)

    def test_unrelated_ip_allowed(self):
        blocking, _ = fb.safety_check("203.0.113.7", None, ["198.51.100.4"])
        self.assertEqual(blocking, [])

    def test_cross_family_does_not_collide(self):
        blocking, _ = fb.safety_check("2001:db8::1", None, ["198.51.100.4"])
        self.assertEqual(blocking, [])

    def test_wide_range_warns_but_does_not_block(self):
        blocking, warnings = fb.safety_check("10.0.0.0", 8, [])
        self.assertEqual(blocking, [])
        self.assertTrue(warnings)

    def test_unparseable_protected_entry_warns_and_is_skipped(self):
        blocking, warnings = fb.safety_check("203.0.113.7", None, ["garbage"])
        self.assertEqual(blocking, [])
        self.assertTrue(warnings)


class TestFindEntry(unittest.TestCase):
    def test_matches_bare_ip(self):
        found = fb.find_entry([entry("203.0.113.7")], "203.0.113.7", None)
        self.assertIsNotNone(found)

    def test_matches_cidr(self):
        found = fb.find_entry([entry("203.0.113.0", 24)], "203.0.113.0", 24)
        self.assertIsNotNone(found)

    def test_string_subnet_from_api_is_handled(self):
        found = fb.find_entry([entry("203.0.113.0", "24")], "203.0.113.0", 24)
        self.assertIsNotNone(found)

    def test_ip_inside_a_blocked_range_is_not_an_exact_match(self):
        found = fb.find_entry([entry("203.0.113.0", 24)], "203.0.113.7", None)
        self.assertIsNone(found)

    def test_unparseable_entry_is_skipped_not_fatal(self):
        found = fb.find_entry(
            [entry("bogus"), entry("203.0.113.7")], "203.0.113.7", None
        )
        self.assertIsNotNone(found)

    def test_missing_returns_none(self):
        self.assertIsNone(fb.find_entry([entry("203.0.113.7")], "198.51.100.1", None))


class TestAdd(unittest.TestCase):
    def test_adds_new_ip_with_label(self):
        client = FakeClient()
        code, out, _ = run(
            fb.cmd_add, client, Args(ip="203.0.113.7", label="scraper, INF-412")
        )
        self.assertEqual(code, fb.EXIT_OK)
        self.assertEqual(client.added, [("203.0.113.7", None, "scraper, INF-412")])
        self.assertIn("Blocked 203.0.113.7", out)

    def test_adds_cidr_with_subnet(self):
        client = FakeClient()
        run(fb.cmd_add, client, Args(ip="203.0.113.0/24", label="bad ASN"))
        self.assertEqual(client.added, [("203.0.113.0", 24, "bad ASN")])

    def test_duplicate_is_a_noop(self):
        client = FakeClient([entry("203.0.113.7", comment="old")])
        code, out, _ = run(fb.cmd_add, client, Args(ip="203.0.113.7", label="new"))
        self.assertEqual(code, fb.EXIT_OK)
        self.assertEqual(client.added, [])
        self.assertEqual(client.updated, [])
        self.assertIn("already in blocklist", out)

    def test_update_relabels_existing(self):
        client = FakeClient([entry("203.0.113.7", comment="old", entry_id="E9")])
        code, out, _ = run(
            fb.cmd_add, client, Args(ip="203.0.113.7", label="new", update=True)
        )
        self.assertEqual(code, fb.EXIT_OK)
        self.assertEqual(client.updated, [("E9", "new")])
        self.assertIn("Relabeled", out)

    def test_update_with_identical_label_is_a_noop(self):
        client = FakeClient([entry("203.0.113.7", comment="same")])
        run(fb.cmd_add, client, Args(ip="203.0.113.7", label="same", update=True))
        self.assertEqual(client.updated, [])

    def test_catch_all_refused_without_force(self):
        client = FakeClient()
        code, _, err = run(fb.cmd_add, client, Args(ip="0.0.0.0/0", label="oops"))
        self.assertEqual(code, fb.EXIT_USAGE)
        self.assertEqual(client.added, [])
        self.assertIn("refusing", err)

    def test_catch_all_allowed_with_force(self):
        client = FakeClient()
        code, _, err = run(
            fb.cmd_add, client, Args(ip="0.0.0.0/0", label="maintenance", force=True)
        )
        self.assertEqual(code, fb.EXIT_OK)
        self.assertEqual(len(client.added), 1)
        self.assertIn("overriding safety check", err)

    def test_protected_ip_refused(self):
        client = FakeClient()
        code, _, err = run(
            fb.cmd_add,
            client,
            Args(ip="198.51.100.4", label="whoops"),
            settings(protected=["198.51.100.0/24"]),
        )
        self.assertEqual(code, fb.EXIT_USAGE)
        self.assertEqual(client.added, [])
        self.assertIn("protected", err)

    def test_dry_run_changes_nothing(self):
        client = FakeClient()
        code, out, _ = run(
            fb.cmd_add, client, Args(ip="203.0.113.7", label="x", dry_run=True)
        )
        self.assertEqual(code, fb.EXIT_OK)
        self.assertEqual(client.added, [])
        self.assertIn("dry run", out)

    def test_dry_run_on_relabel_changes_nothing(self):
        client = FakeClient([entry("203.0.113.7", comment="old")])
        code, out, _ = run(
            fb.cmd_add,
            client,
            Args(ip="203.0.113.7", label="new", update=True, dry_run=True),
        )
        self.assertEqual(client.updated, [])
        self.assertIn("dry run", out)

    def test_invalid_ip_raises_usage_error(self):
        with self.assertRaises(fb.UsageError):
            run(fb.cmd_add, FakeClient(), Args(ip="nope", label="x"))


class TestRemove(unittest.TestCase):
    def test_removes_existing(self):
        client = FakeClient([entry("203.0.113.7", comment="scraper", entry_id="E3")])
        code, out, _ = run(fb.cmd_remove, client, Args(ip="203.0.113.7"))
        self.assertEqual(code, fb.EXIT_OK)
        self.assertEqual(client.deleted, ["E3"])
        self.assertIn("Unblocked", out)

    def test_missing_entry_is_an_error(self):
        client = FakeClient()
        code, _, err = run(fb.cmd_remove, client, Args(ip="203.0.113.7"))
        self.assertEqual(code, fb.EXIT_USAGE)
        self.assertEqual(client.deleted, [])
        self.assertIn("not in blocklist", err)

    def test_dry_run_changes_nothing(self):
        client = FakeClient([entry("203.0.113.7", entry_id="E3")])
        code, out, _ = run(fb.cmd_remove, client, Args(ip="203.0.113.7", dry_run=True))
        self.assertEqual(client.deleted, [])
        self.assertIn("dry run", out)


class TestList(unittest.TestCase):
    def test_empty_acl(self):
        _, out, _ = run(fb.cmd_list, FakeClient(), Args())
        self.assertIn("No entries", out)

    def test_table_shows_ip_and_label(self):
        client = FakeClient([entry("203.0.113.7", comment="scraper, INF-412")])
        _, out, _ = run(fb.cmd_list, client, Args())
        self.assertIn("203.0.113.7", out)
        self.assertIn("scraper, INF-412", out)
        self.assertIn("1 entry", out)

    def test_json_format_is_valid_and_labeled(self):
        client = FakeClient([entry("203.0.113.0", 24, comment="bad ASN")])
        _, out, _ = run(fb.cmd_list, client, Args(format="json"))
        payload = json.loads(out)
        self.assertEqual(payload[0]["cidr"], "203.0.113.0/24")
        self.assertEqual(payload[0]["label"], "bad ASN")

    def test_csv_has_header_and_row(self):
        client = FakeClient([entry("203.0.113.7", comment="scraper")])
        _, out, _ = run(fb.cmd_list, client, Args(format="csv"))
        lines = out.strip().splitlines()
        self.assertTrue(lines[0].startswith("ip,subnet,cidr,label"))
        self.assertIn("scraper", lines[1])

    def test_grep_filters_on_label_and_ip(self):
        client = FakeClient(
            [
                entry("203.0.113.7", comment="scraper", entry_id="a"),
                entry("198.51.100.9", comment="card testing", entry_id="b"),
            ]
        )
        _, out, _ = run(fb.cmd_list, client, Args(grep="card"))
        self.assertIn("198.51.100.9", out)
        self.assertNotIn("203.0.113.7", out)

        _, out, _ = run(fb.cmd_list, client, Args(grep="203.0.113"))
        self.assertIn("203.0.113.7", out)
        self.assertNotIn("198.51.100.9", out)

    def test_entries_are_sorted_numerically_not_lexically(self):
        client = FakeClient(
            [
                entry("203.0.113.100", entry_id="a"),
                entry("203.0.113.9", entry_id="b"),
            ]
        )
        _, out, _ = run(fb.cmd_list, client, Args())
        self.assertLess(out.index("203.0.113.9"), out.index("203.0.113.100"))

    def test_missing_acl_surfaces_a_clear_error(self):
        client = FakeClient(acls=[{"id": "X", "name": "something_else"}])
        with self.assertRaises(fb.FastlyError):
            run(fb.cmd_list, client, Args())


class TestAcls(unittest.TestCase):
    def test_marks_the_configured_acl(self):
        client = FakeClient(
            acls=[{"id": "A1", "name": "blocklist"}, {"id": "A2", "name": "allowlist"}]
        )
        _, out, _ = run(fb.cmd_acls, client, Args())
        self.assertIn("blocklist", out)
        self.assertIn("configured blocklist", out)

    def test_warns_when_configured_acl_is_absent(self):
        client = FakeClient(acls=[{"id": "A2", "name": "allowlist"}])
        _, out, _ = run(fb.cmd_acls, client, Args())
        self.assertIn("is not in this list", out)


class TestClientTransport(unittest.TestCase):
    def _client(self, opener):
        return fb.FastlyClient("SECRET-TOKEN", "SVC123", opener=opener)

    def test_sends_the_token_header(self):
        captured = {}

        def opener(req, timeout=None):
            captured["headers"] = dict(req.headers)
            captured["method"] = req.get_method()
            return _resp(b"[]")

        self._client(opener).request("GET", "/service/SVC123/version")
        self.assertEqual(captured["headers"].get("Fastly-key"), "SECRET-TOKEN")
        self.assertEqual(captured["method"], "GET")

    def test_401_becomes_auth_error_without_leaking_the_token(self):
        def opener(req, timeout=None):
            raise urllib.error.HTTPError(
                req.full_url, 401, "Unauthorized", {}, io.BytesIO(b'{"msg":"bad token"}')
            )

        with self.assertRaises(fb.AuthError) as ctx:
            self._client(opener).request("GET", "/service/SVC123/version")
        self.assertNotIn("SECRET-TOKEN", str(ctx.exception))

    def test_404_carries_the_status_through(self):
        def opener(req, timeout=None):
            raise urllib.error.HTTPError(
                req.full_url, 404, "Not Found", {}, io.BytesIO(b'{"msg":"nope"}')
            )

        with self.assertRaises(fb.FastlyError) as ctx:
            self._client(opener).request("GET", "/x")
        self.assertEqual(ctx.exception.status, 404)

    def test_network_failure_is_a_fastly_error(self):
        def opener(req, timeout=None):
            raise urllib.error.URLError("connection refused")

        with self.assertRaises(fb.FastlyError):
            self._client(opener).request("GET", "/x")

    def test_active_version_prefers_the_active_flag(self):
        def opener(req, timeout=None):
            return _resp(json.dumps([{"number": 4}, {"number": 7, "active": True}]).encode())

        self.assertEqual(self._client(opener).active_version(), 7)

    def test_active_version_falls_back_to_the_highest(self):
        def opener(req, timeout=None):
            return _resp(json.dumps([{"number": 4}, {"number": 9}]).encode())

        self.assertEqual(self._client(opener).active_version(), 9)

    def test_entries_paginates_until_a_short_page(self):
        pages = [
            [entry("203.0.113.%d" % i, entry_id=str(i)) for i in range(fb.PER_PAGE)],
            [entry("198.51.100.1", entry_id="last")],
        ]
        calls = []

        def opener(req, timeout=None):
            calls.append(req.full_url)
            return _resp(json.dumps(pages[len(calls) - 1]).encode())

        entries = self._client(opener).entries("ACL1")
        self.assertEqual(len(entries), fb.PER_PAGE + 1)
        self.assertEqual(len(calls), 2)
        self.assertIn("page=1", calls[0])
        self.assertIn("page=2", calls[1])

    def test_add_entry_omits_subnet_for_a_bare_ip(self):
        captured = {}

        def opener(req, timeout=None):
            captured["body"] = json.loads(req.data.decode())
            return _resp(b"{}")

        self._client(opener).add_entry("ACL1", "203.0.113.7", None, "scraper")
        self.assertNotIn("subnet", captured["body"])
        self.assertEqual(captured["body"]["comment"], "scraper")
        self.assertEqual(captured["body"]["negated"], "0")

    def test_add_entry_includes_subnet_for_a_range(self):
        captured = {}

        def opener(req, timeout=None):
            captured["body"] = json.loads(req.data.decode())
            return _resp(b"{}")

        self._client(opener).add_entry("ACL1", "203.0.113.0", 24, "bad ASN")
        self.assertEqual(captured["body"]["subnet"], 24)


class TestSettings(unittest.TestCase):
    def test_flags_beat_environment(self):
        args = Args(env=None, token="flag-token", service_id="flag-svc", acl="flag-acl")
        with mock.patch.dict(
            "os.environ",
            {"FASTLY_API_TOKEN": "env-token", "FASTLY_SERVICE_ID": "env-svc"},
            clear=True,
        ), mock.patch.object(fb, "CONFIG_CANDIDATES", []):
            resolved = fb.resolve_settings(args)
        self.assertEqual(resolved.token, "flag-token")
        self.assertEqual(resolved.service_id, "flag-svc")
        self.assertEqual(resolved.acl, "flag-acl")

    def test_environment_used_when_no_flags(self):
        args = Args(env=None, token=None, service_id=None, acl=None)
        with mock.patch.dict(
            "os.environ",
            {"FASTLY_API_TOKEN": "env-token", "FASTLY_SERVICE_ID": "env-svc"},
            clear=True,
        ), mock.patch.object(fb, "CONFIG_CANDIDATES", []):
            resolved = fb.resolve_settings(args)
        self.assertEqual(resolved.token, "env-token")
        self.assertEqual(resolved.acl, fb.DEFAULT_ACL)

    def test_missing_token_is_a_usage_error(self):
        args = Args(env=None, token=None, service_id="svc", acl=None)
        with mock.patch.dict("os.environ", {}, clear=True), mock.patch.object(
            fb, "CONFIG_CANDIDATES", []
        ):
            with self.assertRaises(fb.UsageError):
                fb.resolve_settings(args)

    def test_missing_service_id_is_a_usage_error(self):
        args = Args(env=None, token="tok", service_id=None, acl=None)
        with mock.patch.dict("os.environ", {}, clear=True), mock.patch.object(
            fb, "CONFIG_CANDIDATES", []
        ):
            with self.assertRaises(fb.UsageError):
                fb.resolve_settings(args)

    def test_config_file_sections_and_defaults(self):
        import tempfile

        with tempfile.NamedTemporaryFile("w", suffix=".ini", delete=False) as handle:
            handle.write(
                "[defaults]\n"
                "api_token = shared-token\n"
                "protected_ips = 198.51.100.0/24, 203.0.113.1\n"
                "\n"
                "[prod]\n"
                "service_id = PROD_SVC\n"
                "\n"
                "[staging]\n"
                "service_id = STAGE_SVC\n"
                "acl_name = staging_blocklist\n"
            )
            path = handle.name

        args = Args(env="prod", token=None, service_id=None, acl=None)
        with mock.patch.dict("os.environ", {}, clear=True), mock.patch.object(
            fb, "CONFIG_CANDIDATES", [path]
        ):
            resolved = fb.resolve_settings(args)
        self.assertEqual(resolved.service_id, "PROD_SVC")
        self.assertEqual(resolved.token, "shared-token")
        self.assertEqual(resolved.acl, fb.DEFAULT_ACL)
        self.assertEqual(resolved.protected, ["198.51.100.0/24", "203.0.113.1"])

        args = Args(env="staging", token=None, service_id=None, acl=None)
        with mock.patch.dict("os.environ", {}, clear=True), mock.patch.object(
            fb, "CONFIG_CANDIDATES", [path]
        ):
            resolved = fb.resolve_settings(args)
        self.assertEqual(resolved.service_id, "STAGE_SVC")
        self.assertEqual(resolved.acl, "staging_blocklist")

    def test_unknown_env_section_is_a_usage_error(self):
        args = Args(env="nope", token=None, service_id=None, acl=None)
        with mock.patch.dict("os.environ", {}, clear=True), mock.patch.object(
            fb, "CONFIG_CANDIDATES", []
        ):
            with self.assertRaises(fb.UsageError):
                fb.resolve_settings(args)


class TestMainExitCodes(unittest.TestCase):
    def _main(self, argv, side_effect):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.dict(
            "os.environ",
            {"FASTLY_API_TOKEN": "tok", "FASTLY_SERVICE_ID": "svc"},
            clear=True,
        ), mock.patch.object(fb, "CONFIG_CANDIDATES", []), mock.patch.object(
            fb.FastlyClient, "active_version", side_effect=side_effect
        ):
            return fb.main(argv, out, err), out.getvalue(), err.getvalue()

    def test_auth_failure_exits_3(self):
        code, _, err = self._main(["list"], fb.AuthError("token rejected", status=401))
        self.assertEqual(code, fb.EXIT_AUTH)
        self.assertIn("token rejected", err)

    def test_api_failure_exits_2(self):
        code, _, err = self._main(["list"], fb.FastlyError("boom", status=500))
        self.assertEqual(code, fb.EXIT_API)

    def test_bad_ip_exits_1(self):
        code, _, err = self._main(["add", "not-an-ip"], fb.FastlyError("unused"))
        self.assertEqual(code, fb.EXIT_USAGE)
        self.assertIn("not a valid IP", err)


def _resp(payload):
    class _Ctx:
        def __enter__(self_inner):
            return self_inner

        def __exit__(self_inner, *exc):
            return False

        def read(self_inner):
            return payload

    return _Ctx()


if __name__ == "__main__":
    unittest.main(verbosity=2)
