import email.message
import io
import os
import tempfile
import textwrap
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, cast

import cf_hetzner_fw as sync


class ConfigTests(unittest.TestCase):
    def test_loads_and_canonicalizes_config(self):
        content = textwrap.dedent(
            """
            [hetzner]
            firewall_id = 42

            [firewall]
            ports = [443, 80, 443]
            extra_source_cidrs = ["2001:db8::/32", "192.0.2.5/32"]
            """
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.toml"
            path.write_text(content, encoding="utf-8")
            config = sync.load_config(path)

        self.assertEqual(config.firewall_id, 42)
        self.assertEqual(config.ports, (80, 443))
        self.assertEqual(config.extra_source_cidrs, ("192.0.2.5/32", "2001:db8::/32"))
        assert config.env_file is not None
        self.assertEqual(Path(config.env_file).name, ".env")

    def test_rejects_non_network_address(self):
        with self.assertRaises(sync.ConfigError):
            sync.canonical_cidrs(["192.0.2.5/24"], "test")

    def test_rejects_non_finite_timeout(self):
        content = textwrap.dedent(
            """
            [hetzner]
            firewall_id = 42

            [runtime]
            request_timeout_seconds = nan
            """
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.toml"
            path.write_text(content, encoding="utf-8")
            with self.assertRaisesRegex(
                sync.ConfigError, "request_timeout_seconds must be a positive number"
            ):
                sync.load_config(path)

    def test_rejects_api_url_with_embedded_credentials(self):
        content = textwrap.dedent(
            """
            [hetzner]
            firewall_id = 42
            api_url = "https://user:secret@example.com/v1"
            """
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.toml"
            path.write_text(content, encoding="utf-8")
            with self.assertRaisesRegex(
                sync.ConfigError, "hetzner.api_url must be an https:// URL"
            ) as caught:
                sync.load_config(path)

        self.assertNotIn("secret", str(caught.exception))

    def test_rejects_token_pasted_as_environment_variable_name_without_echoing_it(self):
        fake_token = "AbCdEf0123456789"
        content = textwrap.dedent(
            f"""
            [hetzner]
            firewall_id = 42
            token_env = "{fake_token}"
            """
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.toml"
            path.write_text(content, encoding="utf-8")
            with self.assertRaises(sync.ConfigError) as caught:
                sync.load_config(path)

        self.assertNotIn(fake_token, str(caught.exception))
        self.assertIn("not the token itself", str(caught.exception))

    def test_reads_token_from_private_env_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".env"
            path.write_text("# secret\nHCLOUD_TOKEN='test-token'\n", encoding="utf-8")
            os.chmod(path, 0o600)
            self.assertEqual(sync.read_env_value(path, "HCLOUD_TOKEN"), "test-token")

    def test_rejects_env_file_readable_by_others(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".env"
            path.write_text("HCLOUD_TOKEN=test-token\n", encoding="utf-8")
            os.chmod(path, 0o644)
            with self.assertRaisesRegex(sync.ConfigError, "chmod 600"):
                sync.read_env_value(path, "HCLOUD_TOKEN")

    def test_rejects_symlinked_env_file(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "credentials"
            target.write_text("HCLOUD_TOKEN=test-token\n", encoding="utf-8")
            os.chmod(target, 0o600)
            path = Path(directory) / ".env"
            path.symlink_to(target)

            with self.assertRaisesRegex(sync.ConfigError, "cannot safely open"):
                sync.read_env_value(path, "HCLOUD_TOKEN")


class RuleTests(unittest.TestCase):
    def test_builds_one_rule_per_port(self):
        rules = sync.build_managed_rules(
            ["2001:db8::/32", "192.0.2.0/24"], [443, 80], "managed:"
        )
        self.assertEqual([rule["port"] for rule in rules], ["80", "443"])
        self.assertEqual(rules[0]["source_ips"], ["192.0.2.0/24", "2001:db8::/32"])

    def test_passthrough_rules_exclude_only_restricted_tcp_ports(self):
        rules = sync.build_passthrough_rules([443, 80], "managed:")
        tcp_rules = [rule for rule in rules if rule["protocol"] == "tcp"]

        self.assertEqual(
            [rule["port"] for rule in tcp_rules],
            ["1-79", "81-442", "444-65535"],
        )
        self.assertTrue(
            all(rule["source_ips"] == ["0.0.0.0/0", "::/0"] for rule in tcp_rules)
        )
        self.assertEqual(
            {rule["protocol"] for rule in rules if rule["protocol"] != "tcp"},
            {"udp", "icmp", "esp", "gre"},
        )

    def test_passthrough_ranges_handle_edge_ports(self):
        self.assertEqual(sync._unrestricted_tcp_ranges([1, 65535]), ("2-65534",))

    def test_invalid_port_range_is_treated_as_a_conflict(self):
        self.assertTrue(sync._port_rule_overlaps("443-80", {80, 443}))
        self.assertTrue(sync._port_rule_overlaps("0", {80, 443}))

    def test_rules_equal_ignores_order_and_empty_response_fields(self):
        left = [
            {
                "direction": "in",
                "source_ips": ["2001:db8::/32", "192.0.2.0/24"],
                "destination_ips": [],
                "protocol": "tcp",
                "port": "443",
                "description": "managed: web",
            }
        ]
        right = [
            {
                "description": "managed: web",
                "port": "443",
                "protocol": "tcp",
                "source_ips": ["192.0.2.0/24", "2001:db8::/32"],
                "direction": "in",
            }
        ]
        self.assertTrue(sync.rules_equal(left, right))

    def test_finds_public_conflicting_rule(self):
        rules = [
            {
                "direction": "in",
                "source_ips": ["0.0.0.0/0", "::/0"],
                "protocol": "tcp",
                "port": "80-443",
                "description": "public web",
            }
        ]
        conflicts = sync.find_conflicting_rules(
            rules,
            managed_ports=[80, 443],
            allowed_sources=["192.0.2.0/24", "2001:db8::/32"],
            prefix="managed:",
        )
        self.assertEqual(len(conflicts), 1)
        self.assertIn("public web", conflicts[0])

    def test_allows_narrower_trusted_rule(self):
        rules = [
            {
                "direction": "in",
                "source_ips": ["192.0.2.10/32"],
                "protocol": "tcp",
                "port": "1-65535",
                "description": "trusted admin",
            }
        ]
        conflicts = sync.find_conflicting_rules(
            rules,
            managed_ports=[80, 443],
            allowed_sources=["192.0.2.0/24"],
            prefix="managed:",
        )
        self.assertEqual(conflicts, [])


class CloudflareResponseTests(unittest.TestCase):
    def test_invalid_non_object_response_is_reported_cleanly(self):
        class FakeHttp:
            def request(self, *args, **kwargs):
                return []

        config = sync.Config(
            firewall_id=1,
            token_env="HCLOUD_TOKEN",
            hetzner_api_url="https://api.hetzner.cloud/v1",
            cloudflare_api_url="https://api.cloudflare.com/client/v4",
            include_ipv4=True,
            include_ipv6=True,
            ports=(80, 443),
            extra_source_cidrs=(),
            strict_web_rules=True,
            description_prefix="managed:",
            request_timeout_seconds=15,
            max_attempts=1,
            action_timeout_seconds=120,
            lock_file="/tmp/test.lock",
        )
        with self.assertRaisesRegex(sync.SyncError, "Cloudflare API reported an error"):
            sync.fetch_cloudflare_cidrs(FakeHttp(), config)


class HttpClientTests(unittest.TestCase):
    def test_ignores_non_finite_retry_after(self):
        delay = sync.JsonHttpClient._retry_delay({"Retry-After": "nan"}, 1)
        self.assertGreaterEqual(delay, 1)
        self.assertLessEqual(delay, 1.25)

    def test_rejects_non_https_url_before_opening_it(self):
        client = sync.JsonHttpClient(timeout=1, max_attempts=1)
        with self.assertRaisesRegex(sync.SyncError, "non-HTTPS"):
            client.request("GET", "http://example.com/api")

    def test_rejects_cross_origin_redirect(self):
        handler = sync._SafeRedirectHandler()
        request = urllib.request.Request("https://api.hetzner.cloud/v1/firewalls")

        with self.assertRaisesRegex(urllib.error.HTTPError, "cross-origin"):
            handler.redirect_request(
                request,
                None,
                302,
                "Found",
                {},
                "https://example.com/redirected",
            )

    def test_retries_rate_limit_response(self):
        class FakeResponse:
            status = 200
            headers = {}

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self):
                return b'{"ok":true}'

        class FakeOpener:
            def __init__(self):
                self.calls = 0

            def open(self, request, timeout):
                self.calls += 1
                if self.calls == 1:
                    headers = email.message.Message()
                    headers["Retry-After"] = "0"
                    raise urllib.error.HTTPError(
                        request.full_url,
                        429,
                        "rate limited",
                        headers,
                        io.BytesIO(b'{"error":{"message":"slow down"}}'),
                    )
                return FakeResponse()

        delays = []
        client = sync.JsonHttpClient(
            timeout=1,
            max_attempts=2,
            sleeper=delays.append,
        )
        opener = FakeOpener()
        client.opener = cast(Any, opener)

        with self.assertLogs("cf-hetzner-fw", level="WARNING"):
            result = client.request("GET", "https://example.com/api")

        self.assertEqual(result, {"ok": True})
        self.assertEqual(opener.calls, 2)
        self.assertEqual(delays, [0.0])


class HetznerClientTests(unittest.TestCase):
    def test_waits_for_running_action(self):
        class FakeHttp:
            def __init__(self):
                self.requests = []

            def request(self, method, url, **kwargs):
                self.requests.append((method, url, kwargs))
                return {"action": {"id": 9, "status": "success"}}

        config = sync.Config(
            firewall_id=42,
            token_env="HCLOUD_TOKEN",
            hetzner_api_url="https://api.hetzner.cloud/v1",
            cloudflare_api_url="https://api.cloudflare.com/client/v4",
            include_ipv4=True,
            include_ipv6=True,
            ports=(80, 443),
            extra_source_cidrs=(),
            strict_web_rules=True,
            description_prefix="managed:",
            request_timeout_seconds=15,
            max_attempts=1,
            action_timeout_seconds=120,
            lock_file="/tmp/test.lock",
        )
        fake = FakeHttp()
        client = sync.HetznerClient(fake, config, "secret")

        client.wait_for_actions([{"id": 9, "status": "running"}])

        self.assertEqual(len(fake.requests), 1)
        self.assertTrue(fake.requests[0][1].endswith("/firewalls/actions/9"))
        self.assertEqual(
            fake.requests[0][2]["headers"]["Authorization"], "Bearer secret"
        )


class LockTests(unittest.TestCase):
    def test_rejects_second_process_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "sync.lock")
            first = sync.acquire_lock(path)
            try:
                with self.assertRaisesRegex(sync.SyncError, "already running"):
                    sync.acquire_lock(path)
            finally:
                first.close()


class ReconcileTests(unittest.TestCase):
    def test_update_preserves_unmanaged_rules_and_verifies_result(self):
        unmanaged = {
            "direction": "in",
            "source_ips": ["198.51.100.7/32"],
            "destination_ips": [],
            "protocol": "tcp",
            "port": "22",
            "description": "SSH",
        }
        old_managed = {
            "direction": "in",
            "source_ips": ["192.0.2.0/25"],
            "destination_ips": [],
            "protocol": "tcp",
            "port": "443",
            "description": "managed: old",
        }

        class FakeHttp:
            def __init__(self):
                self.updated_rules = None
                self.firewall_gets = 0

            def request(self, method, url, **kwargs):
                if url.endswith("/ips"):
                    return {
                        "success": True,
                        "result": {
                            "ipv4_cidrs": ["192.0.2.0/24"],
                            "ipv6_cidrs": ["2001:db8::/32"],
                            "etag": "test-etag",
                        },
                    }
                if url.endswith("/actions/set_rules"):
                    self.updated_rules = kwargs["payload"]["rules"]
                    return {"actions": [{"id": 9, "status": "success"}]}
                if url.endswith("/firewalls/42"):
                    self.firewall_gets += 1
                    rules = self.updated_rules or [unmanaged, old_managed]
                    return {"firewall": {"id": 42, "name": "web", "rules": rules}}
                raise AssertionError(f"unexpected request: {method} {url}")

        config = sync.Config(
            firewall_id=42,
            token_env="HCLOUD_TOKEN",
            hetzner_api_url="https://api.hetzner.cloud/v1",
            cloudflare_api_url="https://api.cloudflare.com/client/v4",
            include_ipv4=True,
            include_ipv6=True,
            ports=(80, 443),
            extra_source_cidrs=(),
            strict_web_rules=True,
            description_prefix="managed:",
            request_timeout_seconds=15,
            max_attempts=1,
            action_timeout_seconds=120,
            lock_file="/tmp/test.lock",
        )
        fake = FakeHttp()

        self.assertTrue(sync.reconcile(config, fake, "secret", dry_run=False))
        self.assertEqual(fake.firewall_gets, 3)
        updated_rules = fake.updated_rules
        assert updated_rules is not None
        self.assertEqual(updated_rules[0]["description"], "SSH")
        self.assertEqual([rule["port"] for rule in updated_rules[1:3]], ["80", "443"])
        self.assertEqual(
            updated_rules[1]["source_ips"], ["192.0.2.0/24", "2001:db8::/32"]
        )
        self.assertEqual(
            [rule["port"] for rule in updated_rules[3:6]],
            ["1-79", "81-442", "444-65535"],
        )

    def test_ignores_unrelated_ssh_rule(self):
        rules = [
            {
                "direction": "in",
                "source_ips": ["0.0.0.0/0"],
                "protocol": "tcp",
                "port": "22",
                "description": "SSH",
            }
        ]
        conflicts = sync.find_conflicting_rules(
            rules,
            managed_ports=[80, 443],
            allowed_sources=["192.0.2.0/24"],
            prefix="managed:",
        )
        self.assertEqual(conflicts, [])


if __name__ == "__main__":
    unittest.main()
