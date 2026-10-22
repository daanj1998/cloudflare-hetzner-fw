#!/usr/bin/env python3
"""Synchronize Cloudflare proxy networks with a Hetzner Cloud Firewall."""

from __future__ import annotations

import argparse
import email.utils
import fcntl
import ipaddress
import json
import logging
import math
import os
import re
import secrets
import stat
import sys
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

VERSION = "1.1.0"
USER_AGENT = f"cf-hetzner-fw/{VERSION}"
RETRYABLE_STATUS_CODES = frozenset({429, 500, 502, 503, 504})
RULE_KEYS = frozenset(
    {"direction", "source_ips", "destination_ips", "protocol", "port", "description"}
)
LOG = logging.getLogger("cf-hetzner-fw")


class SyncError(RuntimeError):
    """A safe, user-facing synchronization error."""


class ConfigError(SyncError):
    """The configuration is invalid."""


def _https_origin(url: str) -> tuple[str, int | None]:
    try:
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise SyncError("refusing a malformed API URL") from exc
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise SyncError("refusing a malformed or non-HTTPS API URL")
    return parsed.hostname.lower(), port


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        try:
            same_origin = _https_origin(req.full_url) == _https_origin(newurl)
        except SyncError:
            same_origin = False
        if not same_origin:
            raise urllib.error.HTTPError(
                req.full_url,
                code,
                "refusing a cross-origin or non-HTTPS redirect",
                headers,
                fp,
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


@dataclass(frozen=True)
class Config:
    firewall_id: int
    token_env: str
    hetzner_api_url: str
    cloudflare_api_url: str
    include_ipv4: bool
    include_ipv6: bool
    ports: tuple[int, ...]
    extra_source_cidrs: tuple[str, ...]
    strict_web_rules: bool
    description_prefix: str
    request_timeout_seconds: float
    max_attempts: int
    action_timeout_seconds: float
    lock_file: str
    env_file: str | None = None


class HttpClient(Protocol):
    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        payload: Mapping[str, Any] | None = None,
        expected: Sequence[int] = (200,),
    ) -> Any: ...


def _expect_mapping(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise ConfigError(f"{context} must be a TOML table")
    return value


def _reject_unknown(
    mapping: Mapping[str, Any], allowed: set[str], context: str
) -> None:
    unknown = sorted(set(mapping) - allowed)
    if unknown:
        raise ConfigError(f"unknown {context} setting(s): {', '.join(unknown)}")


def _get_bool(mapping: Mapping[str, Any], key: str, default: bool) -> bool:
    value = mapping.get(key, default)
    if not isinstance(value, bool):
        raise ConfigError(f"{key} must be true or false")
    return value


def _get_positive_number(
    mapping: Mapping[str, Any], key: str, default: float, *, integer: bool = False
) -> float | int:
    value = mapping.get(key, default)
    expected = int if integer else (int, float)
    if (
        isinstance(value, bool)
        or not isinstance(value, expected)
        or not math.isfinite(value)
        or value <= 0
    ):
        kind = "a positive integer" if integer else "a positive number"
        raise ConfigError(f"{key} must be {kind}")
    return int(value) if integer else float(value)


def canonical_cidrs(values: Iterable[str], context: str) -> tuple[str, ...]:
    networks: dict[tuple[int, int, int], str] = {}
    for value in values:
        if not isinstance(value, str):
            raise ConfigError(f"{context} entries must be strings")
        try:
            network = ipaddress.ip_network(value, strict=True)
        except ValueError as exc:
            raise ConfigError(f"invalid CIDR in {context}: {value!r} ({exc})") from exc
        key = (network.version, int(network.network_address), network.prefixlen)
        networks[key] = str(network)
    return tuple(networks[key] for key in sorted(networks))


def load_config(path: Path) -> Config:
    try:
        with path.open("rb") as handle:
            raw = tomllib.load(handle)
    except FileNotFoundError as exc:
        raise ConfigError(f"configuration file not found: {path}") from exc
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"cannot read configuration {path}: {exc}") from exc

    _reject_unknown(raw, {"hetzner", "cloudflare", "firewall", "runtime"}, "top-level")
    hetzner = _expect_mapping(raw.get("hetzner", {}), "[hetzner]")
    cloudflare = _expect_mapping(raw.get("cloudflare", {}), "[cloudflare]")
    firewall = _expect_mapping(raw.get("firewall", {}), "[firewall]")
    runtime = _expect_mapping(raw.get("runtime", {}), "[runtime]")

    _reject_unknown(
        hetzner, {"firewall_id", "token_env", "env_file", "api_url"}, "[hetzner]"
    )
    _reject_unknown(
        cloudflare, {"api_url", "include_ipv4", "include_ipv6"}, "[cloudflare]"
    )
    _reject_unknown(
        firewall,
        {"ports", "extra_source_cidrs", "strict_web_rules", "description_prefix"},
        "[firewall]",
    )
    _reject_unknown(
        runtime,
        {
            "request_timeout_seconds",
            "max_attempts",
            "action_timeout_seconds",
            "lock_file",
        },
        "[runtime]",
    )

    firewall_id = hetzner.get("firewall_id")
    if (
        isinstance(firewall_id, bool)
        or not isinstance(firewall_id, int)
        or firewall_id <= 0
    ):
        raise ConfigError("hetzner.firewall_id must be a positive integer")

    token_env = hetzner.get("token_env", "HCLOUD_TOKEN")
    if not isinstance(token_env, str) or not re.fullmatch(
        r"[A-Z_][A-Z0-9_]*", token_env
    ):
        raise ConfigError(
            "hetzner.token_env must be an uppercase environment variable name such as "
            "HCLOUD_TOKEN, not the token itself"
        )

    env_file_raw = hetzner.get("env_file", ".env")
    if not isinstance(env_file_raw, str) or not env_file_raw.strip():
        raise ConfigError("hetzner.env_file must be a non-empty path")
    env_file_path = Path(env_file_raw).expanduser()
    if not env_file_path.is_absolute():
        env_file_path = path.resolve().parent / env_file_path

    hetzner_api_url = hetzner.get("api_url", "https://api.hetzner.cloud/v1")
    cloudflare_api_url = cloudflare.get(
        "api_url", "https://api.cloudflare.com/client/v4"
    )
    for name, value in (
        ("hetzner.api_url", hetzner_api_url),
        ("cloudflare.api_url", cloudflare_api_url),
    ):
        if not isinstance(value, str):
            raise ConfigError(f"{name} must be an https:// URL")
        try:
            _https_origin(value)
            parsed = urllib.parse.urlsplit(value)
        except SyncError as exc:
            raise ConfigError(f"{name} must be an https:// URL") from exc
        if parsed.query or parsed.fragment:
            raise ConfigError(f"{name} must not contain a query string or fragment")

    include_ipv4 = _get_bool(cloudflare, "include_ipv4", True)
    include_ipv6 = _get_bool(cloudflare, "include_ipv6", True)
    if not include_ipv4 and not include_ipv6:
        raise ConfigError("at least one of include_ipv4/include_ipv6 must be true")

    ports_raw = firewall.get("ports", [80, 443])
    if not isinstance(ports_raw, list) or not ports_raw:
        raise ConfigError("firewall.ports must be a non-empty array")
    ports: set[int] = set()
    for port in ports_raw:
        if (
            isinstance(port, bool)
            or not isinstance(port, int)
            or not 1 <= port <= 65535
        ):
            raise ConfigError(
                "firewall.ports entries must be integers from 1 through 65535"
            )
        ports.add(port)

    extra_raw = firewall.get("extra_source_cidrs", [])
    if not isinstance(extra_raw, list):
        raise ConfigError(
            "firewall.extra_source_cidrs must be an array of CIDR strings"
        )
    extra_source_cidrs = canonical_cidrs(extra_raw, "firewall.extra_source_cidrs")

    description_prefix = firewall.get("description_prefix", "cf-hetzner-fw:")
    if not isinstance(description_prefix, str) or not description_prefix.strip():
        raise ConfigError("firewall.description_prefix must be a non-empty string")
    if len(description_prefix) > 60:
        raise ConfigError("firewall.description_prefix may be at most 60 characters")

    lock_file = runtime.get("lock_file", "/run/cf-hetzner-fw/sync.lock")
    if not isinstance(lock_file, str) or not lock_file.startswith("/"):
        raise ConfigError("runtime.lock_file must be an absolute path")

    return Config(
        firewall_id=firewall_id,
        token_env=token_env,
        hetzner_api_url=hetzner_api_url.rstrip("/"),
        cloudflare_api_url=cloudflare_api_url.rstrip("/"),
        include_ipv4=include_ipv4,
        include_ipv6=include_ipv6,
        ports=tuple(sorted(ports)),
        extra_source_cidrs=extra_source_cidrs,
        strict_web_rules=_get_bool(firewall, "strict_web_rules", True),
        description_prefix=description_prefix,
        request_timeout_seconds=float(
            _get_positive_number(runtime, "request_timeout_seconds", 15.0)
        ),
        max_attempts=int(
            _get_positive_number(runtime, "max_attempts", 4, integer=True)
        ),
        action_timeout_seconds=float(
            _get_positive_number(runtime, "action_timeout_seconds", 120.0)
        ),
        lock_file=lock_file,
        env_file=str(env_file_path),
    )


def read_env_value(path: Path, variable: str) -> str | None:
    """Read one variable from a simple dotenv file without modifying os.environ."""
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ConfigError(f"cannot safely open env file {path}: {exc}") from exc

    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ConfigError(f"env file is not a regular file: {path}")
        if metadata.st_uid != os.geteuid():
            raise ConfigError(f"env file {path} is not owned by the current user")
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise ConfigError(
                f"env file {path} is accessible by group/others; run chmod 600 {path}"
            )
        with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
            descriptor = -1
            lines = handle.read().splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise ConfigError(f"cannot read env file {path}: {exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)

    found: str | None = None
    assignment = re.compile(r"^(?:export\s+)?([A-Z_][A-Z0-9_]*)\s*=\s*(.*)$")
    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = assignment.fullmatch(line)
        if not match:
            raise ConfigError(
                f"invalid assignment in env file {path} on line {line_number}"
            )
        name, raw_value = match.groups()
        if name != variable:
            continue
        if found is not None:
            raise ConfigError(f"{variable} occurs more than once in env file {path}")
        value = raw_value.strip()
        if value.startswith(("'", '"')):
            quote = value[0]
            if len(value) < 2 or not value.endswith(quote):
                raise ConfigError(
                    f"unterminated quoted value in env file {path} "
                    f"on line {line_number}"
                )
            value = value[1:-1]
        elif any(character.isspace() for character in value):
            raise ConfigError(
                f"unquoted whitespace in env file {path} on line {line_number}"
            )
        found = value
    return found or None


class JsonHttpClient:
    def __init__(
        self,
        *,
        timeout: float,
        max_attempts: int,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        self.timeout = timeout
        self.max_attempts = max_attempts
        self.sleeper = sleeper
        self.opener = urllib.request.build_opener(_SafeRedirectHandler())

    @staticmethod
    def _retry_delay(headers: Mapping[str, str], attempt: int) -> float:
        retry_after = headers.get("Retry-After")
        if retry_after:
            try:
                numeric_delay = float(retry_after)
            except ValueError:
                numeric_delay = None
            if numeric_delay is not None and math.isfinite(numeric_delay):
                return min(max(numeric_delay, 0.0), 60.0)
            try:
                parsed = email.utils.parsedate_to_datetime(retry_after)
                return min(max(parsed.timestamp() - time.time(), 0.0), 60.0)
            except (TypeError, ValueError, OverflowError):
                pass
        return min(2 ** (attempt - 1) + secrets.randbelow(251) / 1000, 30.0)

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        payload: Mapping[str, Any] | None = None,
        expected: Sequence[int] = (200,),
    ) -> Any:
        _https_origin(url)
        request_headers = {"Accept": "application/json", "User-Agent": USER_AGENT}
        request_headers.update(headers or {})
        body = None
        if payload is not None:
            body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            request_headers["Content-Type"] = "application/json"

        for attempt in range(1, self.max_attempts + 1):
            request = urllib.request.Request(
                url, data=body, headers=request_headers, method=method
            )
            try:
                with self.opener.open(request, timeout=self.timeout) as response:
                    status = response.status
                    response_body = response.read()
                    response_headers = response.headers
            except urllib.error.HTTPError as exc:
                status = exc.code
                response_body = exc.read()
                response_headers = exc.headers
                if status in RETRYABLE_STATUS_CODES and attempt < self.max_attempts:
                    delay = self._retry_delay(dict(response_headers.items()), attempt)
                    LOG.warning(
                        "HTTP %s from %s; retrying in %.1fs", status, url, delay
                    )
                    self.sleeper(delay)
                    continue
                detail = _api_error_detail(response_body)
                raise SyncError(
                    f"{method} {url} returned HTTP {status}: {detail}"
                ) from exc
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                if attempt < self.max_attempts:
                    delay = self._retry_delay({}, attempt)
                    LOG.warning(
                        "request to %s failed (%s); retrying in %.1fs", url, exc, delay
                    )
                    self.sleeper(delay)
                    continue
                raise SyncError(
                    f"{method} {url} failed after {attempt} attempts: {exc}"
                ) from exc

            if status not in expected:
                detail = _api_error_detail(response_body)
                raise SyncError(f"{method} {url} returned HTTP {status}: {detail}")
            if not response_body:
                return {}
            try:
                return json.loads(response_body)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise SyncError(f"{method} {url} returned invalid JSON") from exc

        raise AssertionError("unreachable")


def _api_error_detail(body: bytes) -> str:
    try:
        value = json.loads(body)
        if isinstance(value, dict):
            error = value.get("error")
            if isinstance(error, dict):
                return str(error.get("message") or error.get("code") or error)[:500]
            errors = value.get("errors")
            if errors:
                return str(errors)[:500]
    except (UnicodeDecodeError, json.JSONDecodeError):
        pass
    text = body.decode("utf-8", errors="replace").strip()
    return text[:500] or "empty response"


def fetch_cloudflare_cidrs(
    client: HttpClient, config: Config
) -> tuple[tuple[str, ...], str]:
    url = f"{config.cloudflare_api_url}/ips"
    response = client.request("GET", url)
    if not isinstance(response, dict) or response.get("success") is not True:
        detail = (
            response.get("errors", response) if isinstance(response, dict) else response
        )
        raise SyncError(f"Cloudflare API reported an error: {detail!r}")
    result = response.get("result")
    if not isinstance(result, dict):
        raise SyncError("Cloudflare API response does not contain a result object")

    values: list[str] = []
    for enabled, key in (
        (config.include_ipv4, "ipv4_cidrs"),
        (config.include_ipv6, "ipv6_cidrs"),
    ):
        if not enabled:
            continue
        cidrs = result.get(key)
        if not isinstance(cidrs, list) or not cidrs:
            raise SyncError(f"Cloudflare API returned no {key}")
        values.extend(cidrs)

    try:
        networks = canonical_cidrs(values, "Cloudflare API response")
    except ConfigError as exc:
        raise SyncError(str(exc)) from exc
    return networks, str(result.get("etag", "unknown"))


def sanitize_rule(rule: Mapping[str, Any]) -> dict[str, Any]:
    """Convert a response rule into the accepted set_rules request shape."""
    clean: dict[str, Any] = {}
    for key in RULE_KEYS:
        value = rule.get(key)
        if value is None or value == []:
            continue
        if key in {"source_ips", "destination_ips"}:
            if not isinstance(value, list):
                raise SyncError(f"Hetzner returned a rule with invalid {key}")
            try:
                clean[key] = list(canonical_cidrs(value, f"Hetzner rule {key}"))
            except ConfigError as exc:
                raise SyncError(str(exc)) from exc
        elif key == "port":
            clean[key] = str(value)
        else:
            clean[key] = value
    if not isinstance(clean.get("direction"), str) or not isinstance(
        clean.get("protocol"), str
    ):
        raise SyncError("Hetzner returned an incomplete firewall rule")
    return clean


def is_managed_rule(rule: Mapping[str, Any], prefix: str) -> bool:
    description = rule.get("description")
    return isinstance(description, str) and description.startswith(prefix)


def build_managed_rules(
    cidrs: Iterable[str], ports: Iterable[int], prefix: str
) -> list[dict[str, Any]]:
    sources = list(canonical_cidrs(cidrs, "managed source CIDRs"))
    if not sources:
        raise SyncError("refusing to create web rules without source CIDRs")
    return [
        {
            "direction": "in",
            "source_ips": sources,
            "protocol": "tcp",
            "port": str(port),
            "description": f"{prefix} Cloudflare TCP/{port}",
        }
        for port in sorted(set(ports))
    ]


def _unrestricted_tcp_ranges(restricted_ports: Iterable[int]) -> tuple[str, ...]:
    """Return the TCP port ranges outside the Cloudflare-only ports."""
    ranges: list[str] = []
    start = 1
    for port in sorted(set(restricted_ports)):
        if start < port:
            end = port - 1
            ranges.append(str(start) if start == end else f"{start}-{end}")
        start = port + 1
    if start <= 65535:
        ranges.append(str(start) if start == 65535 else f"{start}-65535")
    return tuple(ranges)


def build_passthrough_rules(
    restricted_ports: Iterable[int], prefix: str
) -> list[dict[str, Any]]:
    """Allow everything Hetzner can filter except the restricted TCP ports.

    Hetzner Cloud Firewalls have an implicit inbound deny. These rules make the
    firewall transparent to SSH, SMTP and all other non-web traffic while the
    Cloudflare rules remain the only rules that admit the restricted ports.
    """
    public_dual_stack = ["0.0.0.0/0", "::/0"]
    rules = [
        {
            "direction": "in",
            "source_ips": public_dual_stack,
            "protocol": "tcp",
            "port": port_range,
            "description": f"{prefix} unrestricted TCP/{port_range}",
        }
        for port_range in _unrestricted_tcp_ranges(restricted_ports)
    ]
    rules.extend(
        [
            {
                "direction": "in",
                "source_ips": public_dual_stack,
                "protocol": "udp",
                "port": "1-65535",
                "description": f"{prefix} unrestricted UDP",
            },
            {
                "direction": "in",
                "source_ips": public_dual_stack,
                "protocol": "icmp",
                "description": f"{prefix} unrestricted ICMP",
            },
            {
                "direction": "in",
                "source_ips": public_dual_stack,
                "protocol": "esp",
                "description": f"{prefix} unrestricted ESP",
            },
            {
                "direction": "in",
                "source_ips": ["0.0.0.0/0"],
                "protocol": "gre",
                "description": f"{prefix} unrestricted GRE (IPv4)",
            },
        ]
    )
    return rules


def _port_rule_overlaps(value: Any, managed_ports: set[int]) -> bool:
    if value is None or value == "":
        return True
    text = str(value)
    try:
        if "-" in text:
            start_text, end_text = text.split("-", 1)
            start, end = int(start_text), int(end_text)
            if not 1 <= start <= end <= 65535:
                return True
            return any(start <= port <= end for port in managed_ports)
        port = int(text)
        return port in managed_ports if 1 <= port <= 65535 else True
    except ValueError:
        return True


def find_conflicting_rules(
    rules: Iterable[Mapping[str, Any]],
    *,
    managed_ports: Iterable[int],
    allowed_sources: Iterable[str],
    prefix: str,
) -> list[str]:
    ports = set(managed_ports)
    allowed = [ipaddress.ip_network(value) for value in allowed_sources]
    conflicts: list[str] = []

    for index, rule in enumerate(rules, start=1):
        if is_managed_rule(rule, prefix):
            continue
        if rule.get("direction") != "in" or rule.get("protocol") != "tcp":
            continue
        if not _port_rule_overlaps(rule.get("port"), ports):
            continue
        sources = rule.get("source_ips")
        unsafe: list[str] = []
        if not isinstance(sources, list) or not sources:
            unsafe.append("all sources")
        else:
            for source in sources:
                try:
                    network = ipaddress.ip_network(source, strict=True)
                except ValueError:
                    unsafe.append(str(source))
                    continue
                if isinstance(network, ipaddress.IPv4Network):
                    permitted_source = any(
                        isinstance(permitted, ipaddress.IPv4Network)
                        and network.subnet_of(permitted)
                        for permitted in allowed
                    )
                else:
                    permitted_source = any(
                        isinstance(permitted, ipaddress.IPv6Network)
                        and network.subnet_of(permitted)
                        for permitted in allowed
                    )
                if not permitted_source:
                    unsafe.append(str(network))
        if unsafe:
            label = rule.get("description") or f"rule #{index}"
            conflicts.append(
                f"{label} (port {rule.get('port') or 'any'}; {', '.join(unsafe)})"
            )
    return conflicts


def _rule_fingerprints(rules: Iterable[Mapping[str, Any]]) -> list[str]:
    return sorted(
        json.dumps(sanitize_rule(rule), sort_keys=True, separators=(",", ":"))
        for rule in rules
    )


def rules_equal(
    left: Iterable[Mapping[str, Any]], right: Iterable[Mapping[str, Any]]
) -> bool:
    return _rule_fingerprints(left) == _rule_fingerprints(right)


class HetznerClient:
    def __init__(self, http: HttpClient, config: Config, token: str) -> None:
        self.http = http
        self.config = config
        self.headers = {"Authorization": f"Bearer {token}"}

    def get_firewall(self) -> dict[str, Any]:
        response = self.http.request(
            "GET",
            f"{self.config.hetzner_api_url}/firewalls/{self.config.firewall_id}",
            headers=self.headers,
        )
        firewall = response.get("firewall") if isinstance(response, dict) else None
        if not isinstance(firewall, dict) or not isinstance(
            firewall.get("rules"), list
        ):
            raise SyncError("Hetzner API returned an invalid firewall response")
        return firewall

    def set_rules(self, rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
        response = self.http.request(
            "POST",
            (
                f"{self.config.hetzner_api_url}/firewalls/"
                f"{self.config.firewall_id}/actions/set_rules"
            ),
            headers=self.headers,
            payload={"rules": rules},
            expected=(200, 201),
        )
        if not isinstance(response, dict):
            raise SyncError("Hetzner API returned an invalid set_rules response")
        actions = response.get("actions")
        if actions is None and isinstance(response.get("action"), dict):
            actions = [response["action"]]
        if actions is None:
            actions = []
        if not isinstance(actions, list) or not all(
            isinstance(item, dict) for item in actions
        ):
            raise SyncError("Hetzner API returned invalid firewall actions")
        return actions

    def wait_for_actions(self, actions: Iterable[Mapping[str, Any]]) -> None:
        pending: dict[int, Mapping[str, Any]] = {}
        for action in actions:
            action_id = action.get("id")
            if isinstance(action_id, bool) or not isinstance(action_id, int):
                raise SyncError("Hetzner returned a firewall action without a valid ID")
            pending[action_id] = action
        deadline = time.monotonic() + self.config.action_timeout_seconds

        while pending:
            for action_id, initial in list(pending.items()):
                action = initial
                if action.get("status") == "running":
                    response = self.http.request(
                        "GET",
                        f"{self.config.hetzner_api_url}/firewalls/actions/{action_id}",
                        headers=self.headers,
                    )
                    action = (
                        response.get("action") if isinstance(response, dict) else None
                    )
                    if not isinstance(action, dict):
                        raise SyncError(
                            f"Hetzner returned an invalid action {action_id}"
                        )
                    pending[action_id] = action

                status = action.get("status")
                if status == "success":
                    del pending[action_id]
                elif status == "error":
                    error = action.get("error") or "unknown error"
                    raise SyncError(
                        f"Hetzner firewall action {action_id} failed: {error}"
                    )
                elif status != "running":
                    raise SyncError(
                        f"Hetzner firewall action {action_id} has status {status!r}"
                    )

            if pending:
                if time.monotonic() >= deadline:
                    ids = ", ".join(str(value) for value in sorted(pending))
                    raise SyncError(f"timed out waiting for Hetzner action(s): {ids}")
                time.sleep(1.0)


def reconcile(
    config: Config,
    http: HttpClient,
    token: str,
    *,
    dry_run: bool,
) -> bool:
    cloudflare_cidrs, etag = fetch_cloudflare_cidrs(http, config)
    allowed_sources = canonical_cidrs(
        (*cloudflare_cidrs, *config.extra_source_cidrs), "all allowed source CIDRs"
    )
    LOG.info("received %d Cloudflare networks (etag %s)", len(cloudflare_cidrs), etag)

    hetzner = HetznerClient(http, config, token)
    firewall = hetzner.get_firewall()
    current_rules = firewall["rules"]
    unmanaged_rules = [
        sanitize_rule(rule)
        for rule in current_rules
        if not is_managed_rule(rule, config.description_prefix)
    ]

    if config.strict_web_rules:
        conflicts = find_conflicting_rules(
            unmanaged_rules,
            managed_ports=config.ports,
            allowed_sources=allowed_sources,
            prefix=config.description_prefix,
        )
        if conflicts:
            details = "\n  - ".join(conflicts)
            raise SyncError(
                "unmanaged inbound TCP rules expose a managed web port to unapproved sources:\n"
                f"  - {details}\n"
                "remove or narrow those rules, add trusted CIDRs to "
                "extra_source_cidrs, or explicitly disable strict_web_rules"
            )

    desired_rules = (
        unmanaged_rules
        + build_managed_rules(allowed_sources, config.ports, config.description_prefix)
        + build_passthrough_rules(config.ports, config.description_prefix)
    )
    if rules_equal(current_rules, desired_rules):
        LOG.info(
            "firewall %s is already current; no update needed",
            firewall.get("name", config.firewall_id),
        )
        return False

    old_managed_count = len(current_rules) - len(unmanaged_rules)
    new_managed_count = len(desired_rules) - len(unmanaged_rules)
    if dry_run:
        LOG.info(
            "dry-run: would replace %d managed rule(s) with %d rule(s); "
            "%d unmanaged rule(s) stay intact",
            old_managed_count,
            new_managed_count,
            len(unmanaged_rules),
        )
        return True

    LOG.info(
        "updating firewall %s: %d managed rule(s), %d unmanaged rule(s) preserved",
        firewall.get("name", config.firewall_id),
        new_managed_count,
        len(unmanaged_rules),
    )
    latest = hetzner.get_firewall()
    if not rules_equal(latest["rules"], current_rules):
        raise SyncError(
            "firewall rules changed during synchronization; refusing to overwrite "
            "the concurrent change"
        )
    actions = hetzner.set_rules(desired_rules)
    hetzner.wait_for_actions(actions)

    verified = hetzner.get_firewall()
    if not rules_equal(verified["rules"], desired_rules):
        raise SyncError(
            "Hetzner accepted the update, but the resulting rules do not match"
        )
    LOG.info("firewall update completed and verified")
    return True


def acquire_lock(path: str):
    try:
        flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags, 0o600)
        handle = os.fdopen(descriptor, "r+", encoding="utf-8")
    except OSError as exc:
        raise SyncError(f"cannot open lock file {path}: {exc}") from exc
    try:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        handle.close()
        raise SyncError("another synchronization is already running") from exc
    return handle


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Synchronize Cloudflare proxy IP ranges to a Hetzner Cloud Firewall."
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("config.toml"),
        help="TOML config (default: config.toml)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="validate and show intent without updating",
    )
    parser.add_argument(
        "--no-lock",
        action="store_true",
        help="do not acquire the configured lock file",
    )
    parser.add_argument(
        "--log-level",
        choices=("DEBUG", "INFO", "WARNING", "ERROR"),
        default="INFO",
        help="logging verbosity (default: INFO)",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(message)s",
    )
    lock_handle = None
    try:
        config = load_config(args.config)
        token = os.environ.get(config.token_env, "").strip()
        if not token and config.env_file:
            token = (
                read_env_value(Path(config.env_file), config.token_env) or ""
            ).strip()
        if not token:
            raise ConfigError(
                "the environment variable configured by hetzner.token_env is not set and no value "
                "was found in the configured env file"
            )
        if not args.no_lock:
            lock_handle = acquire_lock(config.lock_file)
        http = JsonHttpClient(
            timeout=config.request_timeout_seconds,
            max_attempts=config.max_attempts,
        )
        reconcile(config, http, token, dry_run=args.dry_run)
        return 0
    except (ConfigError, SyncError) as exc:
        LOG.error("%s", exc)
        return 1
    except KeyboardInterrupt:
        LOG.error("interrupted")
        return 130
    finally:
        if lock_handle is not None:
            lock_handle.close()


if __name__ == "__main__":
    sys.exit(main())
