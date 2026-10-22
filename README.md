# Cloudflare IP ranges for a Hetzner Cloud Firewall

`cf-hetzner-fw` keeps the public Cloudflare proxy networks synchronized with an
existing Hetzner Cloud Firewall. Only Cloudflare and explicitly trusted CIDRs
can reach the origin on the configured TCP ports (80 and 443 by default).

The synchronizer is conservative and idempotent. It owns only rules whose
description starts with `cf-hetzner-fw:` and preserves every other rule. Because
Hetzner Cloud Firewalls implicitly deny inbound traffic that is not explicitly
allowed, the tool also creates passthrough rules for traffic outside the
restricted TCP ports. This prevents the firewall from unintentionally blocking
SSH, SMTP, and other services.

## Features

- Fetches IPv4 and IPv6 ranges from Cloudflare's public `GET /client/v4/ips`
  endpoint.
- Strictly validates and canonicalizes every CIDR.
- Preserves all firewall rules it does not own.
- Refuses an update by default if an unmanaged rule exposes a restricted port
  to an unapproved source.
- Changes the firewall only when the desired rules differ.
- Detects concurrent firewall edits before writing.
- Waits for asynchronous Hetzner actions and verifies the final rule set.
- Includes bounded retries, `Retry-After` support, timeouts, logging, and a
  process lock.
- Uses only the Python standard library.

## Security model

This tool blocks direct connections from arbitrary internet addresses, even if
the client supplies the expected `Host` header. Cloudflare proxy addresses are
shared by many customers, however. An IP allowlist proves that a connection
passed through Cloudflare, not that it belongs to your Cloudflare zone.

For stronger origin authentication, also consider:

- [Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/),
  so the origin does not need a publicly reachable web port;
- [Authenticated Origin Pulls](https://developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/)
  with a zone-specific certificate; and
- a web server configuration that accepts only the expected hostnames.

See Cloudflare's guidance on how to
[protect an origin server](https://developers.cloudflare.com/fundamentals/security/protect-your-origin-server/).

Hetzner combines the rules of all firewalls attached to a server. Another
attached firewall that allows `0.0.0.0/0` or `::/0` on a restricted port still
makes that port public. This tool checks only the configured firewall.

## Requirements

- Linux with Python 3.11 or newer;
- an existing Hetzner Cloud Firewall attached to the intended server or
  servers;
- a project-scoped Hetzner Cloud API token with **Read & Write** permission;
- proxied (orange-cloud) Cloudflare DNS records for the site.

Use a dedicated firewall for this tool when practical. Before enabling it,
check that the origin address is not exposed through DNS-only records, mail
infrastructure, or old configuration.

## Installation with systemd

The repository includes a hardened oneshot service and an hourly timer:

```bash
sudo install -d -m 0755 /usr/local/lib/cf-hetzner-fw
sudo install -m 0755 cf_hetzner_fw.py /usr/local/lib/cf-hetzner-fw/

sudo install -d -m 0755 /etc/cf-hetzner-fw
sudo install -m 0644 config.example.toml /etc/cf-hetzner-fw/config.toml
sudo install -m 0644 systemd/cf-hetzner-fw.service /etc/systemd/system/
sudo install -m 0644 systemd/cf-hetzner-fw.timer /etc/systemd/system/
```

Set at least the firewall ID:

```bash
sudoedit /etc/cf-hetzner-fw/config.toml
```

Create the credentials file. Do not include literal angle brackets around the
real token:

```bash
sudo sh -c 'umask 077; printf "%s\n" "HCLOUD_TOKEN=your_token" > /etc/cf-hetzner-fw/credentials'
```

The TOML configuration contains no secrets and can be read by the dynamic
systemd user. The credentials file remains mode `0600`; systemd reads it before
starting the service under its temporary user.

## First safe run

Start with a dry run. `--no-lock` is needed here because systemd normally
creates the runtime directory that contains the lock:

```bash
export HCLOUD_TOKEN='your_token'
python3 cf_hetzner_fw.py \
  --config /etc/cf-hetzner-fw/config.toml \
  --dry-run \
  --no-lock
```

If the target firewall already has a public web rule, strict mode stops the
sync. Two safe migration strategies are:

1. Create an unattached firewall, synchronize it, remove public web rules from
   other attached firewalls, and then attach the new firewall.
2. Set `strict_web_rules = false` for one sync so the Cloudflare rules are
   added, remove the public web rule, and immediately enable strict mode again.

The synchronizer adds passthrough rules for SSH, SMTP, and other non-web
traffic. Even so, keep a second management channel available while changing
firewall rules.

After checking the dry-run output, perform the update and enable the timer:

```bash
sudo systemctl daemon-reload
sudo systemctl start cf-hetzner-fw.service
sudo systemctl enable --now cf-hetzner-fw.timer
```

Inspect its status and logs with:

```bash
systemctl status cf-hetzner-fw.timer
journalctl -u cf-hetzner-fw.service
systemctl list-timers cf-hetzner-fw.timer
```

The timer runs approximately once per hour with up to ten minutes of random
jitter.

## Configuration

Copy [`config.example.toml`](config.example.toml) and adjust it for your
firewall.

| Setting | Default | Purpose |
|---|---:|---|
| `hetzner.firewall_id` | required | Numeric ID of the existing firewall |
| `hetzner.token_env` | `HCLOUD_TOKEN` | Name of the environment variable, not the token itself |
| `hetzner.env_file` | `.env` | Dotenv file next to the TOML file; absolute paths are also accepted |
| `cloudflare.include_ipv4` | `true` | Include Cloudflare IPv4 ranges |
| `cloudflare.include_ipv6` | `true` | Include Cloudflare IPv6 ranges |
| `firewall.ports` | `[80, 443]` | TCP ports limited to approved sources |
| `firewall.extra_source_cidrs` | `[]` | Additional trusted sources in CIDR notation |
| `firewall.strict_web_rules` | `true` | Stop when an unmanaged rule conflicts with a restricted port |
| `firewall.description_prefix` | `cf-hetzner-fw:` | Ownership marker for managed rules |
| `runtime.request_timeout_seconds` | `15` | Timeout for each HTTP attempt |
| `runtime.max_attempts` | `4` | Maximum attempts for transient failures |
| `runtime.action_timeout_seconds` | `120` | Maximum wait for Hetzner actions |
| `runtime.lock_file` | `/run/cf-hetzner-fw/sync.lock` | Absolute path of the process lock |

Use `/32` for one IPv4 address and `/128` for one IPv6 address. Host bits in a
network, such as `192.0.2.5/24`, are rejected; use `192.0.2.0/24` instead.

Do not change `description_prefix` after the first run without manually
removing rules that use the old prefix. Otherwise, those rules become
unmanaged and remain in place.

### Strict mode

Strict mode inspects unmanaged inbound TCP rules that overlap a restricted
port. Conflicts include:

- `0.0.0.0/0` or `::/0` on port 80;
- a rule without a source or port restriction; and
- a range such as `80-443` from an unapproved network.

An SSH rule on port 22 does not conflict. A broad management rule from
`203.0.113.10/32` is accepted if that address is also listed in
`extra_source_cidrs`.

## Manual use

For local runs, the script can read the token from `.env`:

```bash
cp .env.example .env
chmod 600 .env
```

Add a newly created token as `HCLOUD_TOKEN=...`. A value already present in the
process environment takes precedence over the dotenv file.

```bash
python3 cf_hetzner_fw.py --config config.toml --dry-run --no-lock
python3 cf_hetzner_fw.py --config config.toml --no-lock
```

Available options:

```text
--config PATH       TOML configuration file
--dry-run           validate and show intent without updating
--no-lock           skip the process lock (for manual testing)
--log-level LEVEL   DEBUG, INFO, WARNING, or ERROR
--version           show the program version
```

## Tests

The test suite has no third-party dependencies:

```bash
python3 -m unittest discover -s tests -v
```

The tests cover configuration and CIDR validation, deterministic rule
generation, idempotent comparison, conflict detection, and reconciliation.

## Scope and limitations

The synchronizer intentionally does not:

- create, delete, or attach firewalls;
- modify other firewalls in the project;
- change Cloudflare zones or DNS records;
- delete unmanaged firewall rules; or
- configure the web server to obtain the real client address.

Restricting only ports 80 and 443 means that other listening services remain
public. Protect those services with manual rules or a separate firewall if
needed. Protocols that Hetzner Cloud Firewalls cannot filter cannot receive a
passthrough rule and remain blocked by an attached firewall.

If the application needs the visitor's address, configure the web server to
trust headers such as `CF-Connecting-IP` only after the network layer is
correctly restricted.

## Contributing and security

Contributions are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md). Please report
security issues privately as described in [SECURITY.md](SECURITY.md).

This project is available under the [MIT License](LICENSE).
