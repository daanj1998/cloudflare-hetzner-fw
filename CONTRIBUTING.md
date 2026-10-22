# Contributing

Thank you for considering a contribution to `cf-hetzner-fw`.

## Before opening an issue

- Search existing issues first.
- Do not include API tokens, firewall exports, public IP addresses, or other
  sensitive infrastructure details.
- For vulnerabilities, follow [SECURITY.md](SECURITY.md) instead of opening a
  public issue.

## Development

The project supports Python 3.11 and newer and intentionally uses only the
standard library. Keep changes focused and preserve that property unless a
dependency provides a clear security or maintenance benefit.

Run the tests before submitting a change:

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q cf_hetzner_fw.py tests
ruff check .
ruff format --check .
```

When behavior changes, add or update tests and documentation. Use English for
code, comments, commit messages, issue reports, and documentation.

## Pull requests

Keep pull requests small enough to review. Explain the problem, the chosen
solution, and any effect on existing firewall rules. Never test a pull request
against production infrastructure without an explicit dry run and a recovery
path.
