# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| 0.2.x | Yes |
| 0.1.x | Security fixes only |
| < 0.1 | No |

## Reporting a vulnerability

Please do **not** open a public GitHub issue for security problems.

Use GitHub's private vulnerability reporting: open the repository's
**Security** tab, choose **Report a vulnerability**, and describe the
issue with reproduction steps. You can also contact the maintainer
directly if you prefer.

You will receive an acknowledgment within a week. Fixes are released on
the normal release cadence once a patch is ready, and you will be
credited in the changelog unless you prefer otherwise.

## Scope notes

PortWatch is a scanning tool; the areas most worth scrutinizing are:

- **Banner handling** — banners from remote servers are attacker-controlled
  input. They are decoded with `errors="replace"` and length-capped before
  rendering, but any new use of banner data should keep that treatment.
- **Target expansion** — CIDR expansion is capped to prevent accidental
  wide-area sweeps; changes to `MAX_CIDR_HOSTS` handling deserve care.
- **File writing** — `-o/--output` writes to any path the user can open;
  there is deliberately no path allowlist.

## Scanning ethics

Please only scan networks and hosts you own or are explicitly authorized
to test. A TCP connect scan is fully visible in target connection logs.
