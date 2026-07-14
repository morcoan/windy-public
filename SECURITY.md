# Security policy

## Supported version

Security fixes are accepted for the current `0.1.x` line while it is supported.

## Reporting

Please use GitHub's private vulnerability reporting for this repository. Do not open a public issue containing exploit details, sensitive binaries, credentials, or private reverse-engineering results.

## v0.1 boundary

Windy's MCP server is intentionally unauthenticated and loopback-only. It rejects non-loopback bind addresses and non-loopback browser origins. Do not expose it through port forwarding, a reverse proxy, a tunnel, or firewall rule.

Opening a PE parses untrusted file content. Use a disposable Windows account or VM for especially hostile samples. Windy does not execute the analyzed PE, but parser defects may still be security-relevant.
