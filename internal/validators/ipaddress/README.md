# IP Address Validator

Detects IPv4 and IPv6 addresses in scanned content, with sensitivity filtering
so non-identifying ranges (private, reserved, test) score lower than routable
public addresses.

## What it detects

- IPv4 addresses and IPv4 with CIDR notation (e.g. documentation range `192.0.2.0/24`)
- IPv6 full, compressed (`2001:db8::8a2e:370:7334`), and CIDR notation
- IPv6 with embedded IPv4
- Classification of each match as private, public, reserved, or test

> Example addresses in this README use the RFC 5737 / RFC 3849 documentation
> ranges (`192.0.2.0/24`, `2001:db8::/32`) on purpose, so the repo's own
> ferret-scan pre-commit hook does not flag the docs.

## Validation pipeline

1. **Regex match** - IPv4 / IPv6 / CIDR patterns
2. **Parse validation** - Must parse as a valid IP via Go's `net` package
3. **Test-range filter** - RFC test / documentation ranges are down-weighted
4. **Type classification** - Loopback, link-local, multicast, private, reserved
5. **Confidence scoring** - Base + type adjustment + context keyword analysis

## Confidence factors

| Factor | Weight | Description |
|--------|--------|-------------|
| Valid Format | 20% | Matches an IP address pattern |
| Valid IP | 20% | Parses as a valid IP (Go `net` package) |
| Not Test IP | 25% | Does not match RFC test ranges |
| Not Reserved | 15% | Higher confidence for non-reserved ranges |
| Reasonable Use | 20% | Context-appropriate IP address usage |

## Usage

```bash
ferret-scan --file network-config.txt --checks IP_ADDRESS
ferret-scan --file server-logs.log --checks IP_ADDRESS --confidence medium
ferret-scan --file infrastructure.json --checks IP_ADDRESS --verbose
```
