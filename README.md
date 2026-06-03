# netbox-scanner

`netbox-scanner` is a Python 3.10+ CLI for scanning NetBox IP ranges, verifying host liveness, and optionally writing IP address records back to NetBox.

## Features

- NetBox integration through `pynetbox` with config-file or environment-based credentials
- Prefix-driven scan selection with interactive multi-select (or config/CLI CIDRs)
- Skip list for IP range names via config `skip_ranges` or `--skip-range`
- Skip entire IP ranges by NetBox Role via config `skip_roles` (default: `DHCP Pool`) or `--skip-role`
- Deduplicated scan targets across overlapping ranges
- Reserved/excluded NetBox IP ranges and local exclusion files applied before any scan traffic
- Two-step liveness verification: ICMP ping (always) plus nmap confirmation on limited service ports
- Default `services` profile scans TCP 22, 23, 80, 443, 445 and UDP 161 only
- Phantom suspect detection for ping-only replies (e.g. switch/router proxy responses)
- Informational DNS lookup (PTR, A, CNAME) for hostname hints — never blocks writes
- DNS drift reporting when NetBox `dns_name` differs from PTR (report-only; no updates)
- Configurable named scan profiles and `--speed` to nmap timing template mapping
- `--confirm`, `--auto-confirm`, and `--dry-run` write controls
- `--max-hosts` guardrail for large ranges
- Rich CLI progress and summary output for ad hoc runs
- Cron scheduling through APScheduler with file-based logging
- JSON or CSV export of scan results

## Requirements

- Python 3.10+
- Debian/Ubuntu Linux
- `nmap` installed on the host:

```bash
sudo apt-get update
sudo apt-get install -y nmap
```

- Python packages:

```bash
python -m pip install -r requirements.txt
```

Or install as a package:

```bash
python -m pip install -e .
```

## Configuration

Configuration is YAML. Both default locations use the same format as [`config.example.yaml`](config.example.yaml). Only **one** file is loaded — they are not merged.

### Resolution order

1. `--config /path/to/file.yaml` if passed on the CLI
2. Otherwise `~/.netbox-scanner.conf` if it exists
3. Otherwise `./config.yaml` in the current working directory if it exists
4. Otherwise no file (NetBox credentials can still come from environment variables)

### When to use which

| Location | Typical use |
|----------|-------------|
| `~/.netbox-scanner.conf` | Personal token and defaults on a shared or multi-project host; works from any directory |
| `./config.yaml` | Per-checkout or per-deployment settings when you always run from the project directory |

If **both** default files exist, `~/.netbox-scanner.conf` wins and `./config.yaml` is ignored.

### Setup

```bash
cp config.example.yaml ~/.netbox-scanner.conf   # user-wide
# or
cp config.example.yaml config.yaml              # project directory
```

Edit the copy and set `netbox.base_url` and `netbox.api_token` (both required).

Environment variables override values from whichever file is loaded:

- `NETBOX_SCANNER_BASE_URL`
- `NETBOX_SCANNER_API_TOKEN`

## Liveness verification

**ICMP ping always runs first on every IP.** There is no option to skip ping.

Each IP is classified into one of three states:

| State | Meaning | NetBox write eligible? |
|-------|---------|------------------------|
| `verified` | ICMP ping succeeded and at least one scanned service port is open (default `services` profile) | Yes |
| `ping_only` | ICMP replied but no scanned service ports are open (phantom suspect) | No |
| `unreachable` | No ICMP reply | No |

With the default `services` profile, a host must have at least one of SSH (22), Telnet (23), HTTP (80), HTTPS (443), SMB (445), or SNMP (161) open to be `verified`. A router answering ICMP alone stays `ping_only`.

The opt-in `full` profile (all ports) uses nmap host-up status instead of requiring a specific open port.

Use `--speed polite` or `--speed sneaky` and increase `scan_rate_limit` in config to reduce scan aggressiveness.

DNS (PTR, A, CNAME) is collected for reporting and as an optional `dns_name` hint when writing to NetBox. DNS never gates liveness or blocks writes.

## Scan profiles

| Profile | Ports | Notes |
|---------|-------|-------|
| `services` (default) | TCP 22, 23, 80, 443, 445; UDP 161 | Requires root/cap_net_raw for `-sS`/`-sU` |
| `web` | 80, 443, 8080, 8443 | HTTP/HTTPS only |
| `stealth` | Same as services via `-sS` | TCP SYN scan of service ports |
| `full` | 1-65535 | Opt-in exhaustive scan |

Copy `config.example.yaml` to configure profiles and timing defaults.

## Required NetBox API permissions

The API token needs:

- `ipam > prefixes`: read
- `ipam > ip-ranges`: read
- `ipam > ip-addresses`: read + write

## Choosing what to scan

By default, the CLI fetches **prefixes** from NetBox and prompts you to pick one or more (no manual name entry). All **IP ranges contained in those prefixes** are included automatically, including multiple NetBox records with the same range name.

Skip IP ranges by **name** via config or CLI:

```yaml
scanner:
  skip_ranges:
    - "reserved-loopbacks"
    - "mgmt-excluded"
```

```bash
python -m netbox_scanner.cli --skip-range "reserved-loopbacks" --dry-run
```

Skip entire IP ranges by NetBox **Role** (not individual IPs within a range). By default, ranges with role `"DHCP Pool"` are excluded from the scan pool. This is separate from `skip_ranges` (by name) and from reserved/excluded ranges whose IPs are subtracted from targets inside other ranges.

```yaml
scanner:
  skip_roles:
    - "DHCP Pool"
```

Set `skip_roles: []` in config to disable role-based skipping. Use `--skip-role` to add roles on the CLI (config defaults still apply unless cleared in config):

```bash
python -m netbox_scanner.cli --skip-role "VIP Pool" --dry-run
```

For scheduled/unattended runs, set prefixes in config:

```yaml
scanner:
  prefixes:
    - "10.10.0.0/24"
    - "10.20.0.0/23"
  skip_ranges:
    - "do-not-scan"
```

## Usage

**Interactive (default)** — pick prefixes from a numbered list:

```bash
python -m netbox_scanner.cli --dry-run
```

**Explicit prefix CIDR(s):**

```bash
python -m netbox_scanner.cli --prefix 10.10.0.0/24 --prefix 10.20.0.0/23 --dry-run
```

**Legacy name-based selection** (still supported):

```bash
python -m netbox_scanner.cli --ranges "Branch A" --dry-run
```

Interactive confirmation per verified record:

```bash
python -m netbox_scanner.cli --prefix 10.10.0.0/24 --confirm
```

Batch approval:

```bash
python -m netbox_scanner.cli --prefix 10.10.0.0/24 --auto-confirm
```

Exclude additional local addresses or CIDRs:

```bash
python -m netbox_scanner.cli --prefix 10.10.0.0/24 --exclude-file ./exclude.txt
```

Limit scan size:

```bash
python -m netbox_scanner.cli --prefix 10.10.0.0/24 --max-hosts 1024
```

Export results:

```bash
python -m netbox_scanner.cli --prefix 10.10.0.0/24 --output results.json
```

Schedule recurring runs (uses `scanner.prefixes` from config):

```bash
python -m netbox_scanner.cli --schedule "0 2 * * *" --auto-confirm
```

Scheduled runs do not support `--confirm`. Use `--auto-confirm` for unattended NetBox writes.

## Tests

Run the unit tests with:

```bash
python -m unittest discover -s tests -v
```
