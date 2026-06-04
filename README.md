# netbox-scanner

`netbox-scanner` is a Python 3.10+ CLI for scanning NetBox IP ranges, verifying host liveness, and optionally writing IP address records back to NetBox.

## Features

- NetBox integration through `pynetbox` with YAML config-file credentials
- Prefix-driven scan selection with interactive multi-select (or config/CLI CIDRs)
- Skip list for IP range names via config `skip_ranges` or `--skip-range`
- Skip entire IP ranges by NetBox Role via config `skip_roles` (default: `DHCP Pool`) or `--skip-role`
- Deduplicated scan targets across overlapping ranges
- Reserved/excluded NetBox IP ranges and local exclusion files applied before any scan traffic
- Two-step liveness verification: ICMP ping (always) plus nmap confirmation on limited service ports
- Default `services` profile scans TCP 22, 23, 80, 443, 445 and UDP 161 only
- Phantom suspect detection for ping-only replies (e.g. switch/router proxy responses)
- Informational DNS lookup (PTR, A, CNAME) for hostname hints — never blocks writes
- DNS drift correction when NetBox `dns_name` differs from PTR (previous name appended to `description`)
- Optional CheckMK 2.4+ REST lookup per verified host; assign a NetBox tag when the host exists in CheckMK
- Verified hosts are written to NetBox by default; use `--no-auto-confirm`, `--confirm`, or `--dry-run` to change behavior
- Configurable named scan profiles and `--speed` to nmap timing template mapping
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
4. Otherwise no file (you must pass `--config` or create one of the files above)

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

Edit the copy and set `netbox.base_url` and `netbox.api_token` (both required). NetBox credentials are read from the config file only (shell environment variables are not used). Both **v1** tokens (`Authorization: Token …`) and **v2** tokens from NetBox 4.5+ (`nbt_…` with `Authorization: Bearer …`) are detected automatically from the token string.

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

Use `--speed polite` or `--speed sneaky` and increase `scan_rate_limit` in config to reduce scan aggressiveness. Keep `netbox.rate_limit` at `0` for fast interactive setup; that delay only affects NetBox API calls during prefix selection and planning, not the host scan loop.

During a run, prefixes and IP ranges are fetched once and cached on the client so setup does not repeat `prefixes.all()` or `ip_ranges.all()` before scanning.

Only one scan may run at a time: the default lock file is `~/.netbox-scanner.lock` (override with `scanner.lock_file`). It is created when a run starts and removed on normal exit, errors, or Ctrl+C; stale locks from crashed processes are replaced automatically.

DNS (PTR, A, CNAME) is collected for reporting and as the `dns_name` written to NetBox. DNS never gates liveness or blocks writes. When an existing NetBox `dns_name` differs from PTR, the scanner updates it and appends `Previous dns_name: … (netbox-scanner)` to the IP address `description`.

### CheckMK tagging (optional)

Set `checkmk.enabled: true` in your config to query CheckMK 2.4+ (Community Edition) for each **verified** host using the REST API (`host_config/collections/all` filtered by `attributes.ipaddress`). Create the NetBox tag first (Extras → Tags), then set `checkmk.tag_slug` (default `checkmk`). The tag is applied only when CheckMK returns a host for that IP; absence of the tag implies the host was not found in CheckMK (or has not been scanned as verified yet).

Authentication uses `Authorization: Bearer <automation_user> <automation_secret>`. Each lookup is a separate API call (`checkmk.rate_limit` adds delay between calls). FIND lines include `CheckMK=yes`, `CheckMK=no`, or the CheckMK host name when enabled.

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
- `extras > tags`: read (tag must exist before assignment)

## Choosing what to scan

Each run prints a **Run Configuration** table (profile, speed, target mode, host count, write mode, and related settings) before scanning begins. When a host is **verified**, the CLI prints a **FIND** line with IP, PTR hostname, open ports, and whether it was added to NetBox (or why not).

By default, the CLI fetches **prefixes** from NetBox and prompts you to pick one or more. The list shows **parent prefixes** (site aggregates) and **standalone** prefixes: rows with NetBox `_depth` greater than zero or a containing prefix in the fetched set are hidden. The **Site** column uses NetBox `scope` (or legacy `site`). The **Scan targets** column shows NetBox `children` when set, otherwise the count of leaf CIDRs that would be scanned. Selecting a parent scans **leaf child prefix CIDRs** (for example `/24` subnets under a `/16`). If a parent has no children, the parent CIDR is scanned. Use `--prefix` with a child CIDR to drill into one subnet only. Before you choose, answer **Show child prefixes?** to print which leaf CIDRs each parent row will scan.

**Scan targets** (during the scan) are usable host addresses in those prefix CIDRs (not NetBox IP range records). **IP ranges** within the selected prefixes are used only to **exclude** addresses (reserved/excluded ranges, `skip_ranges`, and `skip_roles`).

Skip IP ranges by **name** via config or CLI (exclusions):

```yaml
scanner:
  skip_ranges:
    - "reserved-loopbacks"
    - "mgmt-excluded"
```

```bash
python -m netbox_scanner.cli --skip-range "reserved-loopbacks" --dry-run
```

In **prefix mode**, `skip_roles` excludes **NetBox IP range** address spans (for example a DHCP pool from `10.0.0.50`–`10.0.0.200` inside a child `/24`), not whole prefixes or subnets. The scanner loads all `ip_ranges` once, matches each range’s assigned role against config (case-insensitive; spaces and hyphens equivalent, e.g. `DHCP Pool` / `DHCP-Pool` / `dhcp-pool`), and skips only overlapping IPs. This is separate from `skip_ranges` (by range name) and from reserved/excluded ranges.

```yaml
scanner:
  skip_roles:
    - "DHCP Pool"
```

Set `skip_roles: []` in config to disable role-based skipping. Use `--skip-role` to add roles on the CLI (config defaults still apply unless cleared in config):

```bash
python -m netbox_scanner.cli --skip-role "VIP Pool" --dry-run
```

For scheduled/unattended runs, set parent or standalone prefix CIDRs in config (parent entries expand to child prefixes automatically):

```yaml
scanner:
  prefixes:
    - "10.114.0.0/16"
    - "10.200.0.0/24"
  skip_ranges:
    - "do-not-scan"
```

## Usage

**Interactive (default)** — pick prefixes from a numbered list:

```bash
python -m netbox_scanner.cli --dry-run
```

**Explicit prefix CIDR(s)** (parent or child drill-down):

```bash
python -m netbox_scanner.cli --prefix 10.114.0.0/16 --dry-run
python -m netbox_scanner.cli --prefix 10.114.50.0/24 --dry-run
```

**Legacy name-based selection** (still supported):

```bash
python -m netbox_scanner.cli --ranges "Branch A" --dry-run
```

Scan-only (no NetBox writes):

```bash
python -m netbox_scanner.cli --prefix 10.10.0.0/24 --no-auto-confirm
```

Interactive confirmation per verified record:

```bash
python -m netbox_scanner.cli --prefix 10.10.0.0/24 --confirm
```

Dry-run (show planned creates/updates without writing):

```bash
python -m netbox_scanner.cli --prefix 10.10.0.0/24 --dry-run
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
python -m netbox_scanner.cli --schedule "0 2 * * *"
```

Scheduled runs do not support `--confirm`. NetBox writes are enabled by default; use `--no-auto-confirm` or `--dry-run` to disable them.

## Tests

Run the unit tests with:

```bash
python -m unittest discover -s tests -v
```
