# netbox-scanner

`netbox-scanner` is a Python 3.10+ CLI for scanning NetBox IP ranges, double-verifying DNS, and optionally writing verified IP address records back to NetBox.

## Features

- NetBox integration through `pynetbox` with config-file or environment-based credentials
- Repeatable `--ranges` support, including duplicate names
- Reserved/excluded NetBox IP ranges and local exclusion files applied before any scan traffic
- ICMP ping first-pass liveness checks followed by `python-nmap` scans
- Configurable named scan profiles and `--speed` to nmap timing template mapping
- PTR + forward DNS verification before any NetBox write
- `--confirm`, `--auto-confirm`, and `--dry-run` write controls
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
python -m pip install pynetbox python-nmap dnspython click rich pyyaml APScheduler
```

## Configuration

The scanner reads configuration from the first file it finds:

1. `~/.netbox-scanner.conf`
2. `./config.yaml`

You can also override NetBox credentials with environment variables:

- `NETBOX_SCANNER_BASE_URL`
- `NETBOX_SCANNER_API_TOKEN`

Copy `config.example.yaml` and adjust values for your environment.

## Required NetBox API permissions

The API token needs:

- Read access to IP ranges
- Read/write access to IP addresses

## Usage

```bash
python -m netbox_scanner.cli \
  --ranges "Branch A" \
  --ranges "Branch A" \
  --profile web \
  --speed normal \
  --dry-run
```

Interactive confirmation per verified record:

```bash
python -m netbox_scanner.cli --ranges "Branch A" --confirm
```

Batch approval:

```bash
python -m netbox_scanner.cli --ranges "Branch A" --auto-confirm
```

Exclude additional local addresses or CIDRs:

```bash
python -m netbox_scanner.cli --ranges "Branch A" --exclude-file ./exclude.txt
```

Export results:

```bash
python -m netbox_scanner.cli --ranges "Branch A" --output results.json
python -m netbox_scanner.cli --ranges "Branch A" --output results.csv
```

Schedule recurring runs with cron syntax:

```bash
python -m netbox_scanner.cli --ranges "Branch A" --schedule "0 * * * *"
```

## Tests

Run the unit tests with:

```bash
python -m unittest discover -s tests -v
```