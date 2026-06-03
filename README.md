# netbox-scanner
Project Prompt: netbox-scanner — NetBox-Integrated Subnet Scanner
Build a Linux command-line tool in Python called netbox-scanner that integrates with a NetBox IPAM instance to perform subnet discovery, port scanning, and DNS verification, with confirmed results written back to NetBox as IP Address records.

Core Requirements
NetBox Integration

Connect via pynetbox using a configurable base URL and API token (config file or env var)
Pull prefixes to scan by one or more IP Range names passed as CLI args — collect all matches into a list (duplicates by name are expected and supported)
Pull NetBox IP Ranges flagged as reserved/excluded and skip those IPs before any scan traffic is sent
Write verified IP Address records to NetBox only — no device or interface association
Writes gated by --confirm (interactive y/n per record) or --auto-confirm (batch approve all)

Scanning Engine

ICMP ping first-pass liveness check before any nmap scan
Port scanning via python-nmap
Named scan profiles defined in config as arrays of ports or nmap flag strings:

e.g., default, full, web, media, stealth


Scan aggressiveness controlled by a --speed flag mapping to nmap timing templates:

paranoid → -T0, sneaky → -T1, polite → -T2, normal → -T3 (default), aggressive → -T4, insane → -T5


--dry-run mode shows all planned NetBox writes without executing them

DNS Verification

Reverse DNS (PTR) lookup on each discovered IP
Forward DNS confirmation on the returned hostname — must resolve back to same IP
Record hostname only if both agree; flag as dns_mismatch otherwise
All mismatches logged for review

CLI Interface

Built with click
Arguments:

--ranges — one or more IP Range names (repeatable, supports duplicates)
--profile — scan profile name from config
--speed — scan aggressiveness (paranoid | sneaky | polite | normal | aggressive | insane), default normal
--dry-run
--exclude-file — optional local CIDR/IP exclusion list
--output — optional JSON or CSV export
--confirm / --auto-confirm
--schedule — cron expression to run on a schedule (uses schedule or APScheduler)



Progress & UX (CLI/ad hoc mode)

rich progress bar showing:

Current IP being scanned
Hosts completed / total
ETA based on rolling average scan time per host
Live count of: discovered, skipped (excluded), DNS verified, mismatches


Summary table printed at end of run (rich Table)
Scheduled runs log to file only (no interactive UI)


Non-Functional Requirements

Config file: ~/.netbox-scanner.conf or ./config.yaml — stores API creds, default profile, default speed, DNS servers
Structured logging to file + stdout via Python logging
Graceful handling of: NetBox API errors, unreachable hosts, DNS timeouts, nmap failures
Rate limiting on both nmap and NetBox API calls
All exclusions applied before any scan packet is sent
Unit tests for: exclusion logic, DNS double-verification, NetBox API response parsing, range name deduplication, speed flag → nmap timing mapping


Tech Stack

Python 3.10+
pynetbox, python-nmap, dnspython, click, rich, pyyaml, APScheduler
nmap must be installed on the host system
Debian/Ubuntu Linux target


Deliverables

netbox_scanner/ package — cli.py, scanner.py, netbox.py, dns_verify.py, config.py, scheduler.py
tests/ with unit tests for all core logic
config.example.yaml with every option documented
README.md — install, config, usage examples, required NetBox API permissions


That's a solid, self-contained spec. One last thing worth pinning down before you start: NetBox API token permissions — the tool only needs ipam > ip-addresses: read + write and ipam > ip-ranges: read. Worth calling that out explicitly in the README so it doesn't get handed an admin token in production.
