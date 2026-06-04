# netbox-scanner

`netbox-scanner` is a Python 3.10+ CLI that discovers live hosts in NetBox-managed address space, optionally enriches records from DNS and CheckMK, and writes results back to NetBox IPAM.

Use **`python -m netbox_scanner.cli`** or the installed entry point **`netbox-scanner`** (same program).

---

## Table of contents

1. [Features](#features)
2. [Operating modes](#operating-modes)
3. [Requirements](#requirements)
4. [NetBox prerequisites](#netbox-prerequisites)
5. [Configuration](#configuration)
6. [How hosts are classified](#how-hosts-are-classified)
7. [NetBox writes, tags, and description notes](#netbox-writes-tags-and-description-notes)
8. [CheckMK integration](#checkmk-integration)
9. [Scan performance and checkpointing](#scan-performance-and-checkpointing)
10. [Stale IP policy](#stale-ip-policy)
11. [Choosing what to scan](#choosing-what-to-scan)
12. [CLI reference](#cli-reference)
13. [Usage examples](#usage-examples)
14. [Scheduled runs](#scheduled-runs)
15. [Legacy IP range mode](#legacy-ip-range-mode)
16. [Scan speeds](#scan-speeds)
17. [Runtime files](#runtime-files)
18. [Tests](#tests)
19. [Quick troubleshooting](#quick-troubleshooting)

---

## Features

- **NetBox IPAM integration** via `pynetbox` (YAML config; v1 `Token` and v2 `Bearer` API tokens).
- **Prefix-driven scanning** with interactive multi-select, config `scanner.prefixes`, or `--prefix` CIDRs (parent prefixes expand to leaf child CIDRs).
- **Legacy IP range mode** via `--ranges` (NetBox IP Range names).
- **Exclusions**: NetBox reserved/excluded ranges, `skip_ranges` (by range name), `skip_roles` (by range role, e.g. DHCP Pool), and `--exclude-file`.
- **Deduplicated targets** across overlapping ranges; **numeric IPv4 scan order** (A.B.C.D) across and within prefixes.
- **Two-tier verification**:
  - **New IPs** (not yet in NetBox for that prefix): ICMP ping, then nmap (batched by subnet, parallel workers).
  - **Existing NetBox IPs** (fast path): ICMP ping and/or PTR only — no port scan when `scanner.fast_path_existing_netbox` is true.
- **Liveness states**: `verified`, `ping_only` (phantom suspect), `unreachable`, `excluded`.
- **DNS** (PTR, forward A/CNAME) for reporting and `dns_name`; PTR wins for writes; never blocks liveness.
- **Optional CheckMK 2.4+ REST** lookup per verified host; NetBox tag when host exists in CheckMK.
- **CheckMK → NetBox `dns_name` sync** during scan (`--sync-checkmk-dns`) or backfill (`--backfill-checkmk-dns`).
- **NetBox tags**: `netbox-scanner` on verified writes; optional `checkmk`; optional `netbox-scanner-phantom` on phantoms.
- **Custom fields** on verify: last seen time/profile/ports, miss counter for stale policy.
- **Timestamped description lines** that replace prior scanner lines of the same type (no duplicate history stacks).
- **Global re-verification** of all tagged IPs (`--reverify-tagged`): ping/PTR only, no prefix scan.
- **Gap report** after prefix scans (`--gap-report`).
- **Stale policy** (`--stale-report`, `--apply-stale-deletes`): miss counter, optional delete of unassigned stale IPs.
- **Per-prefix checkpoint / resume** (`--resume`).
- **NetBox write modes**: `--dry-run`, `--confirm`, `--auto-confirm` (default), `--no-auto-confirm`.
- **`--max-hosts`** guardrail, JSON/CSV **`--output`**, Rich progress, cron **`--schedule`**, run **lock file**.

---

## Operating modes

The CLI runs in exactly one **primary mode** per invocation. Combining incompatible modes raises an error.

| Mode | Flags | Network scan? | Typical use |
|------|--------|---------------|-------------|
| **Prefix / range scan** | (default) `--prefix` and/or interactive selection; optional `--ranges` | Yes | Discover hosts, create/update NetBox IPs |
| **CheckMK DNS backfill** | `--backfill-checkmk-dns` only | No | Fill empty `dns_name` on CheckMK-tagged IPs from CheckMK |
| **Re-verify tagged** | `--reverify-tagged` only | No (ping/PTR only) | Health-check all `netbox-scanner` tagged IPs globally |
| **Stale policy only** | `--stale-report` without `--prefix`/`--ranges`/`--schedule` | No | Report or delete stale tagged IPs |

**Add-ons** (combine with prefix scan only, unless noted):

| Add-on | Flag | Notes |
|--------|------|--------|
| CheckMK DNS during scan | `--sync-checkmk-dns` | Mutually exclusive with `--backfill-checkmk-dns` |
| Gap report | `--gap-report` | After scan; needs prefix scan |
| Stale report / deletes | `--stale-report`, `--apply-stale-deletes` | After scan, or alone (see above) |
| Resume | `--resume` | Per-prefix checkpoint file |
| Dry run | `--dry-run` | No NetBox writes; stale deletes suppressed on combined scan+stale |

**Cannot combine:**

- `--sync-checkmk-dns` + `--backfill-checkmk-dns`
- `--reverify-tagged` + `--prefix` / `--ranges` / `--schedule`
- `--backfill-checkmk-dns` + `--schedule`
- `--confirm` + `--schedule`

**Mode selection (no flags):**

| Situation | What runs |
|-----------|-----------|
| `--backfill-checkmk-dns` | CheckMK DNS backfill only |
| `--reverify-tagged` | Global tagged re-verify only |
| `--stale-report` (no `--prefix` / `--ranges` / `--schedule`) | Stale policy only |
| `--schedule CRON` | Cron loop over `scanner.prefixes` |
| Otherwise | Prefix scan (interactive picker, `--prefix`, or config `scanner.prefixes` when stdin is not a TTY) |

---

## Requirements

- Python 3.10+
- Linux (ICMP `ping` and `nmap` used from the shell)
- `nmap` installed:

```bash
sudo apt-get update && sudo apt-get install -y nmap
```

- Python dependencies:

```bash
python -m pip install -r requirements.txt
# or
python -m pip install -e .
```

---

## NetBox prerequisites

Create these in NetBox **before** writing from the scanner.

### Tags (Extras → Tags)

| Slug | Required? | When applied |
|------|-----------|--------------|
| `netbox-scanner` | **Yes** (or match `scanner.verified_tag_slug`) | Every successful verify write / fast-path refresh |
| `checkmk` | If CheckMK enabled | CheckMK returns a host for that IP |
| `netbox-scanner-phantom` | Optional | `ping_only` during full port scan when IP exists in NetBox (`stale.phantom_tag_slug`) |

### Custom fields (Extras → Custom Fields → IP Address)

Slugs must match config (`scanner.custom_field_*` or defaults below):

| Slug (default) | Type (suggested) | Purpose |
|----------------|------------------|---------|
| `last_verified_at` | Text or Date/Time | UTC timestamp of last successful verify |
| `last_verified_profile` | Text | Profile name (e.g. `services`, `reverify`, `services-fast`) |
| `last_open_ports` | Text | Comma-separated ports (full scan); `none` on fast path |
| `scanner_miss_count` | Integer | Consecutive failed ping+PTR checks; reset on success |

### API token permissions

| Object | Permission |
|--------|------------|
| Prefixes | read |
| IP ranges | read |
| IP addresses | read, write |
| Tags | read (tags must exist before assignment) |
| Custom fields | read/write via IP address payload |

**Deletes** (`--apply-stale-deletes`): token must be allowed to **delete** IP address objects.

---

## Configuration

Configuration is **YAML**. Only **one** file is loaded (not merged).

| Priority | Path |
|----------|------|
| 1 | `--config /path/to/file.yaml` |
| 2 | `~/.netbox-scanner.conf` |
| 3 | `./config.yaml` in the current working directory |

```bash
cp config.example.yaml ~/.netbox-scanner.conf
# edit netbox.base_url, netbox.api_token, checkmk.*, scanner.*, stale.*
```

See [`config.example.yaml`](config.example.yaml) for every key with inline comments. Summary by section:

| Section | Purpose |
|---------|---------|
| `netbox` | API URL, token, HTTP timeout, API rate limit (planning phase) |
| `checkmk` | Optional REST integration |
| `dns` | Optional resolvers for PTR/forward lookups |
| `logging` | Level and log file path |
| `scanner` | Profiles, speeds, prefixes, fast path, parallel nmap, checkpoint path, custom field slugs, verified tag |
| `stale` | Miss threshold, delete rules, phantom tag, CheckMK exempt |

Environment variables are **not** used for credentials; use the config file only.

---

## How hosts are classified

### Full port scan path (IP **not** in NetBox for that prefix, or fast path disabled)

1. **ICMP ping** always runs first (no option to skip).
2. If ping fails → `unreachable` (no NetBox write).
3. If ping succeeds → **nmap** using the selected profile and `--speed`.
4. Classification (default `services` profile):
   - **`verified`**: at least one configured service port open → eligible for NetBox write.
   - **`ping_only`**: ping OK but no open service ports → phantom suspect (normally no write; optional phantom tag if IP record exists).

The `full` profile uses nmap host-up status instead of requiring specific open ports.

### Fast path (IP **already** in NetBox for that prefix, `scanner.fast_path_existing_netbox: true`)

1. ICMP ping and PTR lookup (no nmap).
2. **Alive** if **ping succeeds OR PTR returns a hostname** (your policy: reverse DNS means still valid).
3. Alive → treated as **`verified`** for metadata/tag updates (profile noted as `<profile>-fast`).
4. Not alive (no ping and no PTR) → `unreachable`; **`scanner_miss_count`** incremented on the NetBox record.

### Scan order

Targets are ordered by numeric IPv4 (A.B.C.D) across selected prefix CIDRs and within each subnet.

### Concurrency

- **New hosts**: nmap runs in **batches per subnet** (`scanner.nmap_batch_prefixlen`, default `/24`) with `scanner.parallel_workers` (default 4, max 16).
- **Existing hosts**: fast path is per-host ping/DNS (lightweight).

---

## NetBox writes, tags, and description notes

### Write eligibility

| State | Default NetBox write? |
|-------|------------------------|
| `verified` | Yes (with `--auto-confirm`, default) |
| `ping_only` | No (optional phantom **tag** only if record exists) |
| `unreachable` | No (fast path may update **miss count** on existing record) |
| `excluded` | No |

Use `--dry-run` to preview, `--confirm` to approve each write, or `--no-auto-confirm` for scan-only.

### `dns_name` rules

- **PTR** is written to `dns_name` when present.
- **No PTR**: full scan may set `description` with discovery note (ports, profile); may set `dns_name` from CheckMK when `--sync-checkmk-dns` and NetBox `dns_name` is empty.
- **DNS drift**: if NetBox `dns_name` differs from PTR, scanner updates `dns_name` and records previous value in `description`.
- **CheckMK** never overwrites an existing NetBox `dns_name` (PTR and existing NetBox name win).

### Description line types (replace-in-place + UTC timestamp)

Each type replaces any previous line with the same prefix:

| Line prefix | Meaning |
|-------------|---------|
| `netbox-scanner: verified (no PTR); …` | Discovery note when verified without PTR |
| `netbox-scanner: Previous dns_name: …` | Prior `dns_name` after drift correction |
| `netbox-scanner: drift: …` | PTR / NetBox / CheckMK mismatch on fast path or re-verify |
| `netbox-scanner: stale miss: …` | Miss counter progress toward stale threshold |

### Tags

- **`netbox-scanner`** (`scanner.verified_tag_slug`): applied on verified writes and successful fast-path refresh.
- **`checkmk`** (`checkmk.tag_slug`): applied only when CheckMK returns a host (not when missing).
- **`netbox-scanner-phantom`**: optional on `ping_only` when a NetBox IP object already exists.

---

## CheckMK integration

Enable in config:

```yaml
checkmk:
  enabled: true
  base_url: "https://nagios.example.com/YourSite"   # site root only, not .../check_mk/api/1.0
  automation_user: "automation"
  automation_secret: "replace-me"
  tag_slug: "checkmk"
  verify_ssl: false   # if needed for internal TLS
```

- API: `domain-types/host/collections/all` filtered by Livestatus `address`.
- Auth: `Authorization: Bearer <user> <secret>`.
- One HTTP request per IP (`checkmk.rate_limit` adds delay between calls).
- FIND lines show `CheckMK=<hostname>`, `CheckMK=no`, or omitted when disabled.

### CheckMK → NetBox `dns_name`

| Flag | When | Behavior |
|------|------|----------|
| `--sync-checkmk-dns` | During prefix/range scan | If verified, no PTR, empty NetBox `dns_name`, and CheckMK has a name → set `dns_name` |
| `--backfill-checkmk-dns` | Standalone (no scan) | All IPs tagged `checkmk` with empty `dns_name` → lookup CheckMK and update |

Requires `checkmk.enabled: true`. Mutually exclusive with each other.

```bash
python -m netbox_scanner.cli --backfill-checkmk-dns --dry-run
```

---

## Scan performance and checkpointing

| Setting | Default | Meaning |
|---------|---------|---------|
| `scanner.fast_path_existing_netbox` | `true` | Skip nmap when IP already in NetBox for prefix |
| `scanner.parallel_workers` | `4` | Concurrent nmap subnet batches (1–16) |
| `scanner.nmap_batch_prefixlen` | `24` | Group new hosts for batched nmap |
| `scanner.scan_rate_limit` | `0.5` | Seconds between nmap operations (per host or batch) |
| `scanner.ping_timeout` | `1` | ICMP timeout (seconds) |
| `scanner.checkpoint_path` | `""` → `~/.netbox-scanner-checkpoint.json` | Per-prefix progress for `--resume` |

```bash
python -m netbox_scanner.cli --prefix 10.0.0.0/16 --resume
```

Checkpoint stores completed IPs per prefix CIDR; finished prefixes are skipped on resume. Start a **new** run (delete checkpoint or new file) to rescan from scratch.

### Gap report (`--gap-report`)

Printed after a **prefix or legacy range scan** completes. Categories:

| Metric | Meaning |
|--------|---------|
| Verified, written, not in prefix index | Created in NetBox during run (edge reporting) |
| Tagged, not in this scan | Global `netbox-scanner` tag but IP not in scanned set |
| Tagged, unreachable this scan | Tagged IP failed in this scan |
| Verified, not in CheckMK | CheckMK enabled but host not found |
| Phantom suspects | `ping_only` in this scan |

---

## Stale IP policy

Configured under `stale:` (see `config.example.yaml`).

| Setting | Default | Meaning |
|---------|---------|---------|
| `scope_tag` | `netbox-scanner` | Only tagged IPs considered (global, all prefixes) |
| `miss_threshold` | `5` | Deletes considered when `scanner_miss_count` ≥ this |
| `delete_unassigned_only` | `true` | Never delete IPs assigned to a device interface |
| `exempt_checkmk` | `true` | Never delete if CheckMK has the host |
| `dry_run_deletes` | `true` | Config default: report only unless CLI applies deletes |
| `phantom_tag_slug` | `netbox-scanner-phantom` | Tag for phantoms (see above) |

**Miss counter**: incremented when an existing/tagged IP fails **both** ping and PTR (fast path or `--reverify-tagged`). Reset to `0` on success.

### CLI

| Flag | Behavior |
|------|----------|
| `--stale-report` | List tagged IPs at/above threshold; with scan, runs **after** scan over **all** tagged IPs globally |
| `--stale-report` (alone) | Same report; no network scan |
| `--apply-stale-deletes` | Actually delete qualifying IPs (still respects assigned + CheckMK exempt) |

Deletes are **not** performed when the CLI run uses `--dry-run` (including standalone stale-only runs). Review `--stale-report` before adding `--apply-stale-deletes`.

**Delete decision table** (after `scanner_miss_count` ≥ `stale.miss_threshold`, and exempt rules pass):

| CLI flags | `stale.dry_run_deletes` | Result |
|-----------|-------------------------|--------|
| `--stale-report` only | `true` (default) | Report / `would_delete` only |
| `--stale-report` + `--apply-stale-deletes` | `true` | Deletes eligible IPs |
| `--stale-report` + `--apply-stale-deletes` | `false` | Deletes eligible IPs |
| `--stale-report` only | `false` | **Deletes** without `--apply-stale-deletes` (avoid; keep default `true`) |
| Any + `--dry-run` | any | Never deletes |

```bash
# Report only (standalone)
python -m netbox_scanner.cli --stale-report

# After a scan, preview then delete
python -m netbox_scanner.cli --prefix 10.0.0.0/16 --stale-report --dry-run
python -m netbox_scanner.cli --stale-report --apply-stale-deletes
```

### Re-verify tagged (`--reverify-tagged`)

- **No** prefix selection, **no** nmap.
- Loads every NetBox IP with `scanner.verified_tag_slug` (global).
- Ping/PTR only; updates metadata, tags, drift notes; increments or resets miss count.

```bash
python -m netbox_scanner.cli --reverify-tagged
python -m netbox_scanner.cli --reverify-tagged --dry-run
```

---

## Choosing what to scan

Each run prints a **Run Configuration** table before scanning.

- **Interactive default**: pick prefixes from NetBox (parents and standalones; children hidden by depth/containment).
- **`--prefix`**: one or more CIDRs; parent expands to leaf child `/24` (etc.) unless no children.
- **`--ranges`**: legacy NetBox IP Range **names**.
- **`scanner.prefixes`**: for unattended/`--schedule` runs.

**Skip lists:**

- `skip_ranges` / `--skip-range`: exclude by IP range **name**.
- `skip_roles` / `--skip-role`: exclude addresses in ranges with matching **role** (e.g. DHCP Pool) inside selected prefixes only.

Only one scan process at a time: `~/.netbox-scanner.lock` (override `scanner.lock_file`).

---

## CLI reference

| Option | Description |
|--------|-------------|
| `--config PATH` | YAML config file |
| `--prefix CIDR` | Prefix to scan (repeatable) |
| `--ranges NAME` | Legacy NetBox IP Range name (repeatable) |
| `--skip-range NAME` | Exclude NetBox range by name (repeatable) |
| `--skip-role NAME` | Exclude ranges with role (repeatable) |
| `--profile NAME` | Scan profile from config (default `scanner.default_profile`) |
| `--speed` | `paranoid` … `insane` → nmap `-T0` … `-T5` (default from `scanner.default_speed`) |
| `--dry-run` | Plan writes only; no NetBox changes |
| `--sync-checkmk-dns` | Set `dns_name` from CheckMK during scan when allowed |
| `--backfill-checkmk-dns` | Standalone CheckMK DNS backfill mode |
| `--exclude-file PATH` | Local CIDRs/IPs to exclude |
| `--output PATH` | Export results `.json` or `.csv` |
| `--confirm` | Prompt per NetBox write |
| `--no-auto-confirm` | Scan without writing (unless dry-run planning) |
| `--auto-confirm` | Write without prompts (default) |
| `--max-hosts N` | Abort if deduplicated targets exceed N |
| `--schedule CRON` | APScheduler cron (uses `scanner.prefixes`) |
| `--resume` | Resume from checkpoint file |
| `--gap-report` | Coverage/gap summary after prefix scan |
| `--reverify-tagged` | Global ping/PTR re-verify of tagged IPs |
| `--stale-report` | Stale IP report (standalone or after scan) |
| `--apply-stale-deletes` | Delete eligible stale IPs |

---

## Usage examples

### First-time setup

```bash
cp config.example.yaml ~/.netbox-scanner.conf
# Create NetBox tags + custom fields (see NetBox prerequisites)
# Edit base_url, api_token, checkmk.* as needed
python -m netbox_scanner.cli --prefix 10.0.0.0/30 --dry-run
```

### Interactive scan with dry-run

```bash
python -m netbox_scanner.cli --dry-run
```

### Production prefix scan

```bash
python -m netbox_scanner.cli --prefix 10.114.0.0/16 --gap-report
```

### Large prefix with resume

```bash
python -m netbox_scanner.cli --prefix 10.70.0.0/16 --resume --output run.json
```

### Scan + CheckMK DNS + gap + stale preview

```bash
python -m netbox_scanner.cli --prefix 10.70.0.0/16 --sync-checkmk-dns --gap-report --stale-report --dry-run
```

### Weekly maintenance (example)

```bash
python -m netbox_scanner.cli --reverify-tagged
python -m netbox_scanner.cli --stale-report
# After review:
python -m netbox_scanner.cli --stale-report --apply-stale-deletes
```

### Scan-only (no writes)

```bash
python -m netbox_scanner.cli --prefix 10.10.0.0/24 --no-auto-confirm
```

### Interactive approval per host

```bash
python -m netbox_scanner.cli --prefix 10.10.0.0/24 --confirm
```

---

## Scheduled runs

```yaml
scanner:
  prefixes:
    - "10.114.0.0/16"
  skip_ranges:
    - "do-not-scan"
```

```bash
python -m netbox_scanner.cli --schedule "0 2 * * *"
```

- Uses `scanner.prefixes` from config (no interactive picker).
- **`--confirm` is not supported** with `--schedule`.
- Default writes enabled; use `--dry-run` or `--no-auto-confirm` in cron command if needed.
- Logs to `logging.file` (default `netbox-scanner.log`).

---

## Scan profiles

| Profile | Ports / behavior |
|---------|------------------|
| `services` (default) | TCP 22, 23, 80, 443, 445; UDP 161 (`-sS`/`-sU`; may need root/CAP_NET_RAW) |
| `web` | 80, 443, 8080, 8443 |
| `media` | 554, 8554, 1935 |
| `stealth` | `-sS` on service TCP ports |
| `full` | 1–65535 (opt-in; slow) |

Override or extend under `scanner.profiles` in config.

---

## Legacy IP range mode

Use **`--ranges NAME`** only when you must target NetBox IP Range objects by **name** (older workflow). Prefer **`--prefix` CIDR** for new deployments.

| Feature | Prefix mode (`--prefix`) | Legacy range mode (`--ranges`) |
|---------|------------------------|--------------------------------|
| Fast path (ping/PTR, no nmap) | Yes, when IP exists in prefix index | No — always full ping + nmap |
| Batched parallel nmap | Yes | Yes |
| Per-prefix `--resume` checkpoint | Yes | No |
| `--gap-report` | Yes | Yes |
| `skip_roles` inside prefix | Yes | N/A (range list defines targets) |

---

## Scan speeds

CLI `--speed` (or `scanner.default_speed` when omitted) maps to nmap timing templates:

| `--speed` | nmap flag | Typical use |
|-----------|-----------|-------------|
| `paranoid` | `-T0` | Very slow, IDS-sensitive |
| `sneaky` | `-T1` | Slow |
| `polite` | `-T2` | **Default** — balanced |
| `normal` | `-T3` | Faster |
| `aggressive` | `-T4` | Fast LAN scans |
| `insane` | `-T5` | Maximum speed |

Profiles may add scan flags (e.g. `-sS`, `-sU`); those are separate from `--speed`.

---

## Runtime files

| Path | Config key | Purpose |
|------|------------|---------|
| `~/.netbox-scanner.conf` | — | Preferred user config (first match if present) |
| `./config.yaml` | — | Project-local config |
| `~/.netbox-scanner-checkpoint.json` | `scanner.checkpoint_path` | Per-prefix scan progress for `--resume` |
| `~/.netbox-scanner.lock` | `scanner.lock_file` | Single-instance run lock |
| `netbox-scanner.log` | `logging.file` | File log (scheduled runs; all runs log here) |

---

## Tests

```bash
python -m pytest tests/ -q
# or
python -m unittest discover -s tests -v
```

---

## Quick troubleshooting

| Issue | Check |
|-------|--------|
| No writes | `--dry-run`, `--no-auto-confirm`, or evaluation returned `already_exists` |
| CheckMK always `no` | `base_url` is site root; `enabled: true`; credentials; `verify_ssl` |
| Tag API errors | Create tag in NetBox first |
| Custom field errors | Create fields with matching slugs |
| Stale never deletes | Need `--apply-stale-deletes` (and not `--dry-run`); assigned or CheckMK exempt; miss count &lt; threshold; or `stale.dry_run_deletes: true` without `--apply-stale-deletes` |
| Stale deletes unexpectedly | `stale.dry_run_deletes: false` deletes on report-only; set `true` or always use `--dry-run` first |
| Resume skips everything | Checkpoint marks prefixes complete; delete checkpoint file to restart |
| Slow huge scans | Enable fast path; tune `parallel_workers`; use `--resume` |
