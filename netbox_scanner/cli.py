from __future__ import annotations

import logging
import sys
from dataclasses import dataclass
from functools import partial
from pathlib import Path

import click
from rich.console import Console
from rich.progress import BarColumn, Progress, TextColumn, TimeRemainingColumn
from rich.table import Table

from .config import AppConfig, _select_config_path, configure_logging, load_config, validate_config
from .netbox import (
    NetBoxClient,
    PrefixRecord,
    RangeRecord,
    netbox_authorization_scheme,
    apply_skip_ranges,
    apply_skip_roles,
    expand_prefixes_to_scan_cidrs,
    iter_unique_targets,
    iter_unique_targets_from_prefixes,
    prefixes_for_display,
)
from .scanner import NetworkScanner, ScanResult, export_results, timing_for_speed
from .run_lock import RunLockError, run_lock
from .scheduler import run_on_schedule
from .selection import prompt_prefix_selection, render_prefix_scan_plan, render_range_plan
from .terminal import effective_width, fit_line, format_list_preview, is_narrow


LOGGER = logging.getLogger("netbox_scanner.cli")
console = Console()


def _clear_interactive_console() -> None:
    if sys.stdout.isatty():
        console.clear(home=True)


@dataclass(slots=True)
class ResolvedScanTargets:
    legacy_ranges: bool
    selection_source: str
    selected_display_prefixes: list[str] | None
    scan_prefixes: list[str] | None
    scan_ranges: list[RangeRecord] | None
    legacy_plan_ranges: list[RangeRecord] | None
    exclusion_ranges: list[RangeRecord] | None
    skip_name_set: set[str]


def _config_source_label(config_path: str | None) -> str:
    if config_path:
        return str(Path(config_path).expanduser())
    selected = _select_config_path(None)
    if selected and selected.exists():
        return str(selected)
    return "no config file loaded (use --config, ~/.netbox-scanner.conf, or ./config.yaml)"


def _run_style(*, interactive: bool, scheduled: bool) -> str:
    if scheduled:
        return "scheduled"
    if interactive:
        return "interactive"
    return "unattended"


def _selection_source(
    *,
    ranges: tuple[str, ...],
    prefixes: tuple[str, ...],
    interactive: bool,
    scheduled: bool,
) -> str:
    if ranges:
        return "--ranges"
    if prefixes:
        return "--prefix"
    if scheduled:
        return "config prefixes (scheduled)"
    if not sys.stdin.isatty():
        return "config prefixes (non-interactive)"
    return "interactive prefix picker"


def _value_column_width(output_console: Console | None = None) -> int:
    return max(30, effective_width(output_console) - 22)


def _write_mode_label(*, dry_run: bool, confirm: bool, auto_confirm: bool) -> str:
    if dry_run:
        return "dry-run (no NetBox writes)"
    if confirm:
        return "confirm each write"
    if auto_confirm:
        return "auto-confirm (write and update verified hosts)"
    return "scan only (--no-auto-confirm)"


def _profile_ports_label(config: AppConfig, profile: str) -> str:
    items = config.scanner.profiles.get(profile, [])
    ports = [item for item in items if not item.startswith("-")]
    if ports:
        return ", ".join(ports)
    return "see config"


def _preview_host_count(
    resolved: ResolvedScanTargets,
    *,
    max_hosts: int | None,
) -> tuple[str, int | None]:
    try:
        if resolved.legacy_ranges:
            assert resolved.scan_ranges is not None
            targets = iter_unique_targets(resolved.scan_ranges, max_hosts=max_hosts)
        else:
            assert resolved.scan_prefixes is not None
            targets = iter_unique_targets_from_prefixes(resolved.scan_prefixes, max_hosts=max_hosts)
        count = len(targets)
        label = str(count)
        if max_hosts is not None:
            label = f"{count} (limit --max-hosts {max_hosts})"
        return label, count
    except ValueError as exc:
        return f"preview failed: {exc}", None


def render_run_configuration(
    *,
    config: AppConfig,
    config_path: str | None,
    resolved: ResolvedScanTargets,
    profile: str,
    speed: str,
    skip_ranges: list[str],
    skip_roles: list[str],
    dry_run: bool,
    confirm: bool,
    auto_confirm: bool,
    exclude_file: str | None,
    output: str | None,
    max_hosts: int | None,
    interactive: bool,
    scheduled: bool,
    host_count_label: str,
    console: Console | None = None,
) -> None:
    output_console = console or Console()
    nmap_timing = timing_for_speed(speed)

    table = Table(title="Run Configuration")
    value_max = _value_column_width(output_console)
    table.add_column("Setting", no_wrap=True)
    table.add_column("Value", overflow="fold", max_width=value_max)

    table.add_row("Run style", _run_style(interactive=interactive, scheduled=scheduled))
    table.add_row("Config source", _config_source_label(config_path))
    table.add_row("Log level", config.logging.level)
    table.add_row("Log file", config.logging.file)
    table.add_row(
        "Log console",
        "file only (Rich UI)" if interactive else "stderr (compact)",
    )

    table.add_row("NetBox URL", config.netbox.base_url)
    table.add_row(
        "API token",
        "configured" if config.netbox.api_token.strip() else "missing",
    )

    target_mode = "legacy IP ranges" if resolved.legacy_ranges else "prefix"
    table.add_row("Target mode", target_mode)
    table.add_row("Selection source", resolved.selection_source)
    if resolved.legacy_ranges:
        range_names = [record.name for record in resolved.scan_ranges or []]
        table.add_row("IP ranges to scan", format_list_preview(range_names))
    else:
        table.add_row(
            "Selected prefixes",
            format_list_preview(resolved.selected_display_prefixes or []),
        )
        table.add_row(
            "Scan prefix CIDRs",
            format_list_preview(resolved.scan_prefixes or []),
        )
    table.add_row("Hosts to scan", host_count_label)

    table.add_row("Profile", profile)
    table.add_row("Nmap speed", f"{speed} ({nmap_timing})")
    table.add_row("Profile ports/args", _profile_ports_label(config, profile))
    table.add_row("Scan delay (s/host)", str(config.scanner.scan_rate_limit))
    table.add_row("Ping timeout (s)", str(config.scanner.ping_timeout))
    table.add_row(
        "DNS servers",
        ", ".join(config.dns.servers) if config.dns.servers else "(system default)",
    )
    table.add_row("DNS timeout (s)", str(config.dns.timeout))
    table.add_row("NetBox HTTP timeout (s)", str(config.netbox.timeout))
    table.add_row("NetBox API delay (s)", str(config.netbox.rate_limit))

    table.add_row("Skip range names", format_list_preview(skip_ranges))
    table.add_row("Skip range roles", format_list_preview(skip_roles))
    table.add_row("Exclude file", exclude_file or "-")

    table.add_row("NetBox writes", _write_mode_label(dry_run=dry_run, confirm=confirm, auto_confirm=auto_confirm))
    table.add_row("Max hosts", str(max_hosts) if max_hosts is not None else "-")
    table.add_row("Output", output or "-")

    output_console.print(table)


def log_run_configuration(
    *,
    config: AppConfig,
    config_path: str | None,
    resolved: ResolvedScanTargets,
    profile: str,
    speed: str,
    dry_run: bool,
    confirm: bool,
    auto_confirm: bool,
    exclude_file: str | None,
    output: str | None,
    max_hosts: int | None,
    interactive: bool,
    scheduled: bool,
    host_count_label: str,
) -> None:
    target_mode = "legacy_ranges" if resolved.legacy_ranges else "prefix"
    scan_cidr_count = len(resolved.scan_prefixes or [])
    scan_range_count = len(resolved.scan_ranges or [])
    LOGGER.info(
        "Run configuration style=%s config_source=%s target_mode=%s selection_source=%s "
        "profile=%s speed=%s nmap_timing=%s dry_run=%s confirm=%s auto_confirm=%s "
        "hosts=%s scan_prefixes=%s scan_ranges=%s max_hosts=%s netbox_url=%s api_token_set=%s",
        _run_style(interactive=interactive, scheduled=scheduled),
        _config_source_label(config_path),
        target_mode,
        resolved.selection_source,
        profile,
        speed,
        timing_for_speed(speed),
        dry_run,
        confirm,
        auto_confirm,
        host_count_label,
        scan_cidr_count,
        scan_range_count,
        max_hosts,
        config.netbox.base_url,
        bool(config.netbox.api_token.strip()),
    )


def netbox_write_dns_name(result: ScanResult) -> str | None:
    payload = result.netbox_payload or {}
    dns_name = payload.get("dns_name")
    if dns_name:
        return str(dns_name)
    if result.ptr_hostname:
        return result.ptr_hostname
    return None


def format_dns_hostname_fields(result: ScanResult) -> str:
    ptr = result.ptr_hostname or "-"
    write_dns = netbox_write_dns_name(result) or "-"
    parts = [f"PTR={ptr}", f"dns_name={write_dns}"]
    if result.netbox_dns_name and result.netbox_status in ("drift", "updated"):
        parts.append(f"NetBox-dns_name={result.netbox_dns_name}")
    elif result.netbox_dns_name and result.netbox_status == "already_exists":
        normalized_netbox = result.netbox_dns_name.rstrip(".").lower()
        normalized_ptr = (result.ptr_hostname or "").rstrip(".").lower()
        normalized_write = write_dns.rstrip(".").lower() if write_dns != "-" else ""
        if normalized_netbox not in {normalized_ptr, normalized_write}:
            parts.append(f"NetBox-dns_name={result.netbox_dns_name}")
    forward = [
        address
        for address in result.forward_addresses
        if address != result.ip
    ]
    if forward:
        parts.append(f"forward={','.join(forward)}")
    return "  ".join(parts)


def netbox_outcome_label(result: ScanResult) -> str:
    status = result.netbox_status or ""
    reason = result.reason or ""
    dns_name = netbox_write_dns_name(result)

    if result.netbox_written and status == "created":
        if dns_name:
            return f"added to NetBox (dns_name={dns_name})"
        return "added to NetBox (no dns_name)"
    if result.netbox_written and status == "updated":
        previous = result.netbox_dns_name or "(none)"
        if dns_name:
            return f"updated NetBox (dns_name={dns_name}, was {previous})"
        return f"updated NetBox (was {previous})"
    if status == "already_exists":
        return "already in NetBox"
    if status == "drift" and reason == "dry_run":
        previous = result.netbox_dns_name or "(none)"
        if dns_name:
            return f"would update NetBox (dns_name={dns_name}, was {previous})"
        return f"would update NetBox (was {previous})"
    if status == "drift":
        if result.netbox_dns_name and result.ptr_hostname:
            return (
                f"not updated (DNS drift: NetBox={result.netbox_dns_name}, PTR={result.ptr_hostname})"
            )
        return "not updated (DNS drift — report only)"
    if status == "planned" and reason == "dry_run":
        if dns_name:
            return f"would add to NetBox (dry-run, dns_name={dns_name})"
        return "would add to NetBox (dry-run, no dns_name)"
    if status == "planned" and reason == "not_confirmed":
        if dns_name:
            return f"not added (not confirmed, dns_name={dns_name})"
        return "not added (not confirmed)"
    if status == "planned":
        if dns_name:
            return f"not added (pending approval, dns_name={dns_name})"
        return "not added (pending approval)"
    if status == "not_found" and reason == "dry_run":
        if dns_name:
            return f"would add to NetBox (dry-run, dns_name={dns_name})"
        return "would add to NetBox (dry-run, no dns_name)"
    if status:
        return status.replace("_", " ")
    return "no NetBox action"


def format_verified_find_line(result: ScanResult, *, max_width: int | None = None) -> str:
    ports = ",".join(str(port) for port in result.open_ports) or "-"
    dns_fields = format_dns_hostname_fields(result)
    netbox = netbox_outcome_label(result)
    parts = [f"FIND {result.ip}", dns_fields, f"ports={ports}", f"NetBox: {netbox}"]
    if max_width is None:
        return "  ".join(parts)
    return fit_line(parts, max_width)


def _find_line_markup(display_line: str) -> str:
    if "NetBox: " in display_line:
        head, netbox = display_line.rsplit("NetBox: ", 1)
        head = head.replace("FIND", "[bold green]FIND[/bold green]", 1)
        return f"{head}NetBox: [cyan]{netbox}[/cyan]"
    return display_line.replace("FIND", "[bold green]FIND[/bold green]", 1)


def _print_find_line(display_line: str, *, output_console: Console) -> None:
    output_console.print(_find_line_markup(display_line))


def report_verified_find(
    result: ScanResult,
    *,
    console: Console | None = None,
    logger: logging.Logger | None = None,
    print_to_console: bool = True,
    progress: Progress | None = None,
) -> None:
    if result.liveness != "verified":
        return
    if logger is not None:
        logger.info(format_verified_find_line(result))
    if not print_to_console:
        return
    output_console = console or (progress.console if progress is not None else None)
    if output_console is None:
        return
    display_line = format_verified_find_line(
        result,
        max_width=effective_width(output_console),
    )
    markup = _find_line_markup(display_line)
    if progress is not None:
        progress.console.print(markup, markup=True)
        return
    _print_find_line(display_line, output_console=output_console)


def _render_summary(summary) -> None:
    value_max = _value_column_width(console)
    table = Table(title="Scan Summary")
    table.add_column("Metric", no_wrap=True)
    table.add_column("Value", justify="right", overflow="fold", max_width=value_max)
    table.add_row("Hosts total", str(summary.total_hosts))
    table.add_row("Hosts completed", str(summary.hosts_completed))
    table.add_row("Verified alive", str(summary.verified))
    table.add_row("Phantom suspects", str(summary.ping_only))
    table.add_row("Unreachable", str(summary.unreachable))
    table.add_row("Excluded", str(summary.excluded))
    table.add_row("PTR found", str(summary.ptr_found))
    table.add_row("NetBox created", str(summary.netbox_created))
    table.add_row("NetBox updated", str(summary.netbox_updated))
    table.add_row("NetBox existing", str(summary.netbox_existing))
    table.add_row("NetBox drift (dry-run)", str(summary.netbox_drift))
    console.print(table)


def _render_planned_writes(summary) -> None:
    planned = [
        result
        for result in summary.results
        if result.netbox_payload and result.netbox_status in ("planned", "not_found", "dry_run")
    ]
    drift = [result for result in summary.results if result.netbox_status == "drift"]
    phantoms = [result for result in summary.results if result.liveness == "ping_only"]
    value_max = _value_column_width(console)

    if phantoms:
        table = Table(title="Phantom Suspects (ping only)")
        table.add_column("IP", no_wrap=True)
        table.add_column("PTR hostname", max_width=24, overflow="ellipsis")
        table.add_column("Open ports", overflow="fold", max_width=value_max)
        for result in phantoms:
            table.add_row(
                result.ip,
                result.ptr_hostname or "",
                ",".join(str(port) for port in result.open_ports) or "-",
            )
        console.print(table)

    if planned:
        table = Table(title="Planned NetBox Writes")
        table.add_column("IP", no_wrap=True)
        table.add_column("PTR hostname", max_width=24, overflow="ellipsis")
        table.add_column("Payload", overflow="fold", max_width=value_max)
        for result in planned:
            table.add_row(result.ip, result.ptr_hostname or "", str(result.netbox_payload))
        console.print(table)

    if drift:
        table = Table(title="Planned NetBox Updates (dry-run)")
        table.add_column("IP", no_wrap=True)
        table.add_column("PTR hostname", max_width=24, overflow="ellipsis")
        table.add_column("Payload", overflow="fold", max_width=value_max)
        for result in drift:
            table.add_row(result.ip, result.ptr_hostname or "", str(result.netbox_payload))
        console.print(table)


def _scan_progress(output_console: Console) -> Progress:
    if is_narrow(output_console):
        return Progress(
            TextColumn("{task.fields[current_ip]}", justify="left"),
            BarColumn(bar_width=20),
            TextColumn("{task.completed}/{task.total}"),
            TextColumn(
                "v={task.fields[verified]} "
                "p={task.fields[phantom]} "
                "e={task.fields[excluded]} "
                "d={task.fields[drift]}"
            ),
            console=output_console,
        )
    return Progress(
        TextColumn("{task.fields[current_ip]}", justify="left"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TimeRemainingColumn(),
        TextColumn(
            "verified={task.fields[verified]} "
            "phantom={task.fields[phantom]} "
            "excluded={task.fields[excluded]} "
            "drift={task.fields[drift]}"
        ),
        console=output_console,
    )


def _confirm_write(result) -> bool:
    hostname = result.ptr_hostname or "<none>"
    return click.confirm(f"Write {result.ip} ({hostname}) to NetBox?", default=False)


def _log_summary(summary) -> None:
    LOGGER.info(
        "Scan complete total=%s completed=%s verified=%s ping_only=%s unreachable=%s excluded=%s "
        "ptr_found=%s netbox_created=%s netbox_updated=%s netbox_existing=%s netbox_drift=%s",
        summary.total_hosts,
        summary.hosts_completed,
        summary.verified,
        summary.ping_only,
        summary.unreachable,
        summary.excluded,
        summary.ptr_found,
        summary.netbox_created,
        summary.netbox_updated,
        summary.netbox_existing,
        summary.netbox_drift,
    )


def _merge_skip_ranges(config: AppConfig, skip_range_flags: tuple[str, ...]) -> list[str]:
    merged: list[str] = []
    for name in [*config.scanner.skip_ranges, *skip_range_flags]:
        if name and name not in merged:
            merged.append(name)
    return merged


def _merge_skip_roles(config: AppConfig, skip_role_flags: tuple[str, ...]) -> list[str]:
    merged: list[str] = []
    for role in [*config.scanner.skip_roles, *skip_role_flags]:
        if role and role not in merged:
            merged.append(role)
    return merged


def _resolve_scan_targets(
    client: NetBoxClient,
    config: AppConfig,
    *,
    ranges: tuple[str, ...],
    prefixes: tuple[str, ...],
    skip_ranges: list[str],
    skip_roles: list[str],
    interactive: bool,
    scheduled: bool,
) -> ResolvedScanTargets:
    skip_name_set = set(skip_ranges)
    selection_source = _selection_source(
        ranges=ranges,
        prefixes=prefixes,
        interactive=interactive,
        scheduled=scheduled,
    )

    if ranges:
        all_ranges = client.fetch_scan_ranges(list(ranges))
        scan_ranges = apply_skip_ranges(all_ranges, skip_ranges)
        scan_ranges = apply_skip_roles(scan_ranges, skip_roles)
        if not scan_ranges:
            raise click.ClickException(
                "All IP ranges were skipped by skip_ranges or skip_roles configuration."
            )
        return ResolvedScanTargets(
            legacy_ranges=True,
            selection_source=selection_source,
            selected_display_prefixes=None,
            scan_prefixes=None,
            scan_ranges=scan_ranges,
            legacy_plan_ranges=all_ranges,
            exclusion_ranges=None,
            skip_name_set=skip_name_set,
        )

    all_prefixes: list[PrefixRecord] | None = None
    selected_prefixes: list[str]
    if prefixes:
        selected_prefixes = list(prefixes)
    elif scheduled or not sys.stdin.isatty():
        selected_prefixes = list(config.scanner.prefixes)
        if not selected_prefixes:
            raise click.ClickException(
                "Scheduled/unattended runs require scanner.prefixes in config, --prefix, or --ranges."
            )
    else:
        all_prefixes = client.fetch_prefixes()
        display_prefixes = prefixes_for_display(all_prefixes)
        if not display_prefixes:
            raise click.ClickException("No NetBox prefixes found.")
        selected_prefixes = prompt_prefix_selection(
            display_prefixes,
            all_prefixes=all_prefixes,
            console=console,
        )

    if all_prefixes is None:
        all_prefixes = client.fetch_prefixes()

    scan_prefixes = expand_prefixes_to_scan_cidrs(all_prefixes, selected_prefixes)
    if not scan_prefixes:
        prefix_list = ", ".join(selected_prefixes)
        raise click.ClickException(f"No scan prefixes resolved from selection: {prefix_list}")

    exclusion_ranges = client.fetch_exclusion_ranges_for_prefixes(
        scan_prefixes,
        skip_ranges,
        skip_roles,
        selected_prefix_cidrs=selected_prefixes,
    )

    return ResolvedScanTargets(
        legacy_ranges=False,
        selection_source=selection_source,
        selected_display_prefixes=selected_prefixes,
        scan_prefixes=scan_prefixes,
        scan_ranges=None,
        legacy_plan_ranges=None,
        exclusion_ranges=exclusion_ranges,
        skip_name_set=skip_name_set,
    )


def _run_scan(
    *,
    config_path: str | None,
    ranges: tuple[str, ...],
    prefixes: tuple[str, ...],
    skip_range_flags: tuple[str, ...],
    skip_role_flags: tuple[str, ...],
    profile: str | None,
    speed: str | None,
    dry_run: bool,
    exclude_file: str | None,
    output: str | None,
    confirm: bool,
    auto_confirm: bool,
    max_hosts: int | None,
    interactive: bool,
    scheduled: bool,
) -> None:
    if interactive:
        _clear_interactive_console()

    config = load_config(config_path)
    validate_config(config)
    try:
        with run_lock(config.scanner.lock_file):
            _run_scan_locked(
                config=config,
                config_path=config_path,
                ranges=ranges,
                prefixes=prefixes,
                skip_range_flags=skip_range_flags,
                skip_role_flags=skip_role_flags,
                profile=profile,
                speed=speed,
                dry_run=dry_run,
                exclude_file=exclude_file,
                output=output,
                confirm=confirm,
                auto_confirm=auto_confirm,
                max_hosts=max_hosts,
                interactive=interactive,
                scheduled=scheduled,
            )
    except RunLockError as exc:
        raise click.ClickException(str(exc)) from exc


def _run_scan_locked(
    *,
    config: AppConfig,
    config_path: str | None,
    ranges: tuple[str, ...],
    prefixes: tuple[str, ...],
    skip_range_flags: tuple[str, ...],
    skip_role_flags: tuple[str, ...],
    profile: str | None,
    speed: str | None,
    dry_run: bool,
    exclude_file: str | None,
    output: str | None,
    confirm: bool,
    auto_confirm: bool,
    max_hosts: int | None,
    interactive: bool,
    scheduled: bool,
) -> None:
    configure_logging(config.logging, console=not interactive)
    chosen_profile = profile or config.scanner.default_profile
    chosen_speed = speed or config.scanner.default_speed
    skip_ranges = _merge_skip_ranges(config, skip_range_flags)
    skip_roles = _merge_skip_roles(config, skip_role_flags)

    client = NetBoxClient(
        config.netbox.base_url,
        config.netbox.api_token,
        timeout=config.netbox.timeout,
        rate_limit=config.netbox.rate_limit,
    )
    try:
        client.verify_authentication()
    except RuntimeError as exc:
        config_source = _config_source_label(config_path)
        raise click.ClickException(
            f"{exc}\n"
            f"Config source: {config_source}.\n"
            f"Compare with: curl -H \"Authorization: "
            f"{netbox_authorization_scheme(config.netbox.api_token)} <token-from-config>\" "
            f"{config.netbox.base_url.rstrip('/')}/api/status/"
        ) from exc

    scanner = NetworkScanner(config=config, netbox_client=client)

    resolved = _resolve_scan_targets(
        client,
        config,
        ranges=ranges,
        prefixes=prefixes,
        skip_ranges=skip_ranges,
        skip_roles=skip_roles,
        interactive=interactive,
        scheduled=scheduled,
    )

    host_count_label, _ = _preview_host_count(resolved, max_hosts=max_hosts)
    render_run_configuration(
        config=config,
        config_path=config_path,
        resolved=resolved,
        profile=chosen_profile,
        speed=chosen_speed,
        skip_ranges=skip_ranges,
        skip_roles=skip_roles,
        dry_run=dry_run,
        confirm=confirm,
        auto_confirm=auto_confirm,
        exclude_file=exclude_file,
        output=output,
        max_hosts=max_hosts,
        interactive=interactive,
        scheduled=scheduled,
        host_count_label=host_count_label,
        console=console,
    )
    log_run_configuration(
        config=config,
        config_path=config_path,
        resolved=resolved,
        profile=chosen_profile,
        speed=chosen_speed,
        dry_run=dry_run,
        confirm=confirm,
        auto_confirm=auto_confirm,
        exclude_file=exclude_file,
        output=output,
        max_hosts=max_hosts,
        interactive=interactive,
        scheduled=scheduled,
        host_count_label=host_count_label,
    )

    if interactive:
        if resolved.legacy_ranges:
            render_range_plan(
                resolved.legacy_plan_ranges or [],
                skipped_names=resolved.skip_name_set,
                skip_roles=skip_roles,
                console=console,
            )
        else:
            render_prefix_scan_plan(
                scan_prefixes=resolved.scan_prefixes or [],
                exclusion_ranges=resolved.exclusion_ranges or [],
                skip_names=resolved.skip_name_set,
                skip_roles=skip_roles,
                console=console,
            )

    run_kwargs = {
        "profile": chosen_profile,
        "speed": chosen_speed,
        "exclude_file": exclude_file,
        "dry_run": dry_run,
        "auto_confirm": auto_confirm,
        "max_hosts": max_hosts,
        "skip_range_names": skip_ranges,
        "skip_role_names": skip_roles,
    }
    if resolved.legacy_ranges:
        run_kwargs["scan_ranges"] = resolved.scan_ranges
    else:
        run_kwargs["scan_prefixes"] = resolved.scan_prefixes
        run_kwargs["prefix_exclusion_ranges"] = resolved.exclusion_ranges

    if interactive:
        with _scan_progress(console) as progress:
            task_id = progress.add_task(
                "scan",
                total=1,
                current_ip="waiting",
                verified=0,
                phantom=0,
                excluded=0,
                drift=0,
            )

            def progress_callback(summary, result):
                report_verified_find(
                    result,
                    console=console,
                    logger=LOGGER,
                    progress=progress,
                )
                progress.update(
                    task_id,
                    total=max(summary.total_hosts, 1),
                    completed=summary.hosts_completed,
                    current_ip=result.ip,
                    verified=summary.verified,
                    phantom=summary.ping_only,
                    excluded=summary.excluded,
                    drift=summary.netbox_drift,
                )

            summary = scanner.run(
                **run_kwargs,
                approval_callback=_confirm_write if confirm else None,
                progress_callback=progress_callback,
            )
    else:

        def progress_callback(summary, result):
            report_verified_find(result, console=console, logger=LOGGER)

        summary = scanner.run(
            **run_kwargs,
            approval_callback=None,
            progress_callback=progress_callback,
        )

    _log_summary(summary)

    if output:
        export_results(summary, output)
        LOGGER.info("Wrote scan results to %s", output)

    if interactive:
        _render_summary(summary)
        if dry_run or summary.netbox_drift or summary.ping_only:
            _render_planned_writes(summary)


@click.command()
@click.option("--config", "config_path", type=click.Path(dir_okay=False, path_type=str))
@click.option("--ranges", "ranges", multiple=True, help="Legacy: NetBox IP Range name. Repeatable.")
@click.option("--prefix", "prefixes", multiple=True, help="Prefix CIDR to scan. Repeatable.")
@click.option("--skip-range", "skip_range_flags", multiple=True, help="IP range name to skip. Repeatable.")
@click.option("--skip-role", "skip_role_flags", multiple=True, help="IP range role to skip. Repeatable.")
@click.option("--profile", type=str, help="Configured scan profile name.")
@click.option(
    "--speed",
    type=click.Choice(["paranoid", "sneaky", "polite", "normal", "aggressive", "insane"]),
    default=None,
    help="nmap timing aggressiveness.",
)
@click.option("--dry-run", is_flag=True, help="Show planned NetBox writes without writing them.")
@click.option("--exclude-file", type=click.Path(exists=True, dir_okay=False, path_type=str))
@click.option("--output", type=click.Path(dir_okay=False, path_type=str))
@click.option("--confirm/--no-confirm", default=False, help="Interactively confirm each NetBox write.")
@click.option("--auto-confirm/--no-auto-confirm", default=True, help="Write verified hosts to NetBox without prompts.")
@click.option("--max-hosts", type=int, default=None, help="Abort if deduplicated target count exceeds this limit.")
@click.option("--schedule", type=str, help="Cron expression for scheduled runs.")
def main(
    config_path: str | None,
    ranges: tuple[str, ...],
    prefixes: tuple[str, ...],
    skip_range_flags: tuple[str, ...],
    skip_role_flags: tuple[str, ...],
    profile: str | None,
    speed: str | None,
    dry_run: bool,
    exclude_file: str | None,
    output: str | None,
    confirm: bool,
    auto_confirm: bool,
    max_hosts: int | None,
    schedule: str | None,
) -> None:
    if schedule and confirm:
        raise click.UsageError(
            "--confirm is not supported with --schedule. Use --auto-confirm for unattended NetBox writes."
        )
    if schedule and not dry_run and not auto_confirm:
        click.echo(
            "Warning: scheduled runs with --no-auto-confirm will scan but will not write to NetBox.",
            err=True,
        )

    runner = partial(
        _run_scan,
        config_path=config_path,
        ranges=ranges,
        prefixes=prefixes,
        skip_range_flags=skip_range_flags,
        skip_role_flags=skip_role_flags,
        profile=profile,
        speed=speed,
        dry_run=dry_run,
        exclude_file=exclude_file,
        output=output,
        confirm=confirm,
        auto_confirm=auto_confirm,
        max_hosts=max_hosts,
        interactive=schedule is None,
        scheduled=schedule is not None,
    )
    if schedule:
        run_on_schedule(schedule, runner)
        return
    runner()


if __name__ == "__main__":
    main()
