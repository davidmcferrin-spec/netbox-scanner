from __future__ import annotations

import logging
import sys
from functools import partial

import click
from rich.console import Console
from rich.progress import BarColumn, Progress, TextColumn, TimeRemainingColumn
from rich.table import Table

from .config import AppConfig, configure_logging, load_config, validate_config
from .netbox import NetBoxClient, apply_skip_ranges, apply_skip_roles
from .scanner import NetworkScanner, export_results
from .scheduler import run_on_schedule
from .selection import prompt_prefix_selection, render_range_plan


LOGGER = logging.getLogger(__name__)
console = Console()


def _render_summary(summary) -> None:
    table = Table(title="Scan Summary")
    table.add_column("Metric")
    table.add_column("Value", justify="right")
    table.add_row("Hosts total", str(summary.total_hosts))
    table.add_row("Hosts completed", str(summary.hosts_completed))
    table.add_row("Verified alive", str(summary.verified))
    table.add_row("Phantom suspects", str(summary.ping_only))
    table.add_row("Unreachable", str(summary.unreachable))
    table.add_row("Excluded", str(summary.excluded))
    table.add_row("PTR found", str(summary.ptr_found))
    table.add_row("NetBox created", str(summary.netbox_created))
    table.add_row("NetBox existing", str(summary.netbox_existing))
    table.add_row("NetBox drift", str(summary.netbox_drift))
    console.print(table)


def _render_planned_writes(summary) -> None:
    planned = [
        result
        for result in summary.results
        if result.netbox_payload and result.netbox_status in ("planned", "not_found", "dry_run")
    ]
    drift = [result for result in summary.results if result.netbox_status == "drift"]
    phantoms = [result for result in summary.results if result.liveness == "ping_only"]

    if phantoms:
        table = Table(title="Phantom Suspects (ping only)")
        table.add_column("IP")
        table.add_column("PTR hostname")
        table.add_column("Open ports")
        for result in phantoms:
            table.add_row(
                result.ip,
                result.ptr_hostname or "",
                ",".join(str(port) for port in result.open_ports) or "-",
            )
        console.print(table)

    if planned:
        table = Table(title="Planned NetBox Writes")
        table.add_column("IP")
        table.add_column("PTR hostname")
        table.add_column("Payload")
        for result in planned:
            table.add_row(result.ip, result.ptr_hostname or "", str(result.netbox_payload))
        console.print(table)

    if drift:
        table = Table(title="DNS Drift (report only)")
        table.add_column("IP")
        table.add_column("PTR hostname")
        table.add_column("NetBox dns_name")
        for result in drift:
            table.add_row(result.ip, result.ptr_hostname or "", result.netbox_dns_name or "")
        console.print(table)


def _confirm_write(result) -> bool:
    hostname = result.ptr_hostname or "<none>"
    return click.confirm(f"Write {result.ip} ({hostname}) to NetBox?", default=False)


def _log_summary(summary) -> None:
    LOGGER.info(
        "Scan complete total=%s completed=%s verified=%s ping_only=%s unreachable=%s excluded=%s "
        "ptr_found=%s netbox_created=%s netbox_existing=%s netbox_drift=%s",
        summary.total_hosts,
        summary.hosts_completed,
        summary.verified,
        summary.ping_only,
        summary.unreachable,
        summary.excluded,
        summary.ptr_found,
        summary.netbox_created,
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
):
    skip_name_set = set(skip_ranges)

    if ranges:
        all_ranges = client.fetch_scan_ranges(list(ranges))
        scan_ranges = apply_skip_ranges(all_ranges, skip_ranges)
        scan_ranges = apply_skip_roles(scan_ranges, skip_roles)
        if not scan_ranges:
            raise click.ClickException(
                "All IP ranges were skipped by skip_ranges or skip_roles configuration."
            )
        if interactive:
            render_range_plan(
                all_ranges,
                skipped_names=skip_name_set,
                skip_roles=skip_roles,
                console=console,
            )
        return None, scan_ranges

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
        prefix_records = client.fetch_prefixes()
        selected_prefixes = prompt_prefix_selection(prefix_records, console=console)

    all_ranges = client.fetch_ranges_within_prefixes(selected_prefixes)
    if not all_ranges:
        prefix_list = ", ".join(selected_prefixes)
        raise click.ClickException(f"No IP ranges found within prefixes: {prefix_list}")

    scan_ranges = apply_skip_ranges(all_ranges, skip_ranges)
    scan_ranges = apply_skip_roles(scan_ranges, skip_roles)
    if not scan_ranges:
        raise click.ClickException(
            "All IP ranges were skipped by skip_ranges or skip_roles configuration."
        )

    if interactive:
        render_range_plan(
            all_ranges,
            skipped_names=skip_name_set,
            skip_roles=skip_roles,
            console=console,
        )

    return selected_prefixes, scan_ranges


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
    config = load_config(config_path)
    validate_config(config)
    configure_logging(config.logging)
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
    scanner = NetworkScanner(config=config, netbox_client=client)

    _, scan_ranges = _resolve_scan_targets(
        client,
        config,
        ranges=ranges,
        prefixes=prefixes,
        skip_ranges=skip_ranges,
        skip_roles=skip_roles,
        interactive=interactive,
        scheduled=scheduled,
    )

    run_kwargs = {
        "profile": chosen_profile,
        "speed": chosen_speed,
        "exclude_file": exclude_file,
        "dry_run": dry_run,
        "auto_confirm": auto_confirm,
        "max_hosts": max_hosts,
        "scan_ranges": scan_ranges,
    }

    if interactive:
        with Progress(
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
            console=console,
        ) as progress:
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
                approval_callback=_confirm_write if confirm and not auto_confirm else None,
                progress_callback=progress_callback,
            )
    else:
        summary = scanner.run(
            **run_kwargs,
            approval_callback=None,
            progress_callback=None,
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
@click.option("--auto-confirm", is_flag=True, help="Approve all NetBox writes.")
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
    if confirm and auto_confirm:
        raise click.UsageError("Use either --confirm or --auto-confirm, not both.")
    if schedule and confirm:
        raise click.UsageError(
            "--confirm is not supported with --schedule. Use --auto-confirm for unattended NetBox writes."
        )
    if schedule and not dry_run and not auto_confirm:
        click.echo(
            "Warning: scheduled runs without --auto-confirm will scan and report drift "
            "but will not write to NetBox.",
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
