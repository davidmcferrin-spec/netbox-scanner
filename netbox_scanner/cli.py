from __future__ import annotations

import logging
from functools import partial

import click
from rich.console import Console
from rich.progress import BarColumn, Progress, TextColumn, TimeRemainingColumn
from rich.table import Table

from .config import configure_logging, load_config
from .netbox import NetBoxClient
from .scanner import NetworkScanner, export_results
from .scheduler import run_on_schedule


LOGGER = logging.getLogger(__name__)
console = Console()


def _render_summary(summary) -> None:
    table = Table(title="Scan Summary")
    table.add_column("Metric")
    table.add_column("Value", justify="right")
    table.add_row("Hosts total", str(summary.total_hosts))
    table.add_row("Hosts completed", str(summary.hosts_completed))
    table.add_row("Discovered", str(summary.discovered))
    table.add_row("Skipped", str(summary.skipped))
    table.add_row("DNS verified", str(summary.dns_verified))
    table.add_row("Mismatches", str(summary.mismatches))
    console.print(table)


def _render_planned_writes(summary) -> None:
    planned = [result for result in summary.results if result.netbox_payload]
    if not planned:
        return

    table = Table(title="Planned NetBox Writes")
    table.add_column("IP")
    table.add_column("Hostname")
    table.add_column("Payload")
    for result in planned:
        table.add_row(result.ip, result.hostname or "", str(result.netbox_payload))
    console.print(table)


def _confirm_write(result) -> bool:
    hostname = result.hostname or "<none>"
    return click.confirm(f"Write {result.ip} ({hostname}) to NetBox?", default=False)


def _run_scan(
    *,
    config_path: str | None,
    ranges: tuple[str, ...],
    profile: str | None,
    speed: str | None,
    dry_run: bool,
    exclude_file: str | None,
    output: str | None,
    confirm: bool,
    auto_confirm: bool,
    interactive: bool,
) -> None:
    config = load_config(config_path)
    configure_logging(config.logging)
    chosen_profile = profile or config.scanner.default_profile
    chosen_speed = speed or config.scanner.default_speed

    client = NetBoxClient(
        config.netbox.base_url,
        config.netbox.api_token,
        timeout=config.netbox.timeout,
        rate_limit=config.netbox.rate_limit,
    )
    scanner = NetworkScanner(config=config, netbox_client=client)

    if interactive:
        with Progress(
            TextColumn("{task.fields[current_ip]}", justify="left"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total}"),
            TimeRemainingColumn(),
            TextColumn(
                "discovered={task.fields[discovered]} "
                "skipped={task.fields[skipped]} "
                "verified={task.fields[verified]} "
                "mismatches={task.fields[mismatches]}"
            ),
            console=console,
        ) as progress:
            task_id = progress.add_task(
                "scan",
                total=1,
                current_ip="waiting",
                discovered=0,
                skipped=0,
                verified=0,
                mismatches=0,
            )

            def progress_callback(summary, result):
                progress.update(
                    task_id,
                    total=max(summary.total_hosts, 1),
                    completed=summary.hosts_completed,
                    current_ip=result.ip,
                    discovered=summary.discovered,
                    skipped=summary.skipped,
                    verified=summary.dns_verified,
                    mismatches=summary.mismatches,
                )

            summary = scanner.run(
                range_names=list(ranges),
                profile=chosen_profile,
                speed=chosen_speed,
                exclude_file=exclude_file,
                dry_run=dry_run,
                auto_confirm=auto_confirm,
                approval_callback=_confirm_write if confirm and not auto_confirm else None,
                progress_callback=progress_callback,
            )
    else:
        summary = scanner.run(
            range_names=list(ranges),
            profile=chosen_profile,
            speed=chosen_speed,
            exclude_file=exclude_file,
            dry_run=dry_run,
            auto_confirm=auto_confirm,
            approval_callback=None,
            progress_callback=None,
        )

    if output:
        export_results(summary, output)
        LOGGER.info("Wrote scan results to %s", output)

    if interactive:
        _render_summary(summary)
        if dry_run:
            _render_planned_writes(summary)


@click.command()
@click.option("--config", "config_path", type=click.Path(dir_okay=False, path_type=str))
@click.option("--ranges", "ranges", multiple=True, required=True, help="NetBox IP Range name. Repeatable.")
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
@click.option("--schedule", type=str, help="Cron expression for scheduled runs.")
def main(
    config_path: str | None,
    ranges: tuple[str, ...],
    profile: str | None,
    speed: str | None,
    dry_run: bool,
    exclude_file: str | None,
    output: str | None,
    confirm: bool,
    auto_confirm: bool,
    schedule: str | None,
) -> None:
    if confirm and auto_confirm:
        raise click.UsageError("Use either --confirm or --auto-confirm, not both.")

    runner = partial(
        _run_scan,
        config_path=config_path,
        ranges=ranges,
        profile=profile,
        speed=speed,
        dry_run=dry_run,
        exclude_file=exclude_file,
        output=output,
        confirm=confirm,
        auto_confirm=auto_confirm,
        interactive=schedule is None,
    )
    if schedule:
        run_on_schedule(schedule, runner)
        return
    runner()


if __name__ == "__main__":
    main()
