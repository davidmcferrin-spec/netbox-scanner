from __future__ import annotations

import click
from rich.console import Console
from rich.table import Table

from .netbox import (
    PrefixRecord,
    children_by_parent,
    count_leaf_descendants,
    range_exclusion_reason,
    range_matches_skip_role,
)


def parse_prefix_selection(raw: str, total: int) -> list[int]:
    value = raw.strip().lower()
    if not value or value == "all":
        return list(range(1, total + 1))
    indices: list[int] = []
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        if not part.isdigit():
            raise ValueError(f"Invalid selection: {part!r}")
        index = int(part)
        if index < 1 or index > total:
            raise ValueError(f"Selection out of range: {index}")
        if index not in indices:
            indices.append(index)
    if not indices:
        raise ValueError("No prefixes selected.")
    return indices


def prompt_prefix_selection(
    prefixes: list[PrefixRecord],
    *,
    all_prefixes: list[PrefixRecord] | None = None,
    console: Console | None = None,
) -> list[str]:
    if not prefixes:
        raise click.ClickException("No NetBox prefixes found.")

    children = children_by_parent(all_prefixes or prefixes)
    output = console or Console()
    table = Table(title="NetBox Prefixes")
    table.add_column("#", justify="right")
    table.add_column("Prefix")
    table.add_column("Description")
    table.add_column("Site")
    table.add_column("Children", justify="right")
    for index, prefix in enumerate(prefixes, start=1):
        child_count = count_leaf_descendants(prefix, children=children)
        child_label = str(child_count) if child_count else "-"
        table.add_row(
            str(index),
            prefix.prefix,
            prefix.description,
            prefix.site or "",
            child_label,
        )
    output.print(table)

    while True:
        raw = click.prompt(
            "Select prefix(es) [comma-separated numbers, all]",
            default="all",
            show_default=True,
        )
        try:
            indices = parse_prefix_selection(raw, len(prefixes))
            return [prefixes[index - 1].prefix for index in indices]
        except ValueError as exc:
            click.echo(str(exc), err=True)


def render_range_plan(
    ranges: list,
    *,
    skipped_names: set[str],
    skip_roles: list[str],
    console: Console | None = None,
) -> None:
    output = console or Console()
    table = Table(title="Scan Plan (legacy IP ranges)")
    table.add_column("Prefix")
    table.add_column("Range name")
    table.add_column("Role")
    table.add_column("Start")
    table.add_column("End")
    table.add_column("Status")
    for record in ranges:
        if record.name in skipped_names:
            status = "skipped (name)"
        elif range_matches_skip_role(record, skip_roles):
            status = "skipped (role)"
        else:
            status = "scan"
        table.add_row(
            record.prefix or "",
            record.name,
            record.role_name or "",
            record.start_address,
            record.end_address,
            status,
        )
    output.print(table)


def render_prefix_scan_plan(
    *,
    scan_prefixes: list[str],
    exclusion_ranges: list,
    skip_names: set[str],
    skip_roles: list[str],
    console: Console | None = None,
) -> None:
    output = console or Console()

    prefix_table = Table(title="Scan Prefixes")
    prefix_table.add_column("Prefix")
    for cidr in scan_prefixes:
        prefix_table.add_row(cidr)
    output.print(prefix_table)

    exclusion_table = Table(title="IP Range Exclusions")
    exclusion_table.add_column("Prefix")
    exclusion_table.add_column("Range name")
    exclusion_table.add_column("Role")
    exclusion_table.add_column("Start")
    exclusion_table.add_column("End")
    exclusion_table.add_column("Reason")
    for record in exclusion_ranges:
        reason = range_exclusion_reason(record, skip_names=skip_names, skip_roles=skip_roles)
        exclusion_table.add_row(
            record.prefix or "",
            record.name,
            record.role_name or "",
            record.start_address,
            record.end_address,
            reason or "excluded",
        )
    if exclusion_ranges:
        output.print(exclusion_table)
    else:
        output.print("[dim]No IP range exclusions in selected prefixes.[/dim]")
