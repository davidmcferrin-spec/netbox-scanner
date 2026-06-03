from __future__ import annotations

import click
from rich.console import Console
from rich.table import Table

from .netbox import PrefixRecord


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


def prompt_prefix_selection(prefixes: list[PrefixRecord], *, console: Console | None = None) -> list[str]:
    if not prefixes:
        raise click.ClickException("No NetBox prefixes found.")

    output = console or Console()
    table = Table(title="NetBox Prefixes")
    table.add_column("#", justify="right")
    table.add_column("Prefix")
    table.add_column("Description")
    table.add_column("Site")
    for index, prefix in enumerate(prefixes, start=1):
        table.add_row(
            str(index),
            prefix.prefix,
            prefix.description,
            prefix.site or "",
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
    console: Console | None = None,
) -> None:
    output = console or Console()
    table = Table(title="Scan Plan")
    table.add_column("Prefix")
    table.add_column("Range name")
    table.add_column("Start")
    table.add_column("End")
    table.add_column("Status")
    for record in ranges:
        skipped = record.name in skipped_names
        table.add_row(
            record.prefix or "",
            record.name,
            record.start_address,
            record.end_address,
            "skipped" if skipped else "scan",
        )
    output.print(table)
