from __future__ import annotations

from rich.console import Console

DEFAULT_WIDTH = 80
NARROW_WIDTH = 80
LIST_PREVIEW_LIMIT = 10
TRUNCATE_SUFFIX = "…"
MIN_TRUNCATABLE_LEN = 8


def effective_width(console: Console | None) -> int:
    if console is not None and console.width:
        return console.width
    return DEFAULT_WIDTH


def is_narrow(console: Console | None, threshold: int = NARROW_WIDTH) -> bool:
    return effective_width(console) <= threshold


def truncate(text: str, max_len: int, suffix: str = TRUNCATE_SUFFIX) -> str:
    if max_len <= 0:
        return suffix if text else ""
    if len(text) <= max_len:
        return text
    if max_len <= len(suffix):
        return suffix[:max_len]
    return text[: max_len - len(suffix)] + suffix


def format_list_preview(items: list[str], *, limit: int = LIST_PREVIEW_LIMIT) -> str:
    if not items:
        return "-"
    if len(items) <= limit:
        return ", ".join(items)
    shown = ", ".join(items[:limit])
    return f"{shown}, ... (+{len(items) - limit} more)"


def fit_line(parts: list[str], max_width: int, sep: str = "  ") -> str:
    line = sep.join(parts)
    if max_width <= 0 or len(line) <= max_width:
        return line

    working = list(parts)
    truncatable = [index for index in range(len(working)) if index > 0]

    while truncatable:
        line = sep.join(working)
        if len(line) <= max_width:
            return line
        longest_index = max(truncatable, key=lambda index: len(working[index]))
        if len(working[longest_index]) <= MIN_TRUNCATABLE_LEN:
            truncatable.remove(longest_index)
            continue
        working[longest_index] = truncate(working[longest_index], len(working[longest_index]) - 1)

    return sep.join(working)
