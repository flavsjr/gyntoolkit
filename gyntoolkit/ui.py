#!/usr/bin/env python3
"""Camada de apresentação com ``rich`` (tabelas, painéis, spinners).

Degrada graciosamente para ``colorama`` puro se ``rich`` não estiver instalado,
então a CLI funciona igual sem a dependência.
"""

from collections.abc import Iterable, Sequence
from contextlib import contextmanager
from typing import Any

from colorama import Fore, Style

console: Any = None
try:
    from rich import box
    from rich.console import Console
    from rich.table import Table

    RICH = True
    console = Console()
except ImportError:  # pragma: no cover - fallback sem rich
    RICH = False
    console = None


def _fmt(value: Any) -> str:
    if value is None:
        return "—"
    if isinstance(value, (list, tuple)):
        return ", ".join(str(v) for v in value) if value else "—"
    return str(value)


def success(msg: str) -> None:
    if RICH:
        console.print(f"[bold green]{msg}[/]")
    else:
        print(f"{Fore.GREEN}{msg}{Style.RESET_ALL}")


def error(msg: str) -> None:
    if RICH:
        console.print(f"[bold red]{msg}[/]")
    else:
        print(f"{Fore.RED}{msg}{Style.RESET_ALL}")


def notice(msg: str) -> None:
    if RICH:
        console.print(f"[cyan]{msg}[/]")
    else:
        print(f"{Fore.CYAN}{msg}{Style.RESET_ALL}")


def print_kv(
    title: str,
    mapping: dict[str, Any],
    warn_keys: dict[str, Any] | None = None,
) -> None:
    """Renderiza um mapa chave/valor. ``warn_keys`` marca chaves cujo valor,
    se satisfizer o predicado, deve aparecer em vermelho.

    ``warn_keys`` mapeia chave -> callable(value) -> bool.
    """
    warn_keys = warn_keys or {}
    if RICH:
        table = Table(title=title, box=box.SIMPLE_HEAVY, title_style="bold green",
                      show_header=False, expand=False)
        table.add_column("campo", style="yellow", no_wrap=True)
        table.add_column("valor", style="white")
        for k, v in mapping.items():
            predicate = warn_keys.get(k)
            style = "bold red" if predicate and predicate(v) else "white"
            table.add_row(str(k), f"[{style}]{_fmt(v)}[/]")
        console.print(table)
    else:
        print(f"\n{Fore.GREEN}{title}{Style.RESET_ALL}")
        for k, v in mapping.items():
            predicate = warn_keys.get(k)
            color = Fore.RED if predicate and predicate(v) else Fore.YELLOW
            print(f" {color}{k}:{Style.RESET_ALL} {_fmt(v)}")


def print_table(
    title: str,
    columns: Sequence[str],
    rows: Iterable[Sequence[Any]],
    row_styles: list[str | None] | None = None,
) -> None:
    """Renderiza uma tabela. ``row_styles`` opcional colore cada linha (rich)."""
    rows = list(rows)
    if RICH:
        table = Table(title=title, box=box.ROUNDED, title_style="bold green",
                      header_style="bold yellow")
        for col in columns:
            table.add_column(str(col))
        for idx, row in enumerate(rows):
            style = row_styles[idx] if row_styles and idx < len(row_styles) else None
            table.add_row(*[_fmt(c) for c in row], style=style)
        console.print(table)
    else:
        print(f"\n{Fore.GREEN}{title}{Style.RESET_ALL}")
        print(f" {Fore.YELLOW}{'  '.join(str(c) for c in columns)}{Style.RESET_ALL}")
        for row in rows:
            print("  " + "  ".join(_fmt(c) for c in row))


def print_list(title: str, items: Sequence[Any]) -> None:
    if RICH:
        console.print(f"[bold green]{title}[/]")
        for it in items:
            console.print(f"  • {_fmt(it)}")
    else:
        print(f"\n{Fore.GREEN}{title}{Style.RESET_ALL}")
        for it in items:
            print(f" - {_fmt(it)}")


@contextmanager
def status(message: str):
    """Spinner enquanto um bloco roda (rich). Fallback imprime a mensagem."""
    if RICH:
        with console.status(f"[cyan]{message}[/]", spinner="dots"):
            yield
    else:
        print(f"{Fore.CYAN}{message}{Style.RESET_ALL}")
        yield


def kv_pairs(mapping: dict[str, Any], labels: dict[str, str]) -> list[tuple[str, Any]]:
    """Filtra/relabela um dict preservando a ordem de ``labels``."""
    return [(labels[k], mapping[k]) for k in labels if k in mapping]
