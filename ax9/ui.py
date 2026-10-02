"""Terminal banner, progress lines and result tables. Everything goes to STDERR
so STDOUT stays clean for pipes. Raw ANSI codes only."""
from __future__ import annotations

import os
import shutil
import sys
from typing import Sequence, TextIO, Union

from . import __version__

BANNER = """\
 █████╗ ██╗  ██╗ █████╗
██╔══██╗╚██╗██╔╝██╔══██╗
███████║ ╚███╔╝ ╚██████║
██╔══██║ ██╔██╗  ╚═══██║
██║  ██║██╔╝ ██╗ █████╔╝
╚═╝  ╚═╝╚═╝  ╚═╝ ╚════╝"""
TAGLINE = "Audit X9 :: your logs can't hide"

RESET = "\033[0m"
COLORS = {
    "red": "\033[31m", "green": "\033[32m", "yellow": "\033[33m", "blue": "\033[34m",
    "cyan": "\033[36m", "bold": "\033[1m", "bold_red": "\033[1;31m", "dim": "\033[2m",
}
PREFIXES = {"info": ("[*]", "blue"), "ok": ("[+]", "green"), "warn": ("[!]", "yellow"), "error": ("[-]", "red")}

# corners/joints in reading order: top, middle, bottom rows; then horizontal, vertical
UNICODE_BOX = {"top": "┌┬┐", "mid": "├┼┤", "bot": "└┴┘", "h": "─", "v": "│", "full": "█", "empty": "░", "more": "…"}
ASCII_BOX = {"top": "+++", "mid": "+++", "bot": "+++", "h": "-", "v": "|", "full": "#", "empty": ".", "more": "~"}

Cell = Union[str, tuple[str, str]]  # plain text, or (text, color name)


class UI:
    """Writes banner, Metasploit-style progress lines and tables to a stream."""

    def __init__(self, stream: TextIO | None = None, show_banner: bool = True) -> None:
        self.stream = stream if stream is not None else sys.stderr
        self.is_tty = self.stream.isatty()
        self.color = self.is_tty and not os.environ.get("NO_COLOR")
        self.show_banner = show_banner and self.is_tty
        self._ensure_utf8()
        self.unicode = self._can_encode(BANNER + "".join(UNICODE_BOX.values()))
        self.box = UNICODE_BOX if self.unicode else ASCII_BOX

    def _ensure_utf8(self) -> None:
        """Windows consoles may use a legacy codepage; try UTF-8 first."""
        reconfigure = getattr(self.stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8")
            except (ValueError, OSError):
                pass

    def _can_encode(self, text: str) -> bool:
        try:
            text.encode(getattr(self.stream, "encoding", None) or "ascii")
            return True
        except UnicodeEncodeError:
            return False

    def _paint(self, text: str, color: str | None) -> str:
        return f"{COLORS[color]}{text}{RESET}" if self.color and color else text

    def _write(self, text: str = "") -> None:
        print(text, file=self.stream, flush=True)

    def banner(self) -> None:
        """Print the ASCII banner, or a plain title if box characters can't be encoded."""
        if not self.show_banner:
            return
        self._write(self._paint(BANNER if self.unicode else "AX9", "red"))
        self._write(f"  v{__version__}  {TAGLINE}\n")

    def _line(self, kind: str, message: str) -> None:
        prefix, color = PREFIXES[kind]
        self._write(f"{self._paint(prefix, color)} {message}")

    def info(self, message: str) -> None:
        self._line("info", message)

    def success(self, message: str) -> None:
        self._line("ok", message)

    def warning(self, message: str) -> None:
        self._line("warn", message)

    def error(self, message: str) -> None:
        self._line("error", message)

    def blank(self) -> None:
        self._write()

    def heading(self, title: str) -> None:
        self._write()
        self.info(self._paint(title, "bold"))

    def _fit(self, text: str, width: int) -> str:
        return text if len(text) <= width else text[: width - 1] + self.box["more"]

    def table(self, title: str, headers: Sequence[str], rows: Sequence[Sequence[Cell]]) -> None:
        """Bordered table. The last column shrinks to fit the terminal width.
        Text is padded before coloring so ANSI codes never break alignment."""
        self.heading(title)
        if not rows:
            self._write(f"    {self._paint('none', 'dim')}")
            return
        cells = [[(c, None) if isinstance(c, str) else c for c in row] for row in rows]
        widths = [max(len(h), *(len(r[i][0]) for r in cells)) for i, h in enumerate(headers)]
        indent = 4
        overflow = indent + sum(widths) + 3 * len(widths) + 1 - shutil.get_terminal_size((140, 24)).columns
        if overflow > 0:
            widths[-1] = max(len(headers[-1]), 8, widths[-1] - overflow)

        b = self.box

        def rule(kind: str) -> str:
            left, joint, right = b[kind]
            return " " * indent + left + joint.join(b["h"] * (w + 2) for w in widths) + right

        def line(values: Sequence[tuple[str, str | None]]) -> str:
            parts = [" " + self._paint(self._fit(t, w).ljust(w), color) + " " for (t, color), w in zip(values, widths)]
            return " " * indent + b["v"] + b["v"].join(parts) + b["v"]

        self._write(rule("top"))
        self._write(line([(h, "bold") for h in headers]))
        self._write(rule("mid"))
        for row in cells:
            self._write(line(row))
        self._write(rule("bot"))

    def bar(self, label: str, percent: float, width: int = 30) -> None:
        """Progress-style bar, colored by how close to 100% it is."""
        filled = round(width * percent / 100)
        color = "green" if percent >= 90 else "yellow" if percent >= 50 else "red"
        gauge = self._paint(self.box["full"] * filled, color) + self._paint(self.box["empty"] * (width - filled), "dim")
        self._write(f"    {label:<28} [{gauge}] {self._paint(f'{percent:5.1f}%', color)}")
