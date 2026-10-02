"""Terminal banner, progress lines and result tables. Everything goes to STDERR
so STDOUT stays clean for pipes. Raw ANSI codes only."""
from __future__ import annotations

import os
import shutil
import sys
import time
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
AUTHOR = "Ariston Cândido"
AUTHOR_ASCII = "Ariston Candido"

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

SPINNER_UNICODE = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
SPINNER_ASCII = "|/-\\"
HIDE_CURSOR, SHOW_CURSOR, CLEAR_LINE = "\033[?25l", "\033[?25h", "\r\033[K"
BANNER_LINE_DELAY = 0.06
TAGLINE_CHAR_DELAY = 0.012
STEP_SECONDS = 0.40
STEP_FRAMES = 12


class UI:
    """Writes banner, Metasploit-style progress lines and tables to a stream."""

    def __init__(self, stream: TextIO | None = None, show_banner: bool = True, animate: bool = True) -> None:
        self.stream = stream if stream is not None else sys.stderr
        self.is_tty = self.stream.isatty()
        self.color = self.is_tty and not os.environ.get("NO_COLOR")
        self.show_banner = show_banner and self.is_tty
        self.animate = animate and self.is_tty
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
        art = BANNER if self.unicode else "AX9"
        tagline = f"  v{__version__}  {TAGLINE}"
        credit = f"  developed by {AUTHOR if self._can_encode(AUTHOR) else AUTHOR_ASCII}"
        if not self.animate:
            self._write(self._paint(art, "red"))
            self._write(tagline)
            self._write(self._paint(credit, "dim") + "\n")
            return
        for row in art.splitlines():
            self._write(self._paint(row, "red"))
            time.sleep(BANNER_LINE_DELAY)
        for text, color in ((tagline, None), (credit, "dim")):
            for char in text:
                self.stream.write(self._paint(char, color))
                self.stream.flush()
                time.sleep(TAGLINE_CHAR_DELAY)
            self._write()
        self._write()

    def progress(self, total: int) -> "Progress":
        """Animated single-line progress bar; does nothing when animation is off."""
        return Progress(self, total)

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


class Progress:
    """Context manager drawing one redrawn line: spinner, step label, bar, percent.
    Each step() is a real stage of the run; the short animation only paces it."""

    def __init__(self, ui: UI, total: int) -> None:
        self.ui = ui
        self.total = total
        self.done = 0
        self.frame = 0
        self.spinner = SPINNER_UNICODE if ui.unicode else SPINNER_ASCII

    def __enter__(self) -> "Progress":
        if self.ui.animate:
            self.ui.stream.write(HIDE_CURSOR)
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        if self.ui.animate:
            if exc_type is None and self.done == self.total:
                time.sleep(STEP_SECONDS)
            self.ui.stream.write(CLEAR_LINE + SHOW_CURSOR)
            self.ui.stream.flush()
        return False

    def step(self, label: str) -> None:
        if not self.ui.animate:
            return
        start = self.done / self.total
        self.done += 1
        end = self.done / self.total
        for i in range(1, STEP_FRAMES + 1):
            self._draw(label, start + (end - start) * i / STEP_FRAMES)
            time.sleep(STEP_SECONDS / STEP_FRAMES)

    def _draw(self, label: str, fraction: float) -> None:
        ui, width = self.ui, 24
        filled = round(width * fraction)
        spin = self.spinner[self.frame % len(self.spinner)]
        self.frame += 1
        gauge = ui._paint(ui.box["full"] * filled, "green") + ui._paint(ui.box["empty"] * (width - filled), "dim")
        ui.stream.write(f"{CLEAR_LINE}{ui._paint(spin, 'cyan')} {label:<36} [{gauge}] {fraction * 100:3.0f}%")
        ui.stream.flush()
