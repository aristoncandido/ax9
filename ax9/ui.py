"""Terminal presentation: banner, animation, [*]/[+]/[!]/[-] lines and tables.

Engineering rules followed here (they matter more than the looks):

1. Everything goes to STDERR. STDOUT stays clean, so the tool can be piped
   and scripted without decoration getting in the way.
2. Decoration only on a real terminal. When stderr is a file, a pipe or a CI
   log: no banner, no colors, no animation, no delays.
3. NO_COLOR is honored (https://no-color.org), and --no-banner / --no-anim
   switch the extras off by hand.
4. Raw ANSI escape codes only: no colorama/rich, the project uses stdlib only.
5. Never crash on an old console: if the terminal encoding cannot draw the
   box characters, fall back to plain ASCII.
6. Data from input files is untrusted: control characters are stripped
   before printing, so a hostname cannot inject escape sequences.

Want to tweak the look? Colors live in COLORS, the [*] prefixes in PREFIXES,
the animation speed in the *_DELAY / STEP_* constants.
"""
from __future__ import annotations

import os
import re
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
AUTHOR_ASCII = "Ariston Candido"  # for consoles that cannot print "â"

# ANSI escape codes: "\033[31m" means "from here on, red"; RESET goes back to normal.
RESET = "\033[0m"
COLORS = {
    "red": "\033[31m", "green": "\033[32m", "yellow": "\033[33m", "blue": "\033[34m",
    "cyan": "\033[36m", "bold": "\033[1m", "bold_red": "\033[1;31m", "dim": "\033[2m",
}
# Metasploit-style prefixes: info, success, warning/action needed, error.
PREFIXES = {"info": ("[*]", "blue"), "ok": ("[+]", "green"), "warn": ("[!]", "yellow"), "error": ("[-]", "red")}

# Characters used to draw tables and bars. Each "top"/"mid"/"bot" string is
# (left corner, column joint, right corner) for that border line.
UNICODE_BOX = {"top": "┌┬┐", "mid": "├┼┤", "bot": "└┴┘", "h": "─", "v": "│", "full": "█", "empty": "░", "more": "…"}
ASCII_BOX = {"top": "+++", "mid": "+++", "bot": "+++", "h": "-", "v": "|", "full": "#", "empty": ".", "more": "~"}

Cell = Union[str, tuple[str, str]]  # table cell: plain text, or (text, color name)

# Animation. Total run time on a terminal is roughly
# 6 banner lines * BANNER_LINE_DELAY + tagline chars * TAGLINE_CHAR_DELAY + 8 * STEP_SECONDS.
SPINNER_UNICODE = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
SPINNER_ASCII = "|/-\\"
HIDE_CURSOR, SHOW_CURSOR = "\033[?25l", "\033[?25h"
CLEAR_LINE = "\r\033[K"  # go to column 0 and erase the line: lets the bar redraw itself in place
BANNER_LINE_DELAY = 0.06
TAGLINE_CHAR_DELAY = 0.012
STEP_SECONDS = 0.12
STEP_FRAMES = 6

# C0/C1 control characters (ESC, BEL, backspace, ...), never legitimate inside a table cell.
CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def sanitize(text: str) -> str:
    """Make untrusted text safe to print: control characters become '?'."""
    return CONTROL_CHARS.sub("?", text)


class UI:
    """Everything the CLI prints goes through one instance of this class.

    Pass a different `stream` (e.g. io.StringIO) to capture output in tests.
    """

    def __init__(self, stream: TextIO | None = None, show_banner: bool = True, animate: bool = True) -> None:
        self.stream = stream if stream is not None else sys.stderr
        self.is_tty = self.stream.isatty()
        self.color = self.is_tty and not os.environ.get("NO_COLOR")
        self.show_banner = show_banner and self.is_tty
        self.animate = animate and self.is_tty
        self._ensure_utf8()
        self.unicode = self._can_encode(BANNER + "".join(UNICODE_BOX.values()))
        self.box = UNICODE_BOX if self.unicode else ASCII_BOX

    # -- low-level helpers ---------------------------------------------------

    def _ensure_utf8(self) -> None:
        """Windows consoles may default to a legacy codepage (cp1252): ask for UTF-8 first."""
        reconfigure = getattr(self.stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8")
            except (ValueError, OSError):
                pass

    def _can_encode(self, text: str) -> bool:
        """True if the stream's encoding can represent every character of `text`."""
        try:
            text.encode(getattr(self.stream, "encoding", None) or "ascii")
            return True
        except UnicodeEncodeError:
            return False

    def _paint(self, text: str, color: str | None) -> str:
        """Wrap text in a color, but only when colors are enabled."""
        return f"{COLORS[color]}{text}{RESET}" if self.color and color else text

    def _write(self, text: str = "") -> None:
        print(text, file=self.stream, flush=True)

    @property
    def width(self) -> int:
        """Width of the terminal this UI writes to (stderr, not stdout:
        `ax9 > out.txt` still has a real terminal on stderr)."""
        try:
            return os.get_terminal_size(self.stream.fileno()).columns
        except (AttributeError, OSError, ValueError):
            return shutil.get_terminal_size((140, 24)).columns

    # -- banner and messages ---------------------------------------------------

    def banner(self) -> None:
        """Logo + version + tagline + credit. Animated on a terminal, instant otherwise."""
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
        for row in art.splitlines():  # logo appears line by line
            self._write(self._paint(row, "red"))
            time.sleep(BANNER_LINE_DELAY)
        for text, color in ((tagline, None), (credit, "dim")):  # then "typed" char by char
            for char in text:
                self.stream.write(self._paint(char, color))
                self.stream.flush()
                time.sleep(TAGLINE_CHAR_DELAY)
            self._write()
        self._write()

    def progress(self, total: int) -> "Progress":
        """Animated progress bar for `total` steps; silent when animation is off."""
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
        """Section title: blank line + bold [*] line."""
        self._write()
        self.info(self._paint(title, "bold"))

    # -- tables and bars -------------------------------------------------------

    def _fit(self, text: str, width: int) -> str:
        """Cut text to `width` characters, ending with "…" when truncated."""
        return text if len(text) <= width else text[: width - 1] + self.box["more"]

    def table(self, title: str, headers: Sequence[str], rows: Sequence[Sequence[Cell]]) -> None:
        """Draw a bordered table.

        How it works:
          1. every column is as wide as its longest value
          2. if the table is wider than the terminal, the LAST column shrinks
             (so put the long free-text column last)
          3. each cell is padded to its width BEFORE being colored: ANSI codes
             are invisible but have length, so padding colored text would
             misalign the borders
        """
        self.heading(title)
        if not rows:
            self._write(f"    {self._paint('none', 'dim')}")
            return
        cells = [[(sanitize(c), None) if isinstance(c, str) else (sanitize(c[0]), c[1]) for c in row] for row in rows]
        widths = [max(len(h), *(len(r[i][0]) for r in cells)) for i, h in enumerate(headers)]
        indent = 4
        # total width = indent + text + 2 spaces of padding per column + one border per column + the last border
        overflow = indent + sum(widths) + 3 * len(widths) + 1 - self.width
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
        """Static gauge: red below 50%, yellow below 90%, green from 90%."""
        filled = round(width * percent / 100)
        color = "green" if percent >= 90 else "yellow" if percent >= 50 else "red"
        gauge = self._paint(self.box["full"] * filled, color) + self._paint(self.box["empty"] * (width - filled), "dim")
        self._write(f"    {label:<28} [{gauge}] {self._paint(f'{percent:5.1f}%', color)}")


class Progress:
    """One self-redrawing line: spinner, step label, bar and percentage.

    Use it as a context manager so the cursor is ALWAYS restored, even on an
    error or Ctrl+C:

        with ui.progress(total=3) as progress:
            progress.step("Loading files")
            ...

    Each step() should match a real stage of the work; the animation only
    paces it so a human can read it. When animation is off, step() returns
    immediately and nothing is printed.
    """

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
                time.sleep(STEP_SECONDS)  # let the 100% frame stay visible for a moment
            self.ui.stream.write(CLEAR_LINE + SHOW_CURSOR)
            self.ui.stream.flush()
        return False  # never swallow the exception: the caller must still handle it

    def step(self, label: str) -> None:
        """Advance one step, animating the bar from the previous % to the new one."""
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
