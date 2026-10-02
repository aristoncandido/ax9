"""Terminal banner and progress output. Everything goes to STDERR so STDOUT
stays clean for pipes. Raw ANSI codes only."""
from __future__ import annotations

import os
import sys
from typing import TextIO

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
COLORS = {"red": "\033[31m", "green": "\033[32m", "yellow": "\033[33m", "blue": "\033[34m"}
PREFIXES = {"info": ("[*]", "blue"), "ok": ("[+]", "green"), "warn": ("[!]", "yellow"), "error": ("[-]", "red")}


class UI:
    """Writes banner and Metasploit-style progress lines to a stream."""

    def __init__(self, stream: TextIO | None = None, show_banner: bool = True) -> None:
        self.stream = stream if stream is not None else sys.stderr
        self.is_tty = self.stream.isatty()
        self.color = self.is_tty and not os.environ.get("NO_COLOR")
        self.show_banner = show_banner and self.is_tty
        self._ensure_utf8()

    def _ensure_utf8(self) -> None:
        """Windows consoles may use a legacy codepage; try UTF-8 first."""
        reconfigure = getattr(self.stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8")
            except (ValueError, OSError):
                pass

    def _paint(self, text: str, color: str) -> str:
        return f"{COLORS[color]}{text}{RESET}" if self.color else text

    def _write(self, text: str) -> None:
        print(text, file=self.stream, flush=True)

    def banner(self) -> None:
        """Print the ASCII banner, falling back to a plain title if the
        terminal encoding cannot represent box-drawing characters."""
        if not self.show_banner:
            return
        art = BANNER
        try:
            art.encode(self.stream.encoding or "ascii")
        except UnicodeEncodeError:
            art = "AX9"
        self._write(self._paint(art, "red"))
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
