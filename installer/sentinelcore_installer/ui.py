"""Terminal UI: whiptail screens when available, clean plain-text prompts otherwise.

Every prompt method returns ``None`` when the user chooses Back/Cancel, which
the wizard treats as "go to the previous screen".
"""

from __future__ import annotations

import getpass
import os
import shutil
import subprocess
import sys
import textwrap
from typing import Sequence

BACKTITLE = "SentinelCore setup"


class UI:
    interactive = True

    def msg(self, title: str, text: str) -> None: ...
    def yesno(self, title: str, text: str, yes: str = "Yes", no: str = "No", default_yes: bool = True) -> bool | None: ...
    def input(self, title: str, text: str, default: str = "") -> str | None: ...
    def password(self, title: str, text: str) -> str | None: ...
    def menu(self, title: str, text: str, items: Sequence[tuple[str, str]], default: str | None = None) -> str | None: ...
    def scroll(self, title: str, text: str, accept: str = "Accept", decline: str = "Decline") -> bool | None: ...
    def step(self, index: int, total: int, label: str) -> None: ...
    def step_done(self, label: str, ok: bool, detail: str = "") -> None: ...
    def info(self, text: str) -> None: ...


class PlainUI(UI):
    """Line-oriented prompts. 'b' goes back, 'q' quits."""

    def _out(self, text: str = "") -> None:
        print(text, flush=True)

    def _header(self, title: str) -> None:
        self._out()
        self._out(f"== {title} ==")

    def _read(self, prompt: str) -> str:
        try:
            return input(prompt)
        except EOFError:
            raise KeyboardInterrupt from None

    def msg(self, title, text):
        self._header(title)
        self._out(textwrap.fill(text, 78, replace_whitespace=False) if "\n" not in text else text)
        self._read("Press Enter to continue... ")

    def yesno(self, title, text, yes="Yes", no="No", default_yes=True):
        self._header(title)
        self._out(text)
        hint = f"[{yes[0].upper()}]/{no[0].lower()}" if default_yes else f"{yes[0].lower()}/[{no[0].upper()}]"
        while True:
            ans = self._read(f"{yes} or {no}? {hint}  (b = back) ").strip().lower()
            if ans == "b":
                return None
            if ans == "":
                return default_yes
            if ans[0] == yes[0].lower():
                return True
            if ans[0] == no[0].lower():
                return False

    def input(self, title, text, default=""):
        self._header(title)
        self._out(text)
        suffix = f" [{default}]" if default else ""
        ans = self._read(f"> {suffix} (b = back): ").strip()
        if ans.lower() == "b":
            return None
        return ans or default

    def password(self, title, text):
        self._header(title)
        self._out(text)
        try:
            ans = getpass.getpass("Password (b = back, input hidden): ")
        except EOFError:
            raise KeyboardInterrupt from None
        return None if ans == "b" else ans

    def menu(self, title, text, items, default=None):
        self._header(title)
        self._out(text)
        for i, (key, label) in enumerate(items, 1):
            marker = "*" if key == default else " "
            self._out(f" {marker}{i}) {label}")
        while True:
            ans = self._read("Choose a number (b = back): ").strip().lower()
            if ans == "b":
                return None
            if ans == "" and default is not None:
                return default
            if ans.isdigit() and 1 <= int(ans) <= len(items):
                return items[int(ans) - 1][0]

    def scroll(self, title, text, accept="Accept", decline="Decline"):
        self._header(title)
        self._out(text)
        return self.yesno(title, "", accept, decline, default_yes=False)

    def step(self, index, total, label):
        self._out(f"[{index:>2}/{total}] {label} ...")

    def step_done(self, label, ok, detail=""):
        mark = "ok" if ok else "FAILED"
        extra = f" - {detail}" if detail else ""
        self._out(f"        {mark}{extra}")

    def info(self, text):
        self._out(text)


class WhiptailUI(UI):
    def __init__(self, binary: str):
        self.binary = binary
        self.height, self.width = self._size()

    @staticmethod
    def _size() -> tuple[int, int]:
        cols, rows = shutil.get_terminal_size((80, 24))
        return max(16, min(rows - 4, 30)), max(60, min(cols - 6, 100))

    def _run(self, args: list[str]) -> tuple[int, str]:
        # whiptail draws on stdout and reports the answer on stderr.
        proc = subprocess.run(
            [self.binary, "--backtitle", BACKTITLE, *args],
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        return proc.returncode, proc.stderr.strip()

    def msg(self, title, text):
        self._run(["--title", title, "--msgbox", text, str(self.height), str(self.width)])

    def yesno(self, title, text, yes="Yes", no="No", default_yes=True):
        args = ["--title", title, "--yes-button", yes, "--no-button", no]
        if not default_yes:
            args.append("--defaultno")
        code, _ = self._run([*args, "--yesno", text, str(self.height), str(self.width)])
        if code == 255:
            return None
        return code == 0

    def input(self, title, text, default=""):
        code, out = self._run([
            "--title", title, "--cancel-button", "Back",
            "--inputbox", text, str(self.height), str(self.width), default,
        ])
        return out if code == 0 else None

    def password(self, title, text):
        code, out = self._run([
            "--title", title, "--cancel-button", "Back",
            "--passwordbox", text, str(self.height), str(self.width),
        ])
        return out if code == 0 else None

    def menu(self, title, text, items, default=None):
        flat: list[str] = []
        for key, label in items:
            flat += [key, label]
        args = ["--title", title, "--cancel-button", "Back"]
        if default is not None:
            args += ["--default-item", default]
        code, out = self._run([
            *args, "--menu", text, str(self.height), str(self.width),
            str(max(3, min(len(items), self.height - 8))), *flat,
        ])
        return out if code == 0 else None

    def scroll(self, title, text, accept="Accept", decline="Decline"):
        code, _ = self._run([
            "--title", title, "--scrolltext", "--yes-button", accept, "--no-button", decline,
            "--defaultno", "--yesno", text, str(self.height), str(self.width),
        ])
        if code == 255:
            return None
        return code == 0

    # Progress is plain text in both modes: it is also what ends up in a
    # terminal scrollback or a CI log, and a gauge hides failures.
    def step(self, index, total, label):
        print(f"[{index:>2}/{total}] {label} ...", flush=True)

    def step_done(self, label, ok, detail=""):
        mark = "ok" if ok else "FAILED"
        print(f"        {mark}" + (f" - {detail}" if detail else ""), flush=True)

    def info(self, text):
        print(text, flush=True)


class NonInteractiveUI(PlainUI):
    """Used by --non-interactive: any attempt to prompt is a programming error."""

    interactive = False

    def _read(self, prompt):  # pragma: no cover - guard
        raise RuntimeError("prompt requested in non-interactive mode")

    def msg(self, title, text):
        self._out(f"{title}: {text}")


def make_ui(plain: bool = False, non_interactive: bool = False) -> UI:
    if non_interactive:
        return NonInteractiveUI()
    tty = sys.stdin.isatty() and sys.stdout.isatty()
    binary = shutil.which("whiptail")
    if binary and tty and not plain and os.environ.get("TERM", "dumb") != "dumb":
        return WhiptailUI(binary)
    return PlainUI()
