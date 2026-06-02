"""terminal_ui.py — Interactive terminal helpers for safe-pip-compile.

Contains:
  - _getch()                      Cross-platform single-keypress reader
  - _multiselect_prompt()         Arrow-key multi-select checklist
  - _numbered_select_fallback()   Non-TTY numbered-input fallback
  - write_cve_warning_to_output() Insert CVE warning block into output file header
"""

from __future__ import annotations

import os
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from safe_pip_compile.models import PinnedBlockingPackage


# ---------------------------------------------------------------------------
# Cross-platform single-keypress reader
# ---------------------------------------------------------------------------

def _getch() -> str:
    """Return a normalised key token from a single keypress (no echo).

    Returns one of: 'UP', 'DOWN', 'SPACE', 'ENTER', 'ALL', 'NONE', 'QUIT',
    or the raw character for anything else.
    Supports Windows (msvcrt) and Unix (tty/termios).
    """
    if sys.platform == "win32":
        import msvcrt  # type: ignore[import]
        ch = msvcrt.getwch()
        if ch in ("\x00", "\xe0"):          # special-key prefix
            ch2 = msvcrt.getwch()
            return {"H": "UP", "P": "DOWN", "K": "LEFT", "M": "RIGHT"}.get(ch2, "UNKNOWN")
        char_map = {
            " ": "SPACE", "\r": "ENTER", "\n": "ENTER",
            "a": "ALL",   "A": "ALL",
            "n": "NONE",  "N": "NONE",
            "q": "QUIT",  "Q": "QUIT",  "\x1b": "QUIT",
        }
        return char_map.get(ch, ch)
    else:
        import termios  # type: ignore[import]
        import tty       # type: ignore[import]
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            ch = sys.stdin.read(1)
            if ch == "\x1b":                # ANSI escape sequence
                ch2 = sys.stdin.read(1)
                if ch2 == "[":
                    ch3 = sys.stdin.read(1)
                    return {"A": "UP", "B": "DOWN", "C": "RIGHT", "D": "LEFT"}.get(ch3, "UNKNOWN")
                return "QUIT"
            char_map = {
                " ": "SPACE", "\r": "ENTER", "\n": "ENTER",
                "a": "ALL",   "A": "ALL",
                "n": "NONE",  "N": "NONE",
                "q": "QUIT",  "Q": "QUIT",  "\x03": "QUIT",
            }
            return char_map.get(ch, ch)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)


# ---------------------------------------------------------------------------
# Arrow-key multi-select checklist
# ---------------------------------------------------------------------------

def multiselect_prompt(packages: list[PinnedBlockingPackage]) -> list[int]:
    """Interactive arrow-key multi-select checklist.

    Falls back to a numbered-input prompt when stdin is not a TTY
    (e.g. in tests or CI).

    Keybindings:
        ↑ / ↓     Move cursor
        Space      Toggle selection
        Enter      Confirm and return selected indices
        a          Select all
        n          Deselect all
        q          Cancel (returns empty list)

    Returns a sorted list of selected indices.
    """
    if not sys.stdin.isatty():
        return _numbered_select_fallback(packages)

    # All packages selected by default.
    selected: set[int] = set(range(len(packages)))
    cursor: int = 0

    def _render(first: bool = False) -> None:
        if not first:
            # Move cursor up past: header(1) + hint(1) + blank(1) + items + blank(1)
            n_lines = len(packages) + 4
            sys.stdout.write(f"\033[{n_lines}A\033[0J")

        hint = (
            "(\u2191\u2193 navigate"
            "  \u00b7  Space toggle"
            "  \u00b7  Enter confirm"
            "  \u00b7  a=all"
            "  \u00b7  n=none"
            "  \u00b7  q=cancel)"
        )
        sys.stdout.write("  Select packages to unpin:\n")
        sys.stdout.write(f"  {hint}\n\n")
        for i, pkg in enumerate(packages):
            check = "x" if i in selected else " "
            caret = ">" if i == cursor else " "
            vuln_ids = ", ".join(pkg.vuln_ids[:2])
            fix = f">={pkg.fix_versions[0]}" if pkg.fix_versions else "no fix"
            label = f"{pkg.name}=={pkg.version}"
            sys.stdout.write(
                f"  {caret} [{check}] {label:<35}  {vuln_ids} ({pkg.severity.name}, fix: {fix})\n"
            )
        sys.stdout.write("\n")
        sys.stdout.flush()

    _render(first=True)

    while True:
        key = _getch()
        if key == "UP":
            cursor = max(0, cursor - 1)
        elif key == "DOWN":
            cursor = min(len(packages) - 1, cursor + 1)
        elif key == "SPACE":
            selected.symmetric_difference_update({cursor})
        elif key == "ALL":
            selected = set(range(len(packages)))
        elif key == "NONE":
            selected = set()
        elif key == "ENTER":
            return sorted(selected)
        elif key == "QUIT":
            return []
        _render()


def _numbered_select_fallback(packages: list[PinnedBlockingPackage]) -> list[int]:
    """Non-TTY fallback: display a numbered list and accept comma-separated input."""
    print("  Available packages (all pre-selected):\n")
    for i, pkg in enumerate(packages, 1):
        vuln_ids = ", ".join(pkg.vuln_ids[:2])
        fix = f">={pkg.fix_versions[0]}" if pkg.fix_versions else "no fix"
        print(f"    {i}. {pkg.name}=={pkg.version}  ({vuln_ids}, fix: {fix})")
    print()
    try:
        raw = input("  Enter numbers to unpin (comma-separated, or 'all'): ").strip()
    except (EOFError, KeyboardInterrupt):
        return []
    if not raw or raw.lower() == "all":
        return list(range(len(packages)))
    indices: list[int] = []
    for part in raw.split(","):
        try:
            n = int(part.strip()) - 1
            if 0 <= n < len(packages):
                indices.append(n)
        except ValueError:
            pass
    return indices


# ---------------------------------------------------------------------------
# CVE warning header writer
# ---------------------------------------------------------------------------

def write_cve_warning_to_output(
    output_file: str,
    pinned_blockers: list[PinnedBlockingPackage],
) -> None:
    """Insert a CVE warning block into the output file's header section.

    The file already starts with the 3-line autogenerated header written by
    _sanitize_compile_output.  The warning is injected immediately after those
    3 lines so it's the first thing anyone reading the file will see.

    Example output header after this call::

        #
        # This file is autogenerated by safe-pip-compile for Python 3.12
        #
        #
        # ⚠  WARNING: This file contains UNRESOLVED CVEs!
        #    Dependencies are resolved but the following packages are pinned
        #    and could NOT be automatically upgraded. Review before production use.
        #
        #      django==3.2.1  —  GHSA-xxx (CRITICAL, fix: >=3.2.25)
        #
    """
    if not os.path.exists(output_file):
        return

    with open(output_file, encoding="utf-8") as f:
        lines = f.readlines()

    warning: list[str] = [
        "#\n",
        "# \u26a0  WARNING: This file contains UNRESOLVED CVEs!\n",
        "#    Dependencies are resolved but the following packages are pinned\n",
        "#    and could NOT be automatically upgraded. Review before production use.\n",
        "#\n",
    ]
    for pkg in pinned_blockers:
        vuln_str = ", ".join(pkg.vuln_ids[:3])
        fix_str = f">={pkg.fix_versions[0]}" if pkg.fix_versions else "no fix available"
        warning.append(
            f"#      {pkg.name}=={pkg.version}\u2002\u2014\u2002"
            f"{vuln_str} ({pkg.severity.name}, fix: {fix_str})\n"
        )
    warning.append("#\n")

    # Our header is always exactly 3 lines (written by _sanitize_compile_output).
    header_end = min(3, len(lines))
    with open(output_file, "w", encoding="utf-8") as f:
        f.writelines(lines[:header_end])
        f.writelines(warning)
        f.writelines(lines[header_end:])
