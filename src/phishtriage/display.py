"""Make outside text safe to print in a terminal (week 3, step 13).

Outside text is anything this program did not write itself: an email's headers, file names
and links, and the answers of the lookup services.

Why rich.markup.escape() was not enough: it only stops "[bold]" being read as Rich
formatting. Control characters went straight through to the terminal, which obeys them. So
an email could put these in its Subject, a display name or an attachment's name:
- ESC [2J clears the screen, and cursor moves can overwrite lines (hiding findings)
- ESC ]8 makes text a clickable link to any address (undoing defanging)
- ESC ]52 writes to the clipboard, in terminals that allow it
- a newline starts a fake report line
- U+202E (right-to-left override) makes "invoice<U+202E>fdp.exe" look like "invoiceexe.pdf"
Found during the week 3 gate, before any real phishing sample had been analysed.

visible() writes each such character out as its code (\\x1b, \\u202e), so the analyst can
see it was there and the terminal never receives it. safe() does that, then Rich's escape().

Joiners (U+200C, U+200D) are left alone: Sinhala and emoji need them, and they cannot
control a terminal.
"""

from __future__ import annotations

from rich.markup import escape as escape_markup

# Unicode category Cc, exactly: C0 controls (ESC, BEL, newline...), DEL, and C1 controls
CONTROL_CHARACTERS = [*range(0x00, 0x20), *range(0x7F, 0xA0)]
# Not category Cc, but they change the order or the lines text is shown in
LAYOUT_CHARACTERS = [0x061C, 0x200E, 0x200F, 0x2028, 0x2029, *range(0x202A, 0x202F)]
LAYOUT_CHARACTERS += [*range(0x2066, 0x206A)]

_WRITTEN_OUT = {code: f"\\x{code:02x}" for code in CONTROL_CHARACTERS}
_WRITTEN_OUT |= {code: f"\\u{code:04x}" for code in LAYOUT_CHARACTERS}


def visible(text: str) -> str:
    """'Hi\\x1b[2J' -> 'Hi\\\\x1b[2J': every control and layout character written out."""
    return text.translate(_WRITTEN_OUT)  # Java: like a char-by-char replace with a lookup table


def safe(text: str) -> str:
    """visible(), then Rich's escape(): use this for every piece of outside text."""
    return escape_markup(visible(text))
