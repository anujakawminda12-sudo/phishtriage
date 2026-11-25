"""No hidden characters in the source code (week 4, step 6).

Step 6 found that the tool used to write content.py had turned escapes such as "\\u200b"
into the real, invisible characters. In the editor the line read
INVISIBLE = dict.fromkeys(map(ord, ""), None), as if the string were empty. A Cyrillic
"\\u0430" written as itself looks exactly like a Latin "a", so a test about it reads as
if it tested nothing.

Invisible characters and text-direction controls in source code are also how the
"Trojan Source" attacks (CVE-2021-42574) hide code from a reviewer. So every such
character must be written as an escape, "\\u200b", which anyone can see.

Allowed as written: a zero-width joiner or non-joiner inside a Sinhala or Tamil word,
where it is a normal part of the writing ("\\u0dc1\\u0dca\\u200d\\u0dbb\\u0dd3"), or between
two emoji, which is how emoji such as a family are built (week 3's test_display.py has
one); and visibly different letters such as full-width "\\uff50" or "\\u00fc".
"""

import unicodedata
from pathlib import Path

import pytest

PROJECT = Path(__file__).resolve().parent.parent
SOURCES = sorted(
    path
    for folder in ("src", "tests", "scripts")
    for path in (PROJECT / folder).rglob("*.py")
    if "__pycache__" not in path.parts
)
JOINERS = "\u200c\u200d"


def _joins_naturally(char: str) -> bool:
    """Sinhala (U+0D80-U+0DFF), Tamil (U+0B80-U+0BFF) or an emoji (a "So" symbol from
    U+1F000 up): the characters a zero-width joiner normally sits between."""
    if unicodedata.category(char) == "So" and ord(char) >= 0x1F000:
        return True
    return "\u0d80" <= char <= "\u0dff" or "\u0b80" <= char <= "\u0bff"


def hidden_characters(text: str) -> list[str]:
    """'line 3: U+200B ZERO WIDTH SPACE' for each character that must be an escape."""
    problems = []
    for number, line in enumerate(text.splitlines(), start=1):
        for index, char in enumerate(line):
            if char.isascii():
                continue
            before = line[index - 1] if index else ""
            after = line[index + 1] if index + 1 < len(line) else ""
            if char in JOINERS and (_joins_naturally(before) or _joins_naturally(after)):
                continue
            category = unicodedata.category(char)
            name = unicodedata.name(char, "UNNAMED")
            invisible = category in ("Cf", "Zs", "Zl", "Zp", "Cc", "Co", "Cn")
            lookalike = name.startswith(("CYRILLIC", "GREEK"))
            if invisible or lookalike:
                problems.append(f"line {number}: U+{ord(char):04X} {name}")
    return problems


@pytest.mark.parametrize("path", SOURCES, ids=lambda path: str(path.relative_to(PROJECT)))
def test_no_hidden_or_lookalike_characters(path):
    assert hidden_characters(path.read_text(encoding="utf-8")) == []


def test_the_project_files_are_found():
    names = {path.name for path in SOURCES}
    assert {"content.py", "lookalike.py", "test_content.py", "pack.py"} <= names


@pytest.mark.parametrize(
    ("text", "problem"),
    [
        ('x = "a\u200bb"', "line 1: U+200B ZERO WIDTH SPACE"),
        ("# comment\ny = '\u202e'", "line 2: U+202E RIGHT-TO-LEFT OVERRIDE"),  # Trojan Source
        ('z = "\u00a0"', "line 1: U+00A0 NO-BREAK SPACE"),
        ('name = "p\u0430ypal"', "line 1: U+0430 CYRILLIC SMALL LETTER A"),
        ('name = "g\u03bfogle"', "line 1: U+03BF GREEK SMALL LETTER OMICRON"),
        ("\ufeffimport os", "line 1: U+FEFF ZERO WIDTH NO-BREAK SPACE"),  # a byte order mark
        ('j = "a\u200db"', "line 1: U+200D ZERO WIDTH JOINER"),  # a joiner between Latin letters
    ],
)
def test_hidden_characters_are_found(text, problem):
    assert hidden_characters(text) == [problem]


@pytest.mark.parametrize(
    "text",
    [
        'word = "\u0dc1\u0dca\u200d\u0dbb\u0dd3"',  # Sinhala "shri": the joiner belongs
        'wide = "\uff50\uff41\uff59"',  # full-width letters look different
        'family = "\U0001f468\u200d\U0001f469\u200d\U0001f467"',  # emoji joined on purpose
        'city = "m\u00fcnchen"',
        'escaped = "\\u200b"',  # written as an escape: plain ASCII
        "plain = 'hello'\n",
    ],
)
def test_ordinary_text_is_allowed(text):
    assert hidden_characters(text) == []
