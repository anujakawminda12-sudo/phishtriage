"""Make a zip of the project to move it to another machine (week 4, step 1).

Why: twice now a zip made with Finder's "Compress" took the whole folder, with samples/
(personal emails), .env (API keys) and .venv inside. This script works the other way
round. It starts from a short list of what MAY go in (an allowlist), so a new folder that
nobody thought about is left out by default instead of packed by default.

    python scripts/pack.py ~/Downloads/phishtriage_week4.zip

What goes in:
    folders  src/  tests/  scripts/  .github/
    files    pyproject.toml  README.md  LICENSE  .gitignore  .env.example
Everything else at the top of the project (samples/, .env, .venv, reports/, caches...) is
left out, and only its name is printed.

Always skipped inside those folders: __pycache__, *.pyc, .DS_Store, ._* (macOS extras),
*.egg-info and tool caches.

Refused: no zip is written at all, and the reason is printed. These are things that
should never be inside the allowed folders in the first place:
    - a secrets file: .env, .env.local, prod.env ... (.env.example is fine)
    - an email file (.eml, .msg, .mbox) outside tests/fixtures/
    - a folder called samples, heldout, gate, reports or .venv
    - a database file (*.sqlite3, *.sqlite, *.db): the lookup cache holds what you looked up
    - a symbolic link: it could point anywhere, for example into samples/
    - an output path inside the project, which would put this zip into the next one

Only names are looked at when deciding. A file that is left out or refused is never
opened. After writing, the zip is opened again and every name in it is checked once more,
so a mistake in the selection code cannot slip through unseen.

Standard library only, so it also runs before `pip install`.
"""

import argparse
import hashlib
import os
import sys
import zipfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

ALLOWED_DIRS = ("src", "tests", "scripts", ".github")
ALLOWED_FILES = ("pyproject.toml", "README.md", "LICENSE", ".gitignore", ".env.example")
# Without these two, the folder is not this project (a typo in --root, for example)
REQUIRED = ("pyproject.toml", "src")

# Rebuilt automatically, so never worth packing
JUNK_NAMES = frozenset({"__pycache__", ".DS_Store", ".pytest_cache", ".ruff_cache", ".mypy_cache"})
JUNK_SUFFIXES = (".pyc", ".pyo", ".egg-info")

FORBIDDEN_DIRS = frozenset({"samples", "heldout", "gate", "reports", ".venv"})
EMAIL_SUFFIXES = (".eml", ".msg", ".mbox")
DATABASE_SUFFIXES = (".sqlite3", ".sqlite", ".db")
FIXTURES = ("tests", "fixtures")  # the one place where (hand-built) .eml files belong
ENV_EXAMPLE = ".env.example"


@dataclass
class Selection:
    """What select_files() decided (Java: a plain mutable result object).

    files:    paths to pack, relative to the project folder, sorted
    left_out: names at the top of the project that are not packed (never opened)
    junk:     how many __pycache__, .DS_Store ... entries were skipped
    problems: reasons to refuse; if there is even one, no zip is written
    """

    files: list[PurePosixPath] = field(default_factory=list)
    left_out: list[str] = field(default_factory=list)
    junk: int = 0
    problems: list[str] = field(default_factory=list)


def is_junk(name: str) -> bool:
    return name in JUNK_NAMES or name.startswith("._") or name.endswith(JUNK_SUFFIXES)


def is_secrets_file(name: str) -> bool:
    """.env, .env.local, prod.env ... but not .env.example."""
    if name == ENV_EXAMPLE:
        return False
    return name == ".env" or name.startswith(".env.") or name.endswith(".env")


def problem_with(relative: PurePosixPath, is_dir: bool) -> str | None:
    """Why this path must not be packed, or None if it may be.

    relative is the path inside the project, e.g. PurePosixPath("tests/fixtures/a.eml").
    Only the name is looked at; the file itself is never opened.
    """
    name = relative.name
    if is_dir:
        if name in FORBIDDEN_DIRS:
            return f"a folder called {name}"
        return None
    suffix = relative.suffix.lower()
    if is_secrets_file(name):
        return "looks like a secrets file (.env)"
    if suffix in EMAIL_SUFFIXES and relative.parts[:2] != FIXTURES:
        return "an email file outside tests/fixtures/"
    if suffix in DATABASE_SUFFIXES:
        return "a database file (the lookup cache keeps everything you looked up)"
    return None


def select_files(root: Path) -> Selection:
    """Decide what goes into the zip. Nothing is written and no file is opened."""
    selection = Selection()
    problems = selection.problems
    for missing in (name for name in REQUIRED if not (root / name).exists()):
        problems.append(f"{missing}: not found, so {root} is not the project folder")
    if problems:
        return selection

    for entry in sorted(root.iterdir(), key=lambda path: path.name):
        name = entry.name
        if entry.is_symlink() and (name in ALLOWED_DIRS or name in ALLOWED_FILES):
            problems.append(f"{name}: a symbolic link")
        elif name in ALLOWED_FILES and entry.is_file():
            selection.files.append(PurePosixPath(name))
        elif name in ALLOWED_DIRS and entry.is_dir():
            _walk(root, entry, selection)
        else:
            selection.left_out.append(name)

    selection.files.sort()
    return selection


def _walk(root: Path, top: Path, selection: Selection) -> None:
    """Add the files under one allowed folder (Java: Files.walkFileTree with a visitor)."""

    def unreadable(error: OSError) -> None:
        # A folder that cannot be listed would silently be missing on the other machine
        where = Path(error.filename).relative_to(root).as_posix() if error.filename else top
        selection.problems.append(f"{where}: could not be read ({error.strerror})")

    # Path.walk() does not follow links: a link, even one to a folder, is listed among the
    # filenames and never entered, so the is_symlink() check on files below catches it
    for folder, dirnames, filenames in top.walk(on_error=unreadable):
        keep = []
        for name in sorted(dirnames):
            relative = PurePosixPath((folder / name).relative_to(root).as_posix())
            if is_junk(name):
                selection.junk += 1
            elif reason := problem_with(relative, is_dir=True):
                selection.problems.append(f"{relative}/: {reason}")
            else:
                keep.append(name)
        dirnames[:] = keep  # top-down walk: only these folders are entered next

        for name in sorted(filenames):
            path = folder / name
            relative = PurePosixPath(path.relative_to(root).as_posix())
            if is_junk(name):
                selection.junk += 1
            elif path.is_symlink():
                selection.problems.append(f"{relative}: a symbolic link")
            elif reason := problem_with(relative, is_dir=False):
                selection.problems.append(f"{relative}: {reason}")
            else:
                selection.files.append(relative)


def check_zip(zip_path: Path, prefix: str) -> list[str]:
    """Open a written zip again and check every name in it (defence in depth).

    select_files() should never let anything bad through. This repeats the checks on what
    was really written, so a future bug there is caught before the zip is used.
    """
    problems = []
    with zipfile.ZipFile(zip_path) as archive:
        if (broken := archive.testzip()) is not None:
            problems.append(f"{broken}: damaged in the zip")
        for name in archive.namelist():
            path = PurePosixPath(name)
            if path.parts[0] != prefix or len(path.parts) < 2:
                problems.append(f"{name}: not inside the {prefix}/ folder")
                continue
            relative = PurePosixPath(*path.parts[1:])
            first = relative.parts[0]
            allowed = first in ALLOWED_DIRS if len(relative.parts) > 1 else first in ALLOWED_FILES
            if not allowed:
                problems.append(f"{name}: not on the list of what may be packed")
            elif any(is_junk(part) for part in relative.parts):
                problems.append(f"{name}: should have been skipped")
            elif any(part in FORBIDDEN_DIRS for part in relative.parts[:-1]):
                problems.append(f"{name}: inside a folder that is never packed")
            elif reason := problem_with(relative, is_dir=False):
                problems.append(f"{name}: {reason}")
    return problems


def file_sha256(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def write_zip(root: Path, files: list[PurePosixPath], out: Path) -> None:
    """Write the zip. Every entry goes under one folder named like the project."""
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for relative in files:
            archive.write(root / relative, f"{root.name}/{relative}")


def _human_size(size: int) -> str:
    return f"{size / 1024:,.0f} KB" if size >= 1024 else f"{size} bytes"


def _counts(files: list[PurePosixPath]) -> str:
    """'src 45, tests 82, scripts 1, .github 1, top-level files 5' (always in this order)."""
    top_level = "top-level files"
    counts = dict.fromkeys([*ALLOWED_DIRS, top_level], 0)
    for relative in files:
        counts[relative.parts[0] if len(relative.parts) > 1 else top_level] += 1
    return ", ".join(f"{area} {count}" for area, count in counts.items() if count)


def pack(root: Path, out: Path, force: bool = False) -> int:
    """Select, write, check. Returns the exit code: 0 packed, 1 refused."""
    root = root.resolve()
    out = out.expanduser().resolve()

    def refuse(*reasons: str) -> int:
        print("Refused, no zip was written:", file=sys.stderr)
        for reason in reasons:
            print(f"  - {reason}", file=sys.stderr)
        return 1

    if out.suffix.lower() != ".zip":
        return refuse(f"{out.name}: the output name must end in .zip")
    if out.is_relative_to(root):
        return refuse(f"{out}: inside the project, so it would end up in the next zip")
    if out.is_dir():
        return refuse(f"{out}: is a folder")
    if out.exists() and not force:
        return refuse(f"{out}: already exists (add --force to replace it)")
    if not out.parent.is_dir():
        return refuse(f"{out.parent}: folder not found")

    selection = select_files(root)
    if selection.problems:
        return refuse(*selection.problems)
    if not selection.files:
        return refuse("nothing to pack")

    # Write next to the target, then rename: a refused or failed run leaves no half zip
    partial = out.with_name(out.name + ".partial")
    try:
        write_zip(root, selection.files, partial)
        if problems := check_zip(partial, root.name):
            return refuse(*problems)
        os.replace(partial, out)  # Java: Files.move with ATOMIC_MOVE
    finally:
        partial.unlink(missing_ok=True)

    print(f"Packed {len(selection.files)} files ({_human_size(out.stat().st_size)}) into {out}")
    print(f"  {_counts(selection.files)}")
    if selection.left_out:
        print(f"Left out, not opened: {', '.join(selection.left_out)}")
    print(f"Skipped {selection.junk} cache and macOS entries")
    print(f"SHA-256: {file_sha256(out)}")
    print("To check the copy on the other machine: sha256sum " + out.name)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python scripts/pack.py",
        description="Zip the project's code and tests only: never samples/, .env or .venv.",
    )
    parser.add_argument("out", type=Path, help="the zip to write, outside the project")
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="the project folder (default: the folder this script is in)",
    )
    parser.add_argument("--force", action="store_true", help="replace OUT if it exists")
    args = parser.parse_args(argv)
    return pack(args.root, args.out, force=args.force)


if __name__ == "__main__":
    sys.exit(main())
