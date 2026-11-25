"""Pick the week 5 held-out set and the week 3 gate set, and fingerprint them (week 3, step 13).

Week 5 measures how good the verdict is. If I build and tune the rules while looking at the
same emails I later score on, the score is not blind. So both sets are picked now, at random
with a seed written down beforehand, and the held-out set gets a SHA-256 fingerprint before
the tool ever reads it. In week 5, `sha256sum -c heldout.sha256` proves the set did not change.

Rules:
- the same seed and the same files always give the same sets, on any machine: candidates are
  sorted by their SHA-256, not by name or by the order the disk lists them
  (Java: Collections.shuffle(list, new Random(seed)) on a sorted list)
- identical files (same bytes, different names) count once
- files already used while building the tool (--exclude) are never picked: matched by their
  bytes, and also by their Message-ID, because the same email downloaded two ways (Gmail's
  "Download message" and IMAP) may not be byte-for-byte the same
- the output folder must be new or empty: a held-out set is picked once, never re-rolled
- the files are only read as bytes, to hash and copy them: never parsed, opened or rendered
  (the one exception is the Message-ID line, found by scanning the header block's bytes)
- symlinks are skipped: a dataset from the internet could point one at a file outside it
"""

from __future__ import annotations

import hashlib
import json
import random
import re
import shutil
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

HELDOUT = "heldout"
GATE = "gate"
# A name with these cannot be written plainly in a sha256sum file (GNU escapes them)
UNSAFE_NAME_CHARACTERS = ("\n", "\r", "\\")
# Headers sit at the top of an email; reading only this much keeps a 20 MB email cheap
HEADER_SCAN_BYTES = 256 * 1024
MESSAGE_ID = re.compile(rb"<[^<>\s]+>")


@dataclass(frozen=True)
class Sample:
    """One picked email: its SHA-256 and where it came from."""

    sha256: str
    path: Path


@dataclass
class SetSplit:
    """The two sets, and what happened to the other files (counts only)."""

    heldout: list[Sample] = field(default_factory=list)
    gate: list[Sample] = field(default_factory=list)
    found: int = 0  # .eml files in the source folder
    duplicates: int = 0  # same bytes as a file already counted
    excluded: int = 0  # same bytes or same Message-ID as a file in an --exclude folder
    excluded_by_message_id: int = 0  # of those, recognised only by the Message-ID
    skipped: int = 0  # symlinks, and names a sha256sum file cannot hold


def file_sha256(path: Path) -> str:
    """The SHA-256 of a file's bytes, read in chunks (a 20 MB email is not loaded at once)."""
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def fingerprint(hashes: Iterable[str]) -> str:
    """One SHA-256 for a whole set: the hash of its sorted file hashes, one per line.

    The same as `cut -d' ' -f1 heldout.sha256 | LC_ALL=C sort | sha256sum`, so it can be
    checked without this tool. File names and their order do not change it, and it shows
    nothing about the emails: it can go in a README or a study guide.
    """
    text = "".join(f"{value}\n" for value in sorted(hashes))
    return hashlib.sha256(text.encode("ascii")).hexdigest()


def message_id(path: Path) -> str:
    """The Message-ID, e.g. '<abc@mail.example>', or "" if there is none.

    Only the header block is scanned, as bytes (it ends at the first empty line); a header
    folded over two lines is joined first. Nothing else in the email is read.
    """
    with path.open("rb") as handle:
        head = handle.read(HEADER_SCAN_BYTES).replace(b"\r\n", b"\n")
    lines = head.split(b"\n\n", 1)[0].split(b"\n")
    for number, line in enumerate(lines):
        if line[:11].lower() == b"message-id:":
            value = line[11:]
            for more in lines[number + 1 :]:
                if more[:1] not in (b" ", b"\t"):
                    break
                value += more
            match = MESSAGE_ID.search(value)
            return match.group().decode("ascii", "replace") if match else ""
    return ""


def _eml_files(path: Path) -> list[Path]:
    """Every .eml file in a folder and its subfolders (or the file itself), in name order."""
    if path.is_file():
        return [path]
    return sorted(file for file in path.rglob("*.eml") if file.is_file() or file.is_symlink())


def _usable(path: Path) -> bool:
    return not path.is_symlink() and not any(c in path.name for c in UNSAFE_NAME_CHARACTERS)


def pick_sets(
    source: Path, heldout: int, gate: int, seed: int, exclude: Sequence[Path] = ()
) -> SetSplit:
    """Pick `heldout` + `gate` different emails from `source` at random. Copies nothing.

    Raises ValueError if there are not enough emails left to pick from.
    """
    if heldout < 0 or gate < 0 or heldout + gate == 0:
        raise ValueError("ask for at least one email, and no negative counts")
    used_hashes: set[str] = set()
    used_ids: set[str] = set()
    for folder in exclude:
        for file in _eml_files(folder):
            if _usable(file):
                used_hashes.add(file_sha256(file))
                used_ids.add(message_id(file))
    used_ids.discard("")  # emails without a Message-ID cannot be matched this way
    split = SetSplit()
    unique: dict[str, Path] = {}
    for path in _eml_files(source):
        split.found += 1
        if not _usable(path):
            split.skipped += 1
            continue
        digest = file_sha256(path)
        if digest in used_hashes:
            split.excluded += 1
        elif used_ids and message_id(path) in used_ids:
            split.excluded += 1
            split.excluded_by_message_id += 1
        elif digest in unique:
            split.duplicates += 1
        else:
            unique[digest] = path

    candidates = [Sample(digest, unique[digest]) for digest in sorted(unique)]
    wanted = heldout + gate
    if wanted > len(candidates):
        raise ValueError(
            f"{wanted} emails wanted, but only {len(candidates)} can be picked "
            f"({split.found} found, {split.duplicates} duplicates, {split.excluded} already "
            f"used, {split.skipped} skipped)"
        )
    picked = random.Random(seed).sample(candidates, wanted)
    split.heldout, split.gate = picked[:heldout], picked[heldout:]
    return split


# One line of a sha256sum file: the hash, a space, " " (text) or "*" (binary), the name
SHA256_LINE = re.compile(r"([0-9a-f]{64}) [ *](.+)")


@dataclass(frozen=True)
class HeldoutLists:
    """What the held-out sets look like from outside: hashes and Message-IDs only (week 4).

    split-sets copies the emails it picks, so the held-out emails are still in the folder
    they were picked from, and an email can be downloaded again later. analyze uses this
    to recognise them wherever they are, without ever parsing one.
    """

    files: tuple[Path, ...] = ()  # the heldout.sha256 files that were read
    hashes: frozenset[str] = frozenset()
    message_ids: frozenset[str] = frozenset()

    def holds(self, path: Path) -> bool:
        """True if `path` has the same bytes or the same Message-ID as a held-out email."""
        if not self.files:
            return False  # no held-out set anywhere: nothing to hash
        try:
            if file_sha256(path) in self.hashes:
                return True
            return bool(self.message_ids) and message_id(path) in self.message_ids
        except OSError:
            return False  # cannot be read: the analysis cannot read it either


def find_heldout_lists(roots: Iterable[Path]) -> HeldoutLists:
    """Read every heldout.sha256 in these folders and their subfolders.

    The Message-ID is taken from each held-out email listed (the header block only, as
    split-sets and --exclude do), so a copy downloaded again is recognised too. A name that
    points outside the list's own folder is not followed.

    Raises ValueError for a line that is not a sha256sum line: a list that cannot be read
    must stop the run, not let held-out emails through (it fails closed).
    """
    found = {
        listing.resolve()
        for root in roots
        if root.is_dir()
        for listing in root.rglob(f"{HELDOUT}.sha256", case_sensitive=False)
        if listing.is_file()
    }
    hashes: set[str] = set()
    ids: set[str] = set()
    for listing in sorted(found):
        home = listing.parent
        for number, line in enumerate(listing.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            match = SHA256_LINE.fullmatch(line)
            if match is None:
                raise ValueError(f"{listing}, line {number}: not a sha256sum line")
            hashes.add(match[1])
            email = home / match[2]
            if email.resolve().is_relative_to(home) and email.is_file():
                ids.add(message_id(email))
    ids.discard("")  # emails without a Message-ID cannot be matched this way
    return HeldoutLists(tuple(sorted(found)), frozenset(hashes), frozenset(ids))


def write_sets(
    split: SetSplit, out: Path, *, seed: int, source: Path, today: date | None = None
) -> dict:
    """Copy the sets into OUT/heldout and OUT/gate, with a sha256sum file and sets.json each.

    Returns what was written to sets.json. Raises FileExistsError if OUT has files already.
    """
    if out.exists() and any(out.iterdir()):
        raise FileExistsError(
            f"{out} already has files: a set is picked once, so choose a new folder"
        )
    out.mkdir(mode=0o700, parents=True, exist_ok=True)  # personal emails: owner only
    record: dict = {
        "seed": seed,
        "picked_on": (today or date.today()).isoformat(),
        "source": str(source),
        "found": split.found,
        "duplicates": split.duplicates,
        "excluded": split.excluded,
        "excluded_by_message_id": split.excluded_by_message_id,
        "skipped": split.skipped,
        "sets": {},
    }
    for name, samples in ((HELDOUT, split.heldout), (GATE, split.gate)):
        if samples:
            record["sets"][name] = _write_one_set(name, samples, out)
    (out / "sets.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    return record


def _write_one_set(name: str, samples: list[Sample], out: Path) -> dict:
    folder = out / name
    folder.mkdir(mode=0o700)
    lines: list[str] = []
    used: set[str] = set()
    for sample in sorted(samples, key=lambda s: (s.path.name, s.sha256)):
        target = sample.path.name
        if target in used:  # same name in two subfolders: keep both, apart
            target = f"{sample.sha256[:12]}-{target}"
        used.add(target)
        shutil.copyfile(sample.path, folder / target)
        if file_sha256(folder / target) != sample.sha256:  # changed while we were working
            raise RuntimeError(f"{sample.path} changed while it was being copied")
        lines.append(f"{sample.sha256}  {name}/{target}\n")
    (out / f"{name}.sha256").write_text("".join(lines), encoding="utf-8")
    return {"emails": len(samples), "fingerprint": fingerprint(s.sha256 for s in samples)}
