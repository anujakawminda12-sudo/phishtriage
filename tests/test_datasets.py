"""Tests for picking and fingerprinting the held-out and gate sets (week 3, step 13)."""

from __future__ import annotations

import hashlib
import json
import stat
from datetime import date
from pathlib import Path

import pytest
from typer.testing import CliRunner

from phishtriage import datasets
from phishtriage.cli import app
from phishtriage.datasets import (
    HeldoutLists,
    file_sha256,
    find_heldout_lists,
    fingerprint,
    message_id,
    pick_sets,
    write_sets,
)

runner = CliRunner()


def make_emails(folder: Path, count: int, prefix: str = "sample") -> list[Path]:
    """`count` small files with different bytes. They are never parsed, so any bytes do."""
    folder.mkdir(parents=True, exist_ok=True)
    paths = []
    for number in range(count):
        path = folder / f"{prefix}-{number}.eml"
        path.write_bytes(f"Subject: {prefix} {number}\r\n\r\nbody {number}\r\n".encode())
        paths.append(path)
    return paths


def hashes(samples) -> set[str]:
    return {sample.sha256 for sample in samples}


def read_manifest(path: Path) -> dict[str, str]:
    """name -> hash, read the way `sha256sum -c` reads the file."""
    result = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        digest, name = line.split("  ", 1)
        result[name] = digest
    return result


# --- hashing ---------------------------------------------------------------------------------


def test_file_sha256_is_the_hash_of_the_bytes(tmp_path):
    path = tmp_path / "a.eml"
    path.write_bytes(b"hello")
    assert file_sha256(path) == hashlib.sha256(b"hello").hexdigest()


def test_fingerprint_is_the_hash_of_the_sorted_hashes_one_per_line():
    a, b = "a" * 64, "b" * 64
    expected = hashlib.sha256(f"{a}\n{b}\n".encode()).hexdigest()
    assert fingerprint([b, a]) == expected  # what `cut | LC_ALL=C sort | sha256sum` gives
    assert fingerprint([a, b]) == expected  # order does not matter


def test_fingerprint_changes_if_one_email_changes():
    assert fingerprint(["a" * 64, "b" * 64]) != fingerprint(["a" * 64, "c" * 64])


# --- picking ---------------------------------------------------------------------------------


def test_sizes_and_no_email_in_both_sets(tmp_path):
    make_emails(tmp_path / "src", 30)
    split = pick_sets(tmp_path / "src", heldout=10, gate=12, seed=7)
    assert len(split.heldout) == 10
    assert len(split.gate) == 12
    assert not hashes(split.heldout) & hashes(split.gate)
    assert split.found == 30


def test_same_seed_same_sets(tmp_path):
    make_emails(tmp_path / "src", 30)
    first = pick_sets(tmp_path / "src", 10, 10, seed=2026)
    second = pick_sets(tmp_path / "src", 10, 10, seed=2026)
    assert first.heldout == second.heldout
    assert first.gate == second.gate


def test_another_seed_other_sets(tmp_path):
    make_emails(tmp_path / "src", 30)
    first = pick_sets(tmp_path / "src", 10, 10, seed=1)
    second = pick_sets(tmp_path / "src", 10, 10, seed=2)
    assert hashes(first.heldout) != hashes(second.heldout)


def test_file_names_do_not_change_what_is_picked(tmp_path):
    """Candidates are sorted by hash, so renamed copies on another machine give the same sets."""
    originals = make_emails(tmp_path / "one", 20)
    renamed = tmp_path / "two"
    renamed.mkdir()
    for number, path in enumerate(reversed(originals)):
        (renamed / f"zz-{number}.eml").write_bytes(path.read_bytes())
    first = pick_sets(tmp_path / "one", 5, 5, seed=3)
    second = pick_sets(renamed, 5, 5, seed=3)
    assert hashes(first.heldout) == hashes(second.heldout)
    assert hashes(first.gate) == hashes(second.gate)


def test_identical_files_count_once(tmp_path):
    paths = make_emails(tmp_path / "src", 5)
    (tmp_path / "src" / "copy.eml").write_bytes(paths[0].read_bytes())
    split = pick_sets(tmp_path / "src", 3, 2, seed=1)
    assert split.duplicates == 1
    assert len(hashes(split.heldout) | hashes(split.gate)) == 5


def test_emails_already_used_are_never_picked(tmp_path):
    paths = make_emails(tmp_path / "src", 12)
    used = tmp_path / "used"
    used.mkdir()
    for path in paths[:2]:
        (used / f"old-{path.name}").write_bytes(path.read_bytes())
    split = pick_sets(tmp_path / "src", 5, 5, seed=1, exclude=[used])
    assert split.excluded == 2
    assert not (hashes(split.heldout) | hashes(split.gate)) & {file_sha256(p) for p in paths[:2]}


def test_exclude_can_be_a_single_file(tmp_path):
    paths = make_emails(tmp_path / "src", 4)
    split = pick_sets(tmp_path / "src", 2, 1, seed=1, exclude=[paths[0]])
    assert split.excluded == 1


def test_subfolders_are_searched(tmp_path):
    make_emails(tmp_path / "src" / "2024", 3, "a")
    make_emails(tmp_path / "src" / "2025", 3, "b")
    (tmp_path / "src" / "notes.txt").write_text("not an email")
    assert pick_sets(tmp_path / "src", 3, 3, seed=1).found == 6


def test_symlinks_are_skipped(tmp_path):
    make_emails(tmp_path / "src", 3)
    outside = tmp_path / "secret.txt"
    outside.write_text("a file outside the dataset")
    (tmp_path / "src" / "link.eml").symlink_to(outside)
    split = pick_sets(tmp_path / "src", 2, 1, seed=1)
    assert split.skipped == 1
    assert file_sha256(outside) not in hashes(split.heldout) | hashes(split.gate)


def test_a_name_a_sha256sum_file_cannot_hold_is_skipped(tmp_path):
    make_emails(tmp_path / "src", 3)
    (tmp_path / "src" / "back\\slash.eml").write_bytes(b"other bytes")
    assert pick_sets(tmp_path / "src", 2, 1, seed=1).skipped == 1


def test_too_few_emails_says_why(tmp_path):
    paths = make_emails(tmp_path / "src", 4)
    (tmp_path / "src" / "copy.eml").write_bytes(paths[0].read_bytes())
    with pytest.raises(ValueError, match="10 emails wanted, but only 4 can be picked"):
        pick_sets(tmp_path / "src", 5, 5, seed=1)


@pytest.mark.parametrize(("heldout", "gate"), [(0, 0), (-1, 5)])
def test_impossible_counts(tmp_path, heldout, gate):
    make_emails(tmp_path / "src", 4)
    with pytest.raises(ValueError, match="at least one"):
        pick_sets(tmp_path / "src", heldout, gate, seed=1)


# --- writing ---------------------------------------------------------------------------------


def test_write_sets_copies_bytes_and_writes_manifests(tmp_path):
    make_emails(tmp_path / "src", 10)
    split = pick_sets(tmp_path / "src", 3, 4, seed=5)
    out = tmp_path / "sets"
    record = write_sets(split, out, seed=5, source=tmp_path / "src", today=date(2026, 11, 23))

    for name, samples in (("heldout", split.heldout), ("gate", split.gate)):
        manifest = read_manifest(out / f"{name}.sha256")
        assert len(manifest) == len(samples)
        for relative, digest in manifest.items():  # what `sha256sum -c` checks
            assert relative.startswith(f"{name}/")
            assert file_sha256(out / relative) == digest
        assert set(manifest.values()) == hashes(samples)
        assert record["sets"][name]["fingerprint"] == fingerprint(manifest.values())

    saved = json.loads((out / "sets.json").read_text())
    assert saved == record
    assert saved["seed"] == 5
    assert saved["picked_on"] == "2026-11-23"
    assert saved["sets"]["heldout"]["emails"] == 3
    assert stat.S_IMODE((out / "heldout").stat().st_mode) == 0o700


def test_the_source_is_not_changed(tmp_path):
    paths = make_emails(tmp_path / "src", 6)
    before = {path: path.read_bytes() for path in paths}
    split = pick_sets(tmp_path / "src", 2, 2, seed=1)
    write_sets(split, tmp_path / "out", seed=1, source=tmp_path / "src")
    assert {path: path.read_bytes() for path in paths} == before


def test_same_name_in_two_subfolders_keeps_both(tmp_path):
    make_emails(tmp_path / "src" / "a", 1)
    make_emails(tmp_path / "src" / "b", 1)
    (tmp_path / "src" / "b" / "sample-0.eml").write_bytes(b"different bytes")
    split = pick_sets(tmp_path / "src", 2, 0, seed=1)
    write_sets(split, tmp_path / "out", seed=1, source=tmp_path / "src")
    names = sorted(path.name for path in (tmp_path / "out" / "heldout").iterdir())
    assert len(names) == 2
    assert "sample-0.eml" in names
    assert any(name.endswith("-sample-0.eml") for name in names)
    assert "gate" not in json.loads((tmp_path / "out" / "sets.json").read_text())["sets"]


def test_a_set_is_never_picked_twice_into_the_same_folder(tmp_path):
    make_emails(tmp_path / "src", 6)
    split = pick_sets(tmp_path / "src", 2, 2, seed=1)
    write_sets(split, tmp_path / "out", seed=1, source=tmp_path / "src")
    with pytest.raises(FileExistsError, match="choose a new folder"):
        write_sets(split, tmp_path / "out", seed=1, source=tmp_path / "src")


def test_an_empty_existing_folder_is_fine(tmp_path):
    make_emails(tmp_path / "src", 4)
    (tmp_path / "out").mkdir()
    split = pick_sets(tmp_path / "src", 2, 2, seed=1)
    write_sets(split, tmp_path / "out", seed=1, source=tmp_path / "src")
    assert (tmp_path / "out" / "gate.sha256").exists()


def test_a_file_that_changes_while_copying_is_caught(tmp_path, monkeypatch):
    make_emails(tmp_path / "src", 3)
    split = pick_sets(tmp_path / "src", 1, 0, seed=1)

    def copy_and_change(source, target):
        Path(target).write_bytes(Path(source).read_bytes() + b"changed")

    monkeypatch.setattr("phishtriage.datasets.shutil.copyfile", copy_and_change)
    with pytest.raises(RuntimeError, match="changed while it was being copied"):
        write_sets(split, tmp_path / "out", seed=1, source=tmp_path / "src")


# --- the command -----------------------------------------------------------------------------


def test_split_sets_command(tmp_path):
    make_emails(tmp_path / "src", 20)
    out = tmp_path / "sets"
    result = runner.invoke(
        app,
        ["split-sets", str(tmp_path / "src"), str(out), "--seed", "20261123"]
        + ["--heldout", "5", "--gate", "6"],
    )
    assert result.exit_code == 0, result.output
    record = json.loads((out / "sets.json").read_text())
    text = " ".join(result.output.split())  # Rich may wrap long lines
    assert "Picked at random with seed 20261123 from 20 emails" in text
    assert "Held-out (week 5): 5 emails" in text
    assert "Gate (week 3): 6 emails" in text
    assert record["sets"]["heldout"]["fingerprint"] in text
    assert "sha256sum -c heldout.sha256" in text


def test_split_sets_needs_a_seed(tmp_path):
    make_emails(tmp_path / "src", 4)
    result = runner.invoke(app, ["split-sets", str(tmp_path / "src"), str(tmp_path / "out")])
    assert result.exit_code == 2
    assert not (tmp_path / "out").exists()


def test_split_sets_with_too_few_emails(tmp_path):
    make_emails(tmp_path / "src", 4)
    result = runner.invoke(
        app, ["split-sets", str(tmp_path / "src"), str(tmp_path / "out"), "--seed", "1"]
    )
    assert result.exit_code == 1
    assert "100 emails wanted, but only 4" in " ".join(result.output.split())
    assert not (tmp_path / "out").exists()


def test_split_sets_refuses_a_used_folder(tmp_path):
    make_emails(tmp_path / "src", 4)
    (tmp_path / "out").mkdir()
    (tmp_path / "out" / "old.txt").write_text("x")
    args = ["split-sets", str(tmp_path / "src"), str(tmp_path / "out"), "--seed", "1"]
    result = runner.invoke(app, [*args, "--heldout", "1", "--gate", "1"])
    assert result.exit_code == 1
    assert "already has files" in " ".join(result.output.split())


def test_split_sets_gate_only(tmp_path):
    make_emails(tmp_path / "src", 4)
    args = ["split-sets", str(tmp_path / "src"), str(tmp_path / "out"), "--seed", "1"]
    result = runner.invoke(app, [*args, "--heldout", "0", "--gate", "2"])
    assert result.exit_code == 0, result.output
    assert "Held-out" not in result.output
    assert "Do not run" not in result.output


def test_split_sets_with_exclude(tmp_path):
    paths = make_emails(tmp_path / "src", 6)
    args = ["split-sets", str(tmp_path / "src"), str(tmp_path / "out"), "--seed", "1"]
    result = runner.invoke(
        app, [*args, "--heldout", "2", "--gate", "2", "--exclude", str(paths[0])]
    )
    assert result.exit_code == 0, result.output
    assert "1 already used" in result.output


# --- Message-ID: the same email downloaded two ways (step 13) -----------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (
            b"From: a@x.example\r\nMessage-ID: <abc.1@mail.example>\r\n\r\nbody",
            "<abc.1@mail.example>",
        ),
        (b"message-id:   <low@case.example>\n\nbody", "<low@case.example>"),
        (
            b"Subject: s\nMessage-Id:\n\t<folded@mail.example>\nTo: b\n\nbody",
            "<folded@mail.example>",
        ),
        (b"Subject: no id\r\n\r\nMessage-ID: <in-body@x.example>\r\n", ""),
        (b"Message-ID: not-an-id\r\n\r\n", ""),
        (b"", ""),
    ],
)
def test_message_id(tmp_path, raw, expected):
    path = tmp_path / "a.eml"
    path.write_bytes(raw)
    assert message_id(path) == expected


def test_an_email_used_before_is_excluded_even_if_its_bytes_differ(tmp_path):
    source = tmp_path / "src"
    make_emails(source, 6)
    (source / "seen.eml").write_bytes(b"Message-ID: <seen@bank.example>\r\n\r\nbody\r\n")
    used = tmp_path / "used"
    used.mkdir()
    # Same email as downloaded in week 1: LF line endings instead of CRLF, so other bytes
    (used / "old.eml").write_bytes(b"Message-ID: <seen@bank.example>\n\nbody\n")
    split = pick_sets(source, 3, 3, seed=1, exclude=[used])
    assert (split.excluded, split.excluded_by_message_id) == (1, 1)
    picked = {sample.path.name for sample in split.heldout + split.gate}
    assert "seen.eml" not in picked


def test_emails_without_a_message_id_are_not_matched_to_each_other(tmp_path):
    source = tmp_path / "src"
    make_emails(source, 4)  # these have no Message-ID
    used = tmp_path / "used"
    make_emails(used, 1, "other")  # neither does this one
    split = pick_sets(source, 2, 2, seed=1, exclude=[used])
    assert split.excluded == 0


def test_sets_json_and_the_command_report_message_id_matches(tmp_path):
    source = tmp_path / "src"
    make_emails(source, 6)
    (source / "seen.eml").write_bytes(b"Message-ID: <seen@x.example>\r\n\r\nb\r\n")
    (tmp_path / "used").mkdir()
    (tmp_path / "used" / "old.eml").write_bytes(b"Message-ID: <seen@x.example>\n\nb\n")
    args = ["split-sets", str(source), str(tmp_path / "out"), "--seed", "1"]
    args += ["--heldout", "3", "--gate", "3", "--exclude", str(tmp_path / "used")]
    result = runner.invoke(app, args)
    assert result.exit_code == 0, result.output
    assert "1 already used, 1 of them by Message-ID" in " ".join(result.output.split())
    saved = json.loads((tmp_path / "out" / "sets.json").read_text())
    assert saved["excluded_by_message_id"] == 1


# --- week 4: recognising held-out emails wherever they are --------------------------------


def with_id(path: Path, number: int, message_id: str | None) -> Path:
    header = f"Message-ID: {message_id}\r\n" if message_id else ""
    path.write_bytes(f"{header}Subject: s {number}\r\n\r\nbody {number}\r\n".encode())
    return path


@pytest.fixture
def picked(tmp_path) -> tuple[Path, Path]:
    """split-sets' real layout: samples/legit/heldout + heldout.sha256, from inbox/."""
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    for number in range(6):
        with_id(inbox / f"mail-{number}.eml", number, f"<{number}@mail.example>")
    write_sets(pick_sets(inbox, 2, 2, seed=7), tmp_path / "samples" / "legit", seed=7, source=inbox)
    return tmp_path / "samples", inbox


def test_the_lists_hold_every_held_out_hash_and_message_id(picked):
    samples, _ = picked
    lists = find_heldout_lists([samples])
    held = sorted((samples / "legit" / "heldout").iterdir())
    assert lists.files == ((samples / "legit" / "heldout.sha256").resolve(),)
    assert lists.hashes == {file_sha256(path) for path in held}
    assert lists.message_ids == {message_id(path) for path in held}
    assert len(lists.hashes) == len(lists.message_ids) == 2  # the gate set is not in it


def test_the_originals_and_a_new_download_are_recognised(picked, tmp_path):
    samples, inbox = picked
    lists = find_heldout_lists([samples])
    held = {path.name for path in (samples / "legit" / "heldout").iterdir()}
    assert {path.name for path in inbox.iterdir() if lists.holds(path)} == held
    # the same email downloaded again: other bytes, same Message-ID
    original = inbox / sorted(held)[0]
    again = tmp_path / "again.eml"
    again.write_bytes(b"X-Downloaded-Again: yes\r\n" + original.read_bytes())
    assert file_sha256(again) not in lists.hashes
    assert lists.holds(again)


def test_emails_without_a_message_id_are_matched_by_bytes_only(tmp_path):
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    for number in range(2):
        with_id(inbox / f"no-id-{number}.eml", number, None)
    write_sets(pick_sets(inbox, 1, 1, seed=1), tmp_path / "set", seed=1, source=inbox)
    lists = find_heldout_lists([tmp_path / "set"])
    assert lists.message_ids == frozenset()
    other = with_id(tmp_path / "other.eml", 99, None)  # also no Message-ID: a different email
    assert not lists.holds(other)
    assert sum(lists.holds(path) for path in inbox.iterdir()) == 1


def test_no_lists_means_nothing_is_read(tmp_path, monkeypatch):
    lists = find_heldout_lists([tmp_path / "no-such-folder", tmp_path])
    assert lists == HeldoutLists()

    def opened(path):
        raise AssertionError(f"{path} was hashed, but there is no held-out set to compare")

    monkeypatch.setattr(datasets, "file_sha256", opened)
    monkeypatch.setattr(datasets, "message_id", opened)
    email = with_id(tmp_path / "mine.eml", 1, "<1@mail.example>")
    assert not lists.holds(email)  # not even opened


def test_an_unreadable_email_is_not_held_out(picked, tmp_path):
    samples, _ = picked
    lists = find_heldout_lists([samples])
    assert not lists.holds(tmp_path / "missing.eml")
    assert not lists.holds(tmp_path)  # a folder: IsADirectoryError is an OSError


def test_a_broken_list_stops_everything(tmp_path):
    folder = tmp_path / "set"
    folder.mkdir()
    (folder / "heldout.sha256").write_text(f"{'a' * 64}  heldout/x.eml\n\nnot a hash line\n")
    with pytest.raises(ValueError, match=r"heldout\.sha256, line 3: not a sha256sum line"):
        find_heldout_lists([tmp_path])


def test_list_lines_as_sha256sum_writes_them(tmp_path):
    folder = tmp_path / "set"
    folder.mkdir()
    upper = "A" * 64  # sha256sum writes lower case: anything else is not its line
    lines = [f"{'a' * 64}  heldout/x.eml", f"{'b' * 64} *heldout/binary mode.eml", ""]
    (folder / "heldout.sha256").write_text("\n".join(lines))
    assert find_heldout_lists([tmp_path]).hashes == {"a" * 64, "b" * 64}
    (folder / "heldout.sha256").write_text(f"{upper}  heldout/x.eml\n")
    with pytest.raises(ValueError):
        find_heldout_lists([tmp_path])


def test_a_list_cannot_point_outside_its_folder(tmp_path):
    outside = with_id(tmp_path / "outside.eml", 1, "<outside@mail.example>")
    folder = tmp_path / "samples" / "set"
    folder.mkdir(parents=True)
    (folder / "heldout.sha256").write_text(f"{file_sha256(outside)}  ../../outside.eml\n")
    lists = find_heldout_lists([tmp_path / "samples"])
    assert lists.hashes == {file_sha256(outside)}  # the hash still counts
    assert lists.message_ids == frozenset()  # but that file was not read


def test_the_list_name_is_found_in_any_case(tmp_path):
    folder = tmp_path / "deep" / "er"
    folder.mkdir(parents=True)
    (folder / "HELDOUT.SHA256").write_text(f"{'c' * 64}  heldout/x.eml\n")
    assert find_heldout_lists([tmp_path]).hashes == {"c" * 64}
