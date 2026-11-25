"""Tests for scripts/pack.py, the safe project zip (week 4, step 1).

pack.py is a script, not part of the phishtriage package (it is never installed), so it
is loaded here from its file path. Java comparison: like loading a class with a
URLClassLoader pointed at one folder, instead of finding it on the classpath.
"""

import hashlib
import importlib.util
import runpy
import sys
import zipfile
from pathlib import Path, PurePosixPath

import pytest

PROJECT = Path(__file__).resolve().parent.parent
SCRIPT = PROJECT / "scripts" / "pack.py"


def _load_script():
    spec = importlib.util.spec_from_file_location("phishtriage_pack_script", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    # dataclasses look the module up in sys.modules while the class is being built
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


pack = _load_script()

# A small project that looks like the real one, with everything that must stay behind
ALLOWED = [
    "pyproject.toml",
    "README.md",
    "LICENSE",
    ".gitignore",
    ".env.example",
    "src/phishtriage/__init__.py",
    "src/phishtriage/cli.py",
    "src/phishtriage/allowlist.txt",
    "tests/test_cli.py",
    "tests/fixtures/legit_newsletter.eml",
    "tests/fixtures/nested/forwarded.eml",
    "scripts/pack.py",
    ".github/workflows/ci.yml",
]
LEFT_OUT = [
    ".env",
    ".venv/bin/python",
    "samples/legit/heldout/uid-1.eml",
    "reports/one.md",
    ".coverage",
    "notes.txt",
]
JUNK = [
    "src/phishtriage/__pycache__/cli.cpython-315.pyc",
    "src/phishtriage/.DS_Store",
    "src/phishtriage/._cli.py",
    "src/phishtriage.egg-info/PKG-INFO",
    "tests/.pytest_cache/v/cache/lastfailed",
    "tests/old.pyc",
]


def make_project(root: Path, extra: tuple[str, ...] = ()) -> Path:
    """Build a fake project. Every file holds its own path, so contents can be checked."""
    for relative in [*ALLOWED, *LEFT_OUT, *JUNK, *extra]:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"content of {relative}\n", encoding="utf-8")
    return root


@pytest.fixture
def project(tmp_path: Path) -> Path:
    return make_project(tmp_path / "phishtriage")


@pytest.fixture
def out(tmp_path: Path) -> Path:
    folder = tmp_path / "outside"
    folder.mkdir()
    return folder / "project.zip"


def names_in(zip_path: Path) -> list[str]:
    with zipfile.ZipFile(zip_path) as archive:
        return archive.namelist()


# --- what goes in --------------------------------------------------------------------------


def test_packs_exactly_the_allowed_files(project, out):
    assert pack.main([str(out), "--root", str(project)]) == 0
    assert sorted(names_in(out)) == sorted(f"phishtriage/{name}" for name in ALLOWED)


def test_entries_are_sorted_and_under_one_folder(project, out):
    pack.main([str(out), "--root", str(project)])
    names = names_in(out)
    assert names == sorted(names)
    assert all(name.startswith("phishtriage/") for name in names)


def test_file_contents_are_unchanged(project, out):
    pack.main([str(out), "--root", str(project)])
    with zipfile.ZipFile(out) as archive:
        data = archive.read("phishtriage/src/phishtriage/cli.py")
    assert data == b"content of src/phishtriage/cli.py\n"


def test_left_out_names_are_listed_but_never_packed(project, out, capsys):
    pack.main([str(out), "--root", str(project)])
    names = names_in(out)
    assert not any("samples" in name or name.endswith("/.env") for name in names)
    assert not any(".venv" in name or "reports" in name for name in names)
    line = next(x for x in capsys.readouterr().out.splitlines() if x.startswith("Left out"))
    assert line == "Left out, not opened: .coverage, .env, .venv, notes.txt, reports, samples"


def test_junk_is_skipped_and_counted(project, out, capsys):
    pack.main([str(out), "--root", str(project)])
    names = names_in(out)
    assert not any("__pycache__" in name or name.endswith((".pyc", ".DS_Store")) for name in names)
    assert not any("/._" in name or "egg-info" in name or ".pytest_cache" in name for name in names)
    # __pycache__, .DS_Store, ._cli.py, the .egg-info folder, .pytest_cache, old.pyc
    assert "Skipped 6 cache and macOS entries" in capsys.readouterr().out


def test_summary_counts_and_hash(project, out, capsys):
    pack.main([str(out), "--root", str(project)])
    printed = capsys.readouterr().out
    assert f"Packed {len(ALLOWED)} files" in printed
    assert "  src 3, tests 3, scripts 1, .github 1, top-level files 5\n" in printed
    assert f"SHA-256: {hashlib.sha256(out.read_bytes()).hexdigest()}" in printed
    assert "sha256sum project.zip" in printed


def test_env_example_is_allowed_inside_folders_too(project, out):
    make_project(project, extra=("src/phishtriage/.env.example",))
    assert pack.main([str(out), "--root", str(project)]) == 0
    assert "phishtriage/src/phishtriage/.env.example" in names_in(out)


# --- refused: nothing is written ---------------------------------------------------------


@pytest.mark.parametrize(
    ("bad", "where", "reason"),
    [
        ("src/.env", "src/.env", "secrets file"),
        ("tests/.env.local", "tests/.env.local", "secrets file"),
        ("scripts/prod.env", "scripts/prod.env", "secrets file"),
        ("tests/real_phish.eml", "tests/real_phish.eml", "email file outside tests/fixtures/"),
        ("src/phishtriage/Inbox.EML", "src/phishtriage/Inbox.EML", "email file outside"),
        ("tests/data/outlook.msg", "tests/data/outlook.msg", "email file outside"),
        ("scripts/inbox.mbox", "scripts/inbox.mbox", "email file outside"),
        ("tests/fixturesX/a.eml", "tests/fixturesX/a.eml", "email file outside"),
        ("src/cache.sqlite3", "src/cache.sqlite3", "database file"),
        ("tests/old.sqlite", "tests/old.sqlite", "database file"),
        ("tests/x.db", "tests/x.db", "database file"),
        # a forbidden folder is refused as a whole, without listing what is inside it
        ("tests/samples/a.txt", "tests/samples/", "a folder called samples"),
        ("src/heldout/a.txt", "src/heldout/", "a folder called heldout"),
        ("tests/fixtures/gate/a.eml", "tests/fixtures/gate/", "a folder called gate"),
        ("scripts/reports/r.md", "scripts/reports/", "a folder called reports"),
        ("src/.venv/bin/python", "src/.venv/", "a folder called .venv"),
    ],
)
def test_refuses_dangerous_names_inside_allowed_folders(project, out, capsys, bad, where, reason):
    make_project(project, extra=(bad,))
    assert pack.main([str(out), "--root", str(project)]) == 1
    assert not out.exists()
    assert not out.with_name(out.name + ".partial").exists()
    error = capsys.readouterr().err
    assert "Refused, no zip was written" in error
    assert f"  - {where}: " in error  # says where
    assert reason in error
    if where.endswith("/"):
        assert PurePosixPath(bad).name not in error  # the folder was never entered


def test_every_problem_is_listed_not_just_the_first(project, out, capsys):
    make_project(project, extra=("src/.env", "tests/real.eml"))
    pack.main([str(out), "--root", str(project)])
    error = capsys.readouterr().err
    assert "src/.env" in error
    assert "tests/real.eml" in error


def test_refuses_a_link_to_a_file(project, out, capsys):
    (project / "src" / "secret.py").symlink_to(project / ".env")
    assert pack.main([str(out), "--root", str(project)]) == 1
    assert "src/secret.py: a symbolic link" in capsys.readouterr().err
    assert not out.exists()


def test_refuses_a_link_to_a_folder_without_entering_it(project, out, capsys):
    (project / "tests" / "data").symlink_to(project / "samples", target_is_directory=True)
    assert pack.main([str(out), "--root", str(project)]) == 1
    error = capsys.readouterr().err
    assert "tests/data: a symbolic link" in error
    assert "uid-1.eml" not in error  # the linked folder was never listed


def test_refuses_an_allowed_name_that_is_a_link(tmp_path, out, capsys):
    real = make_project(tmp_path / "real")
    linked = tmp_path / "linked"
    linked.mkdir()
    (linked / "pyproject.toml").write_text("x\n", encoding="utf-8")
    (linked / "src").symlink_to(real / "src", target_is_directory=True)
    assert pack.main([str(out), "--root", str(linked)]) == 1
    assert "src: a symbolic link" in capsys.readouterr().err


def test_refuses_a_folder_that_cannot_be_read(project, out, capsys, monkeypatch):
    # Running as root ignores chmod, so the walk is made to report the error instead
    real_walk = Path.walk

    def walk_with_error(self, top_down=True, on_error=None, follow_symlinks=False):
        if self.name == "tests":
            on_error(PermissionError(13, "Permission denied", str(self / "locked")))
        yield from real_walk(self, top_down, on_error, follow_symlinks)

    monkeypatch.setattr(Path, "walk", walk_with_error)
    assert pack.main([str(out), "--root", str(project)]) == 1
    assert "tests/locked: could not be read (Permission denied)" in capsys.readouterr().err


# --- refused: the output path and the project folder ----------------------------------------


def test_refuses_an_output_inside_the_project(project, capsys):
    target = project / "src" / "project.zip"
    assert pack.main([str(target), "--root", str(project)]) == 1
    assert "inside the project" in capsys.readouterr().err
    assert not target.exists()


def test_allows_a_zip_next_to_the_project_with_a_similar_name(project):
    """~/Downloads/phishtriage_week4.zip next to ~/Downloads/phishtriage is outside it.

    is_relative_to() compares whole path parts, not text, so "phishtriage_week4.zip" does
    not count as being inside "phishtriage" (a startswith() on strings would get this wrong).
    """
    sibling = project.parent / f"{project.name}_week4.zip"
    assert pack.main([str(sibling), "--root", str(project)]) == 0
    assert sibling.exists()


def test_refuses_an_output_that_is_not_a_zip(project, tmp_path, capsys):
    assert pack.main([str(tmp_path / "project.tar"), "--root", str(project)]) == 1
    assert "must end in .zip" in capsys.readouterr().err


def test_refuses_an_output_that_is_a_folder(project, tmp_path, capsys):
    folder = tmp_path / "folder.zip"
    folder.mkdir()
    assert pack.main([str(folder), "--root", str(project)]) == 1
    assert "is a folder" in capsys.readouterr().err


def test_refuses_an_output_in_a_missing_folder(project, tmp_path, capsys):
    assert pack.main([str(tmp_path / "nowhere" / "p.zip"), "--root", str(project)]) == 1
    assert "folder not found" in capsys.readouterr().err


def test_does_not_replace_an_existing_zip_without_force(project, out, capsys):
    out.write_bytes(b"older zip")
    assert pack.main([str(out), "--root", str(project)]) == 1
    assert "already exists" in capsys.readouterr().err
    assert out.read_bytes() == b"older zip"


def test_force_replaces_an_existing_zip(project, out):
    out.write_bytes(b"older zip")
    assert pack.main([str(out), "--root", str(project), "--force"]) == 0
    assert len(names_in(out)) == len(ALLOWED)


def test_refuses_a_folder_that_is_not_the_project(tmp_path, out, capsys):
    stray = tmp_path / "Downloads"
    stray.mkdir()
    assert pack.main([str(out), "--root", str(stray)]) == 1
    error = capsys.readouterr().err
    assert "pyproject.toml: not found" in error
    assert "src: not found" in error


def test_refuses_when_there_is_nothing_to_pack(tmp_path, out, capsys):
    empty = tmp_path / "empty"
    (empty / "src").mkdir(parents=True)
    (empty / "pyproject.toml").mkdir()  # a folder, not a file, so nothing at all qualifies
    assert pack.main([str(out), "--root", str(empty)]) == 1
    assert "nothing to pack" in capsys.readouterr().err


def test_a_failed_write_leaves_no_partial_zip(project, out, monkeypatch):
    def broken_write(root, files, target):
        target.write_bytes(b"half a zip")
        raise OSError("disk full")

    monkeypatch.setattr(pack, "write_zip", broken_write)
    with pytest.raises(OSError, match="disk full"):
        pack.main([str(out), "--root", str(project)])
    assert not out.exists()
    assert not out.with_name(out.name + ".partial").exists()


# --- the second check on the written zip ------------------------------------------------


def make_zip(path: Path, names: list[str]) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        for name in names:
            archive.writestr(name, "x")
    return path


def test_check_zip_passes_a_clean_zip(tmp_path):
    clean = make_zip(tmp_path / "ok.zip", ["p/src/a.py", "p/tests/fixtures/a.eml", "p/LICENSE"])
    assert pack.check_zip(clean, "p") == []


@pytest.mark.parametrize(
    ("name", "reason"),
    [
        ("other/src/a.py", "not inside the p/ folder"),
        ("p", "not inside the p/ folder"),
        ("p/notes.txt", "not on the list"),
        ("p/samples/a.eml", "not on the list"),
        ("p/.env", "not on the list"),
        ("p/src/__pycache__/a.pyc", "should have been skipped"),
        ("p/src/samples/a.txt", "inside a folder that is never packed"),
        ("p/src/.env", "secrets file"),
        ("p/tests/real.eml", "email file outside tests/fixtures/"),
        ("p/src/cache.sqlite3", "database file"),
    ],
)
def test_check_zip_catches_what_selection_should_have_stopped(tmp_path, name, reason):
    bad = make_zip(tmp_path / "bad.zip", ["p/src/a.py", name])
    problems = pack.check_zip(bad, "p")
    assert len(problems) == 1
    assert name in problems[0]
    assert reason in problems[0]


def test_check_zip_notices_a_damaged_entry(tmp_path):
    damaged = make_zip(tmp_path / "damaged.zip", ["p/src/a.py"])
    data = bytearray(damaged.read_bytes())
    data[data.index(b"x", 30)] = ord("y")  # change the stored byte, so its CRC no longer fits
    damaged.write_bytes(bytes(data))
    assert pack.check_zip(damaged, "p") == ["p/src/a.py: damaged in the zip"]


def test_pack_refuses_when_the_second_check_fails(project, out, monkeypatch, capsys):
    monkeypatch.setattr(pack, "check_zip", lambda path, prefix: ["p/.env: not on the list"])
    assert pack.main([str(out), "--root", str(project)]) == 1
    assert "p/.env: not on the list" in capsys.readouterr().err
    assert not out.exists()
    assert not out.with_name(out.name + ".partial").exists()


# --- small helpers ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "secret"),
    [
        (".env", True),
        (".env.local", True),
        ("prod.env", True),
        (".env.example", False),
        ("environment.py", False),
        ("env.txt", False),
    ],
)
def test_is_secrets_file(name, secret):
    assert pack.is_secrets_file(name) is secret


def test_human_size():
    assert pack._human_size(512) == "512 bytes"
    assert pack._human_size(2048) == "2 KB"


def test_runs_as_a_script(project, out, monkeypatch, capsys):
    """`python scripts/pack.py OUT --root ...`, the way you run it."""
    monkeypatch.setattr(sys, "argv", [str(SCRIPT), str(out), "--root", str(project)])
    with pytest.raises(SystemExit) as stopped:
        runpy.run_path(str(SCRIPT), run_name="__main__")
    assert stopped.value.code == 0
    assert out.exists()
    assert "Packed 13 files" in capsys.readouterr().out


# --- the real project ---------------------------------------------------------------------


def test_packs_this_project(tmp_path):
    """Pack the real project folder. On your Mac it has samples/, .env and .venv in it."""
    target = tmp_path / "real.zip"
    assert pack.main([str(target), "--root", str(PROJECT)]) == 0
    names = names_in(target)
    prefix = PROJECT.name
    assert f"{prefix}/src/phishtriage/cli.py" in names
    assert f"{prefix}/scripts/pack.py" in names
    assert f"{prefix}/tests/fixtures/phish_paypal_spoof.eml" in names
    assert not any(part in {"samples", ".venv", ".env"} for n in names for part in n.split("/"))
