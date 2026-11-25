"""Week 3, step 4: settings from .env; keys and your addresses are never shown."""

import json
import os
from dataclasses import asdict
from pathlib import Path

import pytest
from rich.console import Console
from typer.testing import CliRunner

from phishtriage import cli
from phishtriage.cli import app
from phishtriage.config import (
    MY_ADDRESSES_VAR,
    SERVICE_KEYS,
    Secret,
    Settings,
    default_cache_path,
    load_settings,
    parse_addresses,
)

runner = CliRunner()

# Fake keys: the right shape, but not real
VT_KEY = "a" * 64
ABUSEIPDB_KEY = "b" * 80
ABUSECH_KEY = "c" * 48
ME = "me.victim@example.org"


def write_env(tmp_path: Path, text: str, mode: int = 0o600) -> Path:
    path = tmp_path / ".env"
    path.write_text(text, encoding="utf-8")
    path.chmod(mode)
    return path


@pytest.fixture
def full_env(tmp_path) -> Path:
    return write_env(
        tmp_path,
        f"VT_API_KEY={VT_KEY}\nABUSEIPDB_API_KEY={ABUSEIPDB_KEY}\n"
        f"ABUSECH_AUTH_KEY={ABUSECH_KEY}\n{MY_ADDRESSES_VAR}={ME}, me@my.example.org\n",
    )


@pytest.fixture
def wide(monkeypatch):
    """A 300-column report, so long temporary paths do not wrap the messages."""
    monkeypatch.setattr(cli, "console", Console(width=300))


@pytest.fixture
def no_real_keys(monkeypatch):
    """Remove any real keys from this process's environment, for the CLI tests."""
    for name in [v for v in SERVICE_KEYS.values() if v] + [MY_ADDRESSES_VAR, "PHISHTRIAGE_CACHE"]:
        monkeypatch.delenv(name, raising=False)


# --- reading the settings --------------------------------------------------------------


def test_keys_and_addresses_come_from_the_env_file(full_env):
    settings = load_settings(full_env, environ={})
    assert settings.vt_api_key.reveal() == VT_KEY
    assert settings.abuseipdb_api_key.reveal() == ABUSEIPDB_KEY
    assert settings.abusech_auth_key.reveal() == ABUSECH_KEY
    assert settings.my_addresses.reveal() == (ME, "me@my.example.org")
    assert settings.env_file == full_env
    assert settings.ready_services() == ["virustotal", "abuseipdb", "urlhaus", "rdap"]
    assert settings.warnings == ()


def test_the_environment_wins_over_the_env_file(full_env):
    settings = load_settings(full_env, environ={"VT_API_KEY": "d" * 64, "ABUSEIPDB_API_KEY": ""})
    assert settings.vt_api_key.reveal() == "d" * 64
    # an empty variable does not hide the value in the file
    assert settings.abuseipdb_api_key.reveal() == ABUSEIPDB_KEY


def test_export_lines_quotes_and_comments_are_understood(tmp_path):
    env = write_env(
        tmp_path,
        f'# my keys\nexport VT_API_KEY="{VT_KEY}"\n'
        f"ABUSEIPDB_API_KEY='{ABUSEIPDB_KEY}'  # free plan\nABUSECH_AUTH_KEY\n"
        "THIS LINE IS BROKEN\nX=${VT_API_KEY}\n",
    )
    settings = load_settings(env, environ={})
    assert settings.vt_api_key.reveal() == VT_KEY
    assert settings.abuseipdb_api_key.reveal() == ABUSEIPDB_KEY
    assert settings.missing_key("urlhaus") == "ABUSECH_AUTH_KEY is not set"  # no "=" at all


def test_a_missing_env_file_is_not_an_error(tmp_path):
    settings = load_settings(tmp_path / ".env", environ={})
    assert settings.env_file is None
    assert settings.missing_key("virustotal") == "VT_API_KEY is not set"
    assert settings.missing_key("abuseipdb") == "ABUSEIPDB_API_KEY is not set"
    assert settings.missing_key("rdap") is None  # needs no key
    assert settings.ready_services() == ["rdap"]
    assert settings.key("rdap") == Secret("")


def test_no_env_file_at_all(tmp_path):
    settings = load_settings(None, environ={"VT_API_KEY": VT_KEY})
    assert settings.env_file is None
    assert settings.ready_services() == ["virustotal", "rdap"]


def test_a_key_with_a_space_is_ignored(tmp_path):
    env = write_env(tmp_path, f'VT_API_KEY="{VT_KEY[:10]} {VT_KEY[10:]}"\n')
    settings = load_settings(env, environ={})
    assert not settings.vt_api_key
    assert any("VT_API_KEY contains a space" in w for w in settings.warnings)


def test_an_unreadable_env_file_is_a_warning(tmp_path):
    env = tmp_path / ".env"
    env.write_bytes(b"VT_API_KEY=\xff\xfe\n")  # not valid UTF-8
    settings = load_settings(env, environ={})
    assert settings.env_file is None
    assert not settings.vt_api_key
    assert any("could not read" in w and "UnicodeDecodeError" in w for w in settings.warnings)


@pytest.mark.skipif(os.name != "posix", reason="Unix file permissions only")
def test_an_env_file_others_can_read_is_a_warning(tmp_path):
    env = write_env(tmp_path, f"VT_API_KEY={VT_KEY}\n", mode=0o644)
    warnings = load_settings(env, environ={}).warnings
    assert any("can be read by other users" in w and "chmod 600" in w for w in warnings)
    env.chmod(0o600)
    assert not any("other users" in w for w in load_settings(env, environ={}).warnings)


# --- your addresses ----------------------------------------------------------------------


def test_parse_addresses():
    assert parse_addresses("Me@Gmail.com; me@my.sliit.lk, junk me@gmail.com") == (
        ("me@gmail.com", "me@my.sliit.lk"),
        1,
    )
    assert parse_addresses("") == ((), 0)
    assert parse_addresses("a@b, @x.test, x@") == ((), 3)  # no dot / no name / no domain


def test_bad_address_entries_are_counted_but_never_repeated(tmp_path):
    env = write_env(tmp_path, f"{MY_ADDRESSES_VAR}={ME}, secret-name-typo\n")
    settings = load_settings(env, environ={})
    assert settings.my_addresses.reveal() == (ME,)
    assert any("1 entry is not an email address and was ignored" in w for w in settings.warnings)
    assert not any("secret-name-typo" in w for w in settings.warnings)


def test_several_bad_address_entries(tmp_path):
    env = write_env(tmp_path, f"{MY_ADDRESSES_VAR}=typo1, {ME}, typo2\n")
    warnings = load_settings(env, environ={}).warnings
    assert any("2 entries are not email addresses and were ignored" in w for w in warnings)


def test_no_addresses_gives_a_warning(tmp_path):
    warnings = load_settings(tmp_path / ".env", environ={}).warnings
    assert any(f"{MY_ADDRESSES_VAR} is not set" in w for w in warnings)


# --- the cache path ------------------------------------------------------------------------


def test_cache_path_default_and_override(tmp_path):
    assert load_settings(None, environ={}).cache_path == default_cache_path()
    assert default_cache_path() == Path.home() / ".cache" / "phishtriage" / "cache.sqlite3"
    custom = load_settings(None, environ={"PHISHTRIAGE_CACHE": "~/pt/cache.sqlite3"})
    assert custom.cache_path == Path.home() / "pt" / "cache.sqlite3"  # "~" is expanded


# --- keys and addresses are never shown -----------------------------------------------------


def test_a_secret_never_prints_its_value():
    key = Secret(VT_KEY)
    for shown in (str(key), repr(key), f"{key}", format(key), str([key])):
        assert VT_KEY not in shown
        assert "********" in shown
    assert key.reveal() == VT_KEY
    assert bool(key) is True
    assert bool(Secret("")) is False
    assert str(Secret("")) == ""
    addresses = Secret((ME,))
    assert ME not in repr(addresses)
    assert addresses.reveal() == (ME,)
    assert Secret("x") == Secret("x")
    assert Secret("x") != Secret("y")
    assert Secret("x") != "x"  # never equal to plain text
    assert len({Secret("x"), Secret("x")}) == 1  # usable in a set or as a dict key


def test_settings_never_show_keys_or_addresses(full_env):
    settings = load_settings(full_env, environ={})
    as_json = json.dumps(asdict(settings), default=str)  # e.g. a future JSON report
    for shown in (repr(settings), str(settings), as_json):
        for value in (VT_KEY, ABUSEIPDB_KEY, ABUSECH_KEY, ME):
            assert value not in shown


def test_settings_are_frozen(full_env):
    settings = load_settings(full_env, environ={})
    with pytest.raises(AttributeError):
        settings.vt_api_key = Secret("other")  # type: ignore[misc]
    assert Settings().ready_services() == ["rdap"]


# --- phishtriage config ---------------------------------------------------------------------


def test_config_command_shows_status_but_never_keys_or_addresses(full_env, no_real_keys, wide):
    result = runner.invoke(app, ["config", "--env-file", str(full_env)])
    assert result.exit_code == 0, result.output
    assert "VT_API_KEY set" in result.output
    assert "ABUSECH_AUTH_KEY set" in result.output
    assert "not needed" in result.output  # RDAP
    assert "ready" in result.output
    assert "Your addresses: 2 in PHISHTRIAGE_MY_ADDRESSES" in result.output
    for value in (VT_KEY, ABUSEIPDB_KEY, ABUSECH_KEY, ME, "me@my.example.org"):
        assert value not in result.output


def test_config_command_without_an_env_file(tmp_path, no_real_keys, wide):
    result = runner.invoke(app, ["config", "--env-file", str(tmp_path / "missing.env")])
    assert result.exit_code == 0, result.output
    assert "not found" in result.output
    assert "VT_API_KEY missing" in result.output
    assert "off" in result.output
    assert "Warning:" in result.output
