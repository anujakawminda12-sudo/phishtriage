"""Week 3, step 7: the cache keeps answers for a while and counts every real API call."""

import os
import sqlite3
import stat
from contextlib import closing
from datetime import UTC, datetime, timedelta

import pytest
from rich.console import Console
from typer.testing import CliRunner

from phishtriage import cli
from phishtriage.cli import app
from phishtriage.enrich.cache import Cache, open_cache, ttl
from phishtriage.enrich.models import DEFERRED, FAILED, FOUND, NOT_FOUND, Lookup, LookupResult

runner = CliRunner()

DOMAIN = Lookup("virustotal", "domain", "paypa1-login.com")
URL = Lookup("urlhaus", "url", "https://paypa1-login.com/verify")
AGE = Lookup("rdap", "domain", "paypa1-login.com")


class FakeClock:
    """A clock the test moves by hand (Java: java.time.Clock.fixed, plus an advance())."""

    def __init__(self) -> None:
        self.now = datetime(2026, 11, 22, 12, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **amount: float) -> None:
        self.now += timedelta(**amount)


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def cache(tmp_path, clock):
    with Cache(tmp_path / "cache" / "cache.sqlite3", clock) as opened:
        yield opened


def found(lookup: Lookup = DOMAIN, **data) -> LookupResult:
    return LookupResult(lookup, FOUND, summary="6 of 94 engines say malicious", data=data)


# --- results ---------------------------------------------------------------------------


def test_a_stored_answer_comes_back_marked_as_cached(cache):
    assert cache.get(DOMAIN) is None
    assert cache.put(found(malicious=6, engines=94)) is True
    result = cache.get(DOMAIN)
    assert result is not None
    assert result.from_cache is True
    assert result.status == FOUND
    assert result.summary == "6 of 94 engines say malicious"
    assert result.data == {"malicious": 6, "engines": 94}
    assert result.checked_at == "2026-11-22T12:00:00+00:00"


def test_each_service_kind_and_value_is_stored_separately(cache):
    cache.put(found(DOMAIN))
    assert cache.get(Lookup("urlhaus", "domain", "paypa1-login.com")) is None
    assert cache.get(Lookup("virustotal", "url", "paypa1-login.com")) is None
    assert cache.get(Lookup("virustotal", "domain", "other.com")) is None


def test_a_newer_answer_replaces_the_old_one(cache):
    cache.put(LookupResult(DOMAIN, NOT_FOUND))
    cache.put(found(malicious=2))
    assert cache.get(DOMAIN).status == FOUND
    assert cache.stats()["virustotal"]["stored"] == 1


@pytest.mark.parametrize(
    ("lookup", "status", "hours"),
    [
        (DOMAIN, FOUND, 24),
        (URL, NOT_FOUND, 6),
        (AGE, FOUND, 30 * 24),
        (AGE, NOT_FOUND, 24),
    ],
)
def test_answers_expire(cache, clock, lookup, status, hours):
    assert ttl(lookup.service, status) == timedelta(hours=hours)
    cache.put(LookupResult(lookup, status))
    clock.advance(hours=hours - 0.01)
    assert cache.get(lookup) is not None
    clock.advance(hours=0.02)
    assert cache.get(lookup) is None


@pytest.mark.parametrize("status", [FAILED, DEFERRED])
def test_failures_are_never_stored(cache, status):
    assert cache.put(LookupResult(DOMAIN, status, error="timed out")) is False
    assert cache.get(DOMAIN) is None


def test_answers_survive_closing_and_reopening(tmp_path, clock):
    path = tmp_path / "cache.sqlite3"
    with Cache(path, clock) as first:
        first.put(found())
        first.record_call("virustotal")
    with Cache(path, clock) as second:
        assert second.get(DOMAIN) is not None
        assert second.calls_within("virustotal") == 1


def test_clear_forgets_results_but_never_the_call_log(cache):
    cache.put(found())
    cache.record_call("virustotal")
    assert cache.clear() == 1
    assert cache.get(DOMAIN) is None
    assert cache.calls_within("virustotal") == 1  # the service still remembers the call


# --- the call log ------------------------------------------------------------------------


def test_calls_are_counted_over_a_rolling_24_hours(cache, clock):
    for _ in range(3):
        cache.record_call("virustotal")
    cache.record_call("abuseipdb")
    assert cache.calls_within("virustotal") == 3
    assert cache.calls_within("abuseipdb") == 1
    assert cache.calls_within("urlhaus") == 0
    clock.advance(hours=23, minutes=59)
    assert cache.calls_within("virustotal") == 3  # still inside the day
    clock.advance(minutes=2)
    assert cache.calls_within("virustotal") == 0


def test_recent_call_times_for_the_per_minute_limit(cache, clock):
    cache.record_call("virustotal")
    clock.advance(seconds=20)
    cache.record_call("virustotal")
    clock.advance(seconds=50)  # the first call is now 70 seconds old
    times = cache.call_times("virustotal", timedelta(minutes=1))
    assert times == [datetime(2026, 11, 22, 12, 0, 20, tzinfo=UTC)]


def test_old_calls_and_expired_results_are_removed_when_the_cache_opens(tmp_path, clock):
    path = tmp_path / "cache.sqlite3"
    with Cache(path, clock) as first:
        first.record_call("virustotal")
        first.put(found())
    clock.advance(days=3)
    with Cache(path, clock):
        pass
    # closing(): sqlite3's own "with" commits but does not close the connection
    with closing(sqlite3.connect(path)) as db:
        assert db.execute("SELECT COUNT(*) FROM calls").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM results").fetchone()[0] == 0


def test_stats(cache, clock):
    cache.put(found(DOMAIN))
    cache.put(LookupResult(URL, NOT_FOUND))
    cache.record_call("virustotal")
    cache.record_call("virustotal")
    assert cache.stats() == {
        "urlhaus": {"stored": 1, "calls_24h": 0},
        "virustotal": {"stored": 1, "calls_24h": 2},
    }
    clock.advance(hours=7)  # the "not found" answer has expired
    assert "urlhaus" not in cache.stats()  # nothing left for it: not listed at all


# --- privacy and robustness -----------------------------------------------------------------


@pytest.mark.skipif(os.name != "posix", reason="Unix file permissions only")
def test_the_cache_and_a_new_folder_are_private(tmp_path, clock):
    path = tmp_path / "new" / "cache.sqlite3"
    with Cache(path, clock):
        pass
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700


@pytest.mark.skipif(os.name != "posix", reason="Unix file permissions only")
def test_an_existing_folder_is_left_as_it_is(tmp_path, clock):
    shared = tmp_path / "shared"
    shared.mkdir(mode=0o755)
    shared.chmod(0o755)
    with Cache(shared / "cache.sqlite3", clock):
        pass
    assert stat.S_IMODE(shared.stat().st_mode) == 0o755  # not ours to change


def test_a_damaged_cache_falls_back_to_memory_with_a_warning(tmp_path, clock):
    path = tmp_path / "cache.sqlite3"
    path.write_bytes(b"this is not a database" * 100)
    cache, warnings = open_cache(path, clock)
    with cache:
        assert len(warnings) == 1
        assert "could not be used (DatabaseError)" in warnings[0]
        assert "watch the daily quotas" in warnings[0]
        cache.put(found())  # still works, just not on disk
        assert cache.get(DOMAIN) is not None


def test_open_cache_normally_has_no_warnings(tmp_path, clock):
    cache, warnings = open_cache(tmp_path / "cache.sqlite3", clock)
    with cache:
        assert warnings == []


# --- phishtriage cache ---------------------------------------------------------------------------


@pytest.fixture
def cache_path(tmp_path, monkeypatch):
    """Point the CLI at a cache in tmp_path (the environment wins over .env)."""
    path = tmp_path / "cache.sqlite3"
    monkeypatch.setenv("PHISHTRIAGE_CACHE", str(path))
    monkeypatch.setattr(cli, "console", Console(width=300))
    return path


def test_cache_command_without_a_cache(cache_path, tmp_path):
    result = runner.invoke(app, ["cache", "--env-file", str(tmp_path / "none.env")])
    assert result.exit_code == 0, result.output
    assert "No cache yet" in result.output
    assert not cache_path.exists()  # looking does not create one


def test_cache_command_shows_counts_and_clears(cache_path, tmp_path):
    with Cache(cache_path) as cache:
        cache.put(found())
        cache.record_call("virustotal")
    no_env = str(tmp_path / "none.env")

    result = runner.invoke(app, ["cache", "--env-file", no_env])
    assert result.exit_code == 0, result.output
    assert "virustotal │              1 │                     1" in result.output

    result = runner.invoke(app, ["cache", "--env-file", no_env, "--clear"])
    assert "Removed 1 stored results. The log of API calls is kept" in result.output
    assert "virustotal │              0 │                     1" in result.output


def test_cache_command_with_a_damaged_cache(cache_path, tmp_path):
    cache_path.write_bytes(b"not a database" * 100)
    result = runner.invoke(app, ["cache", "--env-file", str(tmp_path / "none.env")])
    assert result.exit_code == 0, result.output
    assert "Warning:" in result.output
