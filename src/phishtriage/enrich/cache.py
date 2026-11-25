"""Lookup results kept on disk, and a count of every real API call (week 3, step 7).

Two tables in one SQLite file (default ~/.cache/phishtriage/cache.sqlite3):

    results   one row per Lookup: the answer and when it expires. Repeated runs, and the
              same IOC in many emails, are answered from here without using any quota.
    calls     one row per real API request, kept for 2 days. The free plans count per day
              (VirusTotal: 500), and a limit per run cannot stop three runs in one day from
              going over it. This log can: before each request, step 8 asks how many
              calls were made in the last 24 hours.

How long an answer is trusted:

    found (VirusTotal, AbuseIPDB, URLhaus)   24 hours   (the proposal's figure)
    not found                                 6 hours   (a new phishing URL is often
                                                         listed within hours)
    domain age (RDAP): found 30 days, not found 1 day   (a registration date rarely changes)
    failed or deferred                        never stored, so the next run asks again

Rules:
- the file and its folder are private to your user account (0600 and 0700): the cache
  holds lookup values from your emails (never your address: the plan removed it);
- a broken or unwritable cache never stops an analysis (open_cache);
- clear() forgets the results but never the call log, because the service's own count
  of your calls does not reset either.

sqlite3 is in Python's standard library (Java comparison: an embedded database such as
H2 or SQLite through JDBC, with no server to run). Nothing here touches the network.
"""

import json
import os
import sqlite3
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import TracebackType

from phishtriage.enrich.models import FOUND, NOT_FOUND, Lookup, LookupResult

Clock = Callable[[], datetime]

SCHEMA_VERSION = 1
CALL_LOG_KEPT = timedelta(days=2)
QUOTA_WINDOW = timedelta(hours=24)

DEFAULT_TTL = {FOUND: timedelta(hours=24), NOT_FOUND: timedelta(hours=6)}
SERVICE_TTL = {
    ("rdap", FOUND): timedelta(days=30),
    ("rdap", NOT_FOUND): timedelta(days=1),
}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS results (
    service    TEXT NOT NULL,
    kind       TEXT NOT NULL,
    query      TEXT NOT NULL,
    status     TEXT NOT NULL,
    summary    TEXT NOT NULL,
    data       TEXT NOT NULL,      -- JSON
    checked_at TEXT NOT NULL,      -- ISO 8601, UTC
    expires_at REAL NOT NULL,      -- seconds since 1970, UTC
    PRIMARY KEY (service, kind, query)
);
CREATE TABLE IF NOT EXISTS calls (
    service TEXT NOT NULL,
    at      REAL NOT NULL          -- seconds since 1970, UTC
);
CREATE INDEX IF NOT EXISTS calls_by_service ON calls (service, at);
"""


def utc_now() -> datetime:
    return datetime.now(UTC)


def ttl(service: str, status: str) -> timedelta | None:
    """How long an answer may be reused, or None if it must not be stored at all."""
    return SERVICE_TTL.get((service, status), DEFAULT_TTL.get(status))


class Cache:
    """The results table and the call log, in one SQLite file.

    clock is injected (Java: like passing a java.time.Clock), so tests can move time
    forward by 25 hours without waiting. Use it in a with block, which closes the
    file at the end (Java: try-with-resources).
    """

    def __init__(self, path: Path | str, clock: Clock = utc_now) -> None:
        self.clock = clock
        self.path = path
        if path != ":memory:":
            _make_private_folder(Path(path).parent)
        self._db = sqlite3.connect(str(path), timeout=5)
        try:
            if path != ":memory:" and os.name == "posix":
                os.chmod(path, 0o600)  # only your user account can read the cached values
            self._db.executescript(_SCHEMA)  # fails here if the file is not a database
            self._db.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            self._forget_old_calls()
            self._db.commit()
        except BaseException:
            # Close before giving up, or the connection leaks (Python 3.13+ warns about
            # it: "ResourceWarning: unclosed database"). Java: close() in a catch block.
            self._db.close()
            raise

    # --- results ----------------------------------------------------------------------

    def get(self, lookup: Lookup) -> LookupResult | None:
        """The stored answer, or None if there is none or it has expired."""
        row = self._db.execute(
            "SELECT status, summary, data, checked_at FROM results"
            " WHERE service = ? AND kind = ? AND query = ? AND expires_at > ?",
            (lookup.service, lookup.kind, lookup.query, self._now()),
        ).fetchone()
        if row is None:
            return None
        status, summary, data, checked_at = row
        return LookupResult(
            lookup=lookup,
            status=status,
            summary=summary,
            data=json.loads(data),
            checked_at=checked_at,
            from_cache=True,
        )

    def put(self, result: LookupResult) -> bool:
        """Store an answer. Returns False (and stores nothing) for FAILED or DEFERRED."""
        keep_for = ttl(result.lookup.service, result.status)
        if keep_for is None:
            return False
        lookup = result.lookup
        self._db.execute(
            "INSERT OR REPLACE INTO results VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                lookup.service,
                lookup.kind,
                lookup.query,
                result.status,
                result.summary,
                json.dumps(result.data, sort_keys=True, default=str),
                result.checked_at or self.clock().isoformat(timespec="seconds"),
                (self.clock() + keep_for).timestamp(),
            ),
        )
        self._db.commit()
        return True

    def clear(self) -> int:
        """Forget every stored answer (never the call log). Returns how many were removed."""
        removed = self._db.execute("DELETE FROM results").rowcount
        self._db.commit()
        return removed

    # --- the call log ---------------------------------------------------------------------

    def record_call(self, service: str) -> None:
        """Log one real request to a service, whether it succeeded or not."""
        self._db.execute("INSERT INTO calls VALUES (?, ?)", (service, self._now()))
        self._db.commit()

    def calls_within(self, service: str, window: timedelta = QUOTA_WINDOW) -> int:
        """How many requests were sent to a service in the last `window` (default 24 h).

        A rolling window is safe whichever way a service counts its day: at midnight UTC,
        or 24 hours back from each request.
        """
        since = (self.clock() - window).timestamp()
        row = self._db.execute(
            "SELECT COUNT(*) FROM calls WHERE service = ? AND at > ?", (service, since)
        ).fetchone()
        return int(row[0])

    def call_times(self, service: str, window: timedelta) -> list[datetime]:
        """When each request in the last `window` was sent, oldest first.

        Step 8's per-minute limiter starts from these, so a run started straight after
        another one still waits for VirusTotal's 4-a-minute limit.
        """
        since = (self.clock() - window).timestamp()
        rows = self._db.execute(
            "SELECT at FROM calls WHERE service = ? AND at > ? ORDER BY at", (service, since)
        ).fetchall()
        return [datetime.fromtimestamp(at, UTC) for (at,) in rows]

    # --- state for the report ----------------------------------------------------------------

    def stats(self) -> dict[str, dict[str, int]]:
        """Per service: stored answers that are still valid, and calls in the last 24 h."""
        now = self._now()
        stats: dict[str, dict[str, int]] = {}
        for service, count in self._db.execute(
            "SELECT service, COUNT(*) FROM results WHERE expires_at > ? GROUP BY service",
            (now,),
        ):
            stats.setdefault(service, {"stored": 0, "calls_24h": 0})["stored"] = count
        for service, count in self._db.execute(
            "SELECT service, COUNT(*) FROM calls WHERE at > ? GROUP BY service",
            (now - QUOTA_WINDOW.total_seconds(),),
        ):
            stats.setdefault(service, {"stored": 0, "calls_24h": 0})["calls_24h"] = count
        return dict(sorted(stats.items()))

    def close(self) -> None:
        self._db.close()

    def __enter__(self) -> "Cache":
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    # --- helpers -------------------------------------------------------------------------------

    def _now(self) -> float:
        return self.clock().timestamp()

    def _forget_old_calls(self) -> None:
        cutoff = (self.clock() - CALL_LOG_KEPT).timestamp()
        self._db.execute("DELETE FROM calls WHERE at <= ?", (cutoff,))
        self._db.execute("DELETE FROM results WHERE expires_at <= ?", (self._now(),))


def open_cache(path: Path, clock: Clock = utc_now) -> tuple[Cache, list[str]]:
    """Open the cache file, or fall back to a temporary one that lives in memory.

    A damaged file, a full disk or a folder you cannot write to must not stop an
    analysis, so the problem becomes a warning instead (Week 1's rule: record defects
    instead of crashing). In memory, nothing is reused between runs and the call log
    starts empty, so the warning says so.
    """
    try:
        return Cache(path, clock), []
    except (sqlite3.Error, OSError) as error:
        warning = (
            f"cache {path} could not be used ({type(error).__name__}); a temporary one is "
            "used instead, so earlier calls today are not counted: watch the daily quotas"
        )
        return Cache(":memory:", clock), [warning]


def _make_private_folder(folder: Path) -> None:
    """Create the folder, readable only by your user account, if it does not exist yet.

    An existing folder is left exactly as it is: changing the permissions of a folder we
    did not create (PHISHTRIAGE_CACHE=/tmp/cache.sqlite3, run as root) could lock other
    users out of it.
    """
    if not folder.exists():
        folder.mkdir(mode=0o700, parents=True)
