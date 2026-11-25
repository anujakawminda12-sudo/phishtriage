"""Settings for the threat-intel lookups: API keys, your addresses, the cache (week 3, step 4).

Values come from a .env file in the folder you run phishtriage from (git-ignored; copy
.env.example to start one). A variable already set in the environment wins over .env, so
one command can be run with a different key without editing the file.

Rules:
- A key is never printed, logged or written to a file. It is kept in a Secret, which
  shows as ******** however it is printed; only Secret.reveal() gives the real value,
  and only the code that builds an HTTP request calls it (step 8).
- A missing key switches that one service off, with the reason; it is never an error.
- Problems with the .env file are recorded as warnings instead of stopping the program.
- Your own addresses are a Secret too: only how many there are is ever shown.

Nothing here touches the network.
"""

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import dotenv_values

# Each lookup service and the variable that holds its key (None: it needs no key)
SERVICE_KEYS: dict[str, str | None] = {
    "virustotal": "VT_API_KEY",
    "abuseipdb": "ABUSEIPDB_API_KEY",
    "urlhaus": "ABUSECH_AUTH_KEY",  # one abuse.ch Auth-Key covers URLhaus
    "rdap": None,  # domain registration dates are public: no account needed
}
MY_ADDRESSES_VAR = "PHISHTRIAGE_MY_ADDRESSES"
CACHE_VAR = "PHISHTRIAGE_CACHE"
DEFAULT_ENV_FILE = Path(".env")


class Secret[T]:
    """A value that must never be shown: an API key, or your own addresses.

        key = Secret("abc123")
        print(key), f"{key}", repr(key)  -> ********
        key.reveal()                     -> "abc123"   (only for the HTTP header)

    Secret[T] is generic (Java: class Secret<T>): Secret[str] holds a key and
    Secret[tuple[str, ...]] holds your addresses. Java comparison: like keeping a password
    in a char[] instead of a String so it cannot end up in a log by accident; here printing
    is made safe instead. It is deliberately not a dataclass, so dataclasses.asdict()
    (which a JSON report might use) cannot turn it back into plain text.
    """

    __slots__ = ("_value",)  # no other attributes can be added (and no __dict__ to dump)

    def __init__(self, value: T) -> None:
        self._value = value

    def reveal(self) -> T:
        """The real value. Call this only where it is really needed."""
        return self._value

    def __bool__(self) -> bool:
        return bool(self._value)  # "if settings.vt_api_key:" means "is a key set?"

    def __str__(self) -> str:
        return "********" if self._value else ""

    __repr__ = __str__

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Secret) and other._value == self._value

    def __hash__(self) -> int:
        return hash(self._value)


@dataclass(frozen=True)
class Settings:
    """Everything the lookups need (Java: an immutable record, built once by load_settings).

    The keys and your addresses are Secrets, so neither print(settings) nor
    dataclasses.asdict(settings) can show them.
    """

    vt_api_key: Secret[str] = Secret("")
    abuseipdb_api_key: Secret[str] = Secret("")
    abusech_auth_key: Secret[str] = Secret("")
    my_addresses: Secret[tuple[str, ...]] = Secret(())
    cache_path: Path = field(default_factory=lambda: default_cache_path())
    env_file: Path | None = None  # the .env file that was read, or None
    warnings: tuple[str, ...] = ()

    def key(self, service: str) -> Secret[str]:
        """The key for a service; an empty Secret when it has none or needs none."""
        variable = SERVICE_KEYS[service]
        if variable is None:
            return Secret("")
        return getattr(self, variable.lower())

    def missing_key(self, service: str) -> str | None:
        """Why a service cannot be used, or None when it is ready.

        settings.missing_key("abuseipdb") -> "ABUSEIPDB_API_KEY is not set"
        """
        variable = SERVICE_KEYS[service]
        if variable is None or self.key(service):
            return None
        return f"{variable} is not set"

    def ready_services(self) -> list[str]:
        """The services that can be used, in the order of SERVICE_KEYS."""
        return [service for service in SERVICE_KEYS if self.missing_key(service) is None]


def default_cache_path() -> Path:
    """~/.cache/phishtriage/cache.sqlite3: outside the project folder on purpose, so the
    cache (which holds lookup values from your emails) can never end up in a zip or a commit.
    """
    return Path.home() / ".cache" / "phishtriage" / "cache.sqlite3"


def load_settings(
    env_file: Path | None = DEFAULT_ENV_FILE, environ: Mapping[str, str] | None = None
) -> Settings:
    """Read the settings from the environment and the .env file.

    environ defaults to the real environment (os.environ); tests pass their own dict, so
    they never depend on keys that happen to be set on the machine running them.
    """
    environ = os.environ if environ is None else environ
    warnings: list[str] = []
    from_file: dict[str, str] = {}
    used_file: Path | None = None

    if env_file is not None and env_file.is_file():
        try:
            # interpolate=False: a "$" inside a key is kept as it is, not expanded
            raw = dotenv_values(env_file, interpolate=False)
        except (OSError, UnicodeDecodeError) as error:
            warnings.append(f"could not read {env_file}: {type(error).__name__}")
        else:
            from_file = {name: value for name, value in raw.items() if value is not None}
            used_file = env_file
            warnings.extend(_permission_warnings(env_file))

    def get(name: str) -> str:
        # A non-empty environment variable wins; an empty one does not hide the file's value
        return (environ.get(name) or from_file.get(name) or "").strip()

    keys: dict[str, Secret[str]] = {}
    for variable in (v for v in SERVICE_KEYS.values() if v is not None):
        value = get(variable)
        if re.search(r"\s", value):
            warnings.append(f"{variable} contains a space, so it was ignored (copy-paste slip?)")
            value = ""
        keys[variable.lower()] = Secret(value)

    addresses, ignored = parse_addresses(get(MY_ADDRESSES_VAR))
    if ignored:
        if ignored == 1:
            what = "entry is not an email address and was"
        else:
            what = "entries are not email addresses and were"
        warnings.append(f"{MY_ADDRESSES_VAR}: {ignored} {what} ignored")
    if not addresses:
        warnings.append(
            f"{MY_ADDRESSES_VAR} is not set: your address is hidden only when it is in an "
            "email's To, Cc, Delivered-To or X-Original-To header"
        )

    cache = get(CACHE_VAR)
    return Settings(
        **keys,
        my_addresses=Secret(addresses),
        cache_path=Path(cache).expanduser() if cache else default_cache_path(),
        env_file=used_file,
        warnings=tuple(warnings),
    )


def parse_addresses(value: str) -> tuple[tuple[str, ...], int]:
    """Split a list of addresses written with commas, semicolons or spaces.

        "Me@Gmail.com; me@my.sliit.lk, junk" -> (("me@gmail.com", "me@my.sliit.lk"), 1)

    Returns the addresses (lower-case, no repeats, in order) and how many entries were not
    addresses. The bad entries themselves are not returned, so no message can repeat them.
    """
    entries = [entry for entry in re.split(r"[,;\s]+", value) if entry]
    good = [entry.lower() for entry in entries if re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", entry)]
    return tuple(dict.fromkeys(good)), len(entries) - len(good)


def _permission_warnings(env_file: Path) -> list[str]:
    """Warn when other user accounts on this computer could read the keys."""
    if os.name != "posix":
        return []
    if env_file.stat().st_mode & 0o077:  # any permission for the group or for others
        return [f"{env_file} can be read by other users; run: chmod 600 {env_file}"]
    return []
