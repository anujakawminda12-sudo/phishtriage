"""Shared test setup.

Week 3, step 1: every test runs with the network switched off (block_network below), so
no test can ever call VirusTotal, AbuseIPDB, URLhaus or an RDAP server, use up quota or
leak a value, even by mistake. Tests that need an HTTP reply fake it with respx, which
answers inside httpx before any socket is opened, so the block never gets in its way.
"""

import socket
from pathlib import Path

import pytest

from phishtriage import cli, config
from phishtriage.config import CACHE_VAR, DEFAULT_ENV_FILE, MY_ADDRESSES_VAR, SERVICE_KEYS

FIXTURES = Path(__file__).parent / "fixtures"

BLOCKED_MESSAGE = (
    "Tests must not use the network. Fake the HTTP reply with respx instead "
    "(see tests/test_network_guard.py)."
)

# Unix sockets are files on this machine, not the network; some libraries use them
LOCAL_FAMILIES = {getattr(socket, "AF_UNIX", None)} - {None}


class NetworkBlockedError(RuntimeError):
    """Raised when a test tries to open a network connection or look up a host name."""


@pytest.fixture
def fixtures() -> Path:
    """Folder of safe, hand-built test emails."""
    return FIXTURES


@pytest.fixture(autouse=True)
def block_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make every network connection and DNS lookup fail, in every test.

    autouse=True means pytest applies this fixture to every test without being asked
    (Java/JUnit 5: like an extension registered on every test class). monkeypatch swaps
    the functions for the length of one test only and puts the real ones back afterwards.

    DNS lookups (getaddrinfo) are blocked as well as connections: looking up an attacker's
    domain name would tell their name server that someone is analysing the email.
    """

    def refuse(*args: object, **kwargs: object) -> None:
        raise NetworkBlockedError(BLOCKED_MESSAGE)

    real_connect = socket.socket.connect
    real_connect_ex = socket.socket.connect_ex

    def connect(self: socket.socket, address: object) -> None:
        if self.family in LOCAL_FAMILIES:
            return real_connect(self, address)
        raise NetworkBlockedError(BLOCKED_MESSAGE)

    def connect_ex(self: socket.socket, address: object) -> int:
        if self.family in LOCAL_FAMILIES:
            return real_connect_ex(self, address)
        raise NetworkBlockedError(BLOCKED_MESSAGE)

    monkeypatch.setattr(socket.socket, "connect", connect)
    monkeypatch.setattr(socket.socket, "connect_ex", connect_ex)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    monkeypatch.setattr(socket, "gethostbyname", refuse)
    monkeypatch.setattr(socket, "gethostbyname_ex", refuse)


@pytest.fixture(autouse=True)
def no_real_samples(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """No test reads your real samples/ folder (week 4).

    analyze looks for heldout.sha256 files in the project's samples/ folder, and tests run
    in the project folder, where your real held-out lists sit. A test that needs one makes
    its own and points cli.SAMPLES at it.
    """
    monkeypatch.setattr(cli, "SAMPLES", tmp_path / "no-samples")


@pytest.fixture(autouse=True)
def isolated_settings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """No test reads your real .env or your real environment variables (week 4, step 10)."""
    isolate_settings(tmp_path, monkeypatch)


def isolate_settings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The work of isolated_settings, as a plain function so a test can check it.

    Since step 10, analyze reads the settings on every run (the report hides
    PHISHTRIAGE_MY_ADDRESSES). Tests run in the project folder, where your real .env
    sits with your keys, so: the keys and settings are removed from the environment, and
    the default .env is swapped for a file that does not exist. A test that needs a
    setting sets it itself (monkeypatch.setenv), after this has run.
    """
    for name in (*(v for v in SERVICE_KEYS.values() if v), MY_ADDRESSES_VAR, CACHE_VAR):
        monkeypatch.delenv(name, raising=False)
    real_load_settings = config.load_settings

    def load_settings(
        env_file: Path | None = DEFAULT_ENV_FILE, environ: dict[str, str] | None = None
    ) -> config.Settings:
        if env_file == DEFAULT_ENV_FILE:
            env_file = tmp_path / "no-such.env"
        return real_load_settings(env_file, environ)

    monkeypatch.setattr(cli, "load_settings", load_settings)


# --- Week 3, step 12: a phishing email with real-looking names, and fake APIs ---------

PHISH_ME = "me.victim@gmail.com"
PHISH_EML = """\
Return-Path: <bounce@paypa1-login.com>
Delivered-To: me.victim@gmail.com
Received: from mail.paypa1-login.com (mail.paypa1-login.com [45.33.32.156])
        by mx.google.com with ESMTPS id x1; Mon, 23 Nov 2026 08:00:00 +0000
From: "PayPal Security" <alerts@paypa1-login.com>
To: undisclosed-recipients:;
Subject: Your account is limited
Date: Mon, 23 Nov 2026 08:00:00 +0000
Message-ID: <1@paypa1-login.com>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="b1"

--b1
Content-Type: text/html; charset=utf-8

<p>Dear customer, <a href="https://paypa1-login.com/login">sign in</a> or
<a href="https://paypa1-login.com/verify?u=me.victim%40gmail.com">verify</a>.</p>
--b1
Content-Type: application/pdf; name="invoice.pdf"
Content-Disposition: attachment; filename="invoice.pdf"
Content-Transfer-Encoding: base64

JVBERi0xLjQKJSBmYWtlIFBERgo=
--b1--
"""


@pytest.fixture
def phish_email(tmp_path) -> Path:
    """A harmless phishing-style email whose names are not reserved, so they are looked up.

    paypa1-login.com, 45.33.32.156 and the attachment are only ever sent to the fake APIs
    below: the network guard stops anything else. The victim's address is in Delivered-To
    and inside one link, so tests can check that it is never sent.
    """
    path = tmp_path / "phish.eml"
    path.write_text(PHISH_EML, encoding="utf-8")
    return path


@pytest.fixture
def fake_apis(respx_mock):
    """Fake VirusTotal, URLhaus, AbuseIPDB, IANA and RDAP answers for phish_email.

    Call it with the domain's registration date; it returns the respx router, so a test
    can read every request that was "sent" (respx_mock.calls).
    """
    import httpx

    def install(created: str, vt_engines: int = 5, iana_status: int = 200):
        def virustotal(request: httpx.Request) -> httpx.Response:
            if "/files/" in request.url.path:
                return httpx.Response(404, json={"error": {"code": "NotFoundError"}})
            stats = {"malicious": vt_engines, "suspicious": 0, "harmless": 60, "undetected": 30}
            body = {"data": {"attributes": {"last_analysis_stats": stats, "reputation": -5}}}
            return httpx.Response(200, json=body)

        respx_mock.get(url__startswith="https://www.virustotal.com/api/v3/").mock(
            side_effect=virustotal
        )
        respx_mock.post("https://urlhaus-api.abuse.ch/v1/url/").respond(
            200,
            json={"query_status": "ok", "url_status": "online", "threat": "malware_download"},
        )
        respx_mock.post("https://urlhaus-api.abuse.ch/v1/host/").respond(
            200, json={"query_status": "no_results"}
        )
        respx_mock.post("https://urlhaus-api.abuse.ch/v1/payload/").respond(
            200, json={"query_status": "no_results"}
        )
        respx_mock.get("https://api.abuseipdb.com/api/v2/check").respond(
            200,
            json={"data": {"abuseConfidenceScore": 90, "totalReports": 30, "numDistinctUsers": 12}},
        )
        respx_mock.get("https://data.iana.org/rdap/dns.json").respond(
            iana_status, json={"services": [[["com"], ["https://rdap.verisign.com/com/v1/"]]]}
        )
        respx_mock.get("https://rdap.verisign.com/com/v1/domain/paypa1-login.com").respond(
            200, json={"events": [{"eventAction": "registration", "eventDate": created}]}
        )
        return respx_mock

    return install
