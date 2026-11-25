"""Week 3, step 1: prove that the tests cannot reach the network (see conftest.py).

These tests are the safety net for the whole week: if any of them fails, a later test
could call a real API, use up quota or send a value to a third party.
"""

import socket

import httpx
import pytest

BLOCKED = "must not use the network"


def test_a_raw_connection_is_blocked():
    # 192.0.2.1 is a documentation address (RFC 5737): even if the guard failed, nothing
    # real would answer, and the 1-second timeout stops the test from hanging
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1)
        with pytest.raises(RuntimeError, match=BLOCKED):
            sock.connect(("192.0.2.1", 443))


def test_a_dns_lookup_is_blocked():
    with pytest.raises(RuntimeError, match=BLOCKED):
        socket.getaddrinfo("example.org", 443)


def test_a_real_httpx_request_is_blocked():
    # The error comes from the guard, not from a timeout or a missing network
    with pytest.raises(RuntimeError, match=BLOCKED):
        httpx.get("https://example.org/", timeout=1)


def test_a_faked_reply_still_works(respx_mock):
    """respx answers inside httpx before any socket is opened, so the guard allows it.

    respx_mock is a pytest fixture that comes with respx (Java: like WireMock or OkHttp's
    MockWebServer, but nothing listens on a port). Any request without a matching route
    fails, so a forgotten fake cannot fall through to the real Internet either.
    """
    respx_mock.get("https://api.example.test/ping").respond(200, json={"ok": True})

    response = httpx.get("https://api.example.test/ping")

    assert response.json() == {"ok": True}


@pytest.mark.skipif(not hasattr(socket, "AF_UNIX"), reason="no Unix sockets on this system")
def test_local_unix_sockets_are_still_allowed():
    # A Unix socket is a file on this machine, so the guard lets it through: connecting to
    # one that does not exist fails with an ordinary OSError, not with the guard's error
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        with pytest.raises(OSError):
            sock.connect("/tmp/phishtriage-test-no-such.sock")
