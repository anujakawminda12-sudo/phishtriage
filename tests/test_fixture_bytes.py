"""The hand-built test emails stay byte for byte the same (GitHub phase, step 3).

Git can change a file's line endings when it stores or checks out a file. .gitattributes
tells git never to touch *.eml, and these tests prove that it did not: every fixture's
SHA-256 is pinned. Java comparison: like checking the digest of a test resource before
trusting what the tests built on it say.

Why it matters: broken_charset.eml is the only fixture with CRLF line endings, the way
email travels between mail servers. Without `*.eml -text`, git would quietly store it
with LF instead, and all the other tests would still pass.

Changing a fixture on purpose is a decision: update its number here in the same step.
"""

import hashlib

import pytest
from conftest import FIXTURES

FIXTURE_SHA256 = {
    "attachments_phish.eml": "e51da072002cf9217908ed663a8a8ac86ae476c9572a443fea318fcce4365b52",
    "broken_charset.eml": "e7b9c946d428226e63eb551b43cfeced196fe230c48c4b1c3a88f89dff5ef571",
    "forwarded_phish.eml": "40ee4eb3b16d0eaa4f60eaab5f9915ba3c44a1d53485828dc7942fc51237dea4",
    "legit_newsletter.eml": "5d4537f12b26752a976e9b102a22f3029912edd11ba8020197f6931b59b4ab49",
    "phish_microsoft_format.eml": (
        "b5f0f70d154220f976c9d17dba5034a457c873a289509a64313de67b75f5d422"
    ),
    "phish_open_redirect.eml": "722a2c2dd0d9d8310ce0af13cbe253cc5f55bea84e4826cd544337e5311be757",
    "phish_paypal_spoof.eml": "f592f6f0c9da22f3622f08bcd857810d8116e01e7cae917a99f4fdaa76a85fb6",
    "wrapped_links.eml": "9837effa2d09d2f44f80c055c482ff5d5998b920828fd750fda77dcefa5b548d",
}


def test_every_fixture_is_pinned():
    """A new fixture must be added to FIXTURE_SHA256 too, so none escapes the check."""
    assert {path.name for path in FIXTURES.glob("*.eml")} == set(FIXTURE_SHA256)


@pytest.mark.parametrize("name", sorted(FIXTURE_SHA256))
def test_the_fixture_bytes_are_unchanged(name):
    digest = hashlib.sha256((FIXTURES / name).read_bytes()).hexdigest()
    assert digest == FIXTURE_SHA256[name]


def test_broken_charset_keeps_its_crlf_line_endings():
    """Says plainly what a changed hash above would only hint at."""
    data = (FIXTURES / "broken_charset.eml").read_bytes()
    assert data.count(b"\r\n") == data.count(b"\n") == 6
