"""Week 3, step 3: your address never leaves the machine, in any of its forms."""

import base64
import hashlib
from pathlib import Path

import pytest

from phishtriage.models import ParsedEmail
from phishtriage.privacy import (
    REDACTED,
    AddressRedactor,
    addresses_to_hide,
    without_fragment,
)

ME = "me.victim@example.org"
redactor = AddressRedactor([ME])


def b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def hexdigest(name: str, text: str) -> str:
    return hashlib.new(name, text.encode()).hexdigest()


def assert_removed(url: str, forms: tuple[str, ...]) -> None:
    result = redactor.redact(url)
    assert result.changed
    assert result.forms == forms
    assert REDACTED in result.value
    assert not redactor.contains(result.value)  # nothing of the address is left


# --- plain and percent-encoded ---------------------------------------------------------


@pytest.mark.parametrize(
    ("url", "form"),
    [
        # Google's "Check activity" link (a Week 2 limitation)
        (f"https://accounts.google.com/AccountChooser?Email={ME}", "plain"),
        ("https://accounts.google.com/AccountChooser?Email=Me.Victim@Example.ORG", "plain"),
        # The "user@host" trick: the address is the part before the last "@"
        (f"https://{ME}@evil.test/login", "plain"),
        # AliExpress order tracking (a Week 2 limitation)
        ("https://www.aliexpress.com/p/track?to_address=me.victim%40example.org",
         "percent-encoded"),
        # Encoded twice, as in a link inside a link: %25 is "%" itself
        ("https://t.shop.test/c?u=https%253A%252F%252Fx.test%252F%253Fe%253D"
         "me.victim%2540example.org", "percent-encoded"),
        # Every character encoded, in capitals
        ("https://t.shop.test/?e=" + "".join(f"%{ord(c):02X}" for c in ME), "percent-encoded"),
    ],
)  # fmt: skip
def test_plain_and_percent_encoded_addresses_are_removed(url, form):
    assert_removed(url, (form,))


def test_a_plus_tag_address_percent_encoded():
    tagged = AddressRedactor(["me.victim+news@example.org"])
    result = tagged.redact("https://x.test/?e=me.victim%2Bnews%40example.org")
    assert result.forms == ("percent-encoded",)
    assert result.value == f"https://x.test/?e={REDACTED}"


# --- base64 ----------------------------------------------------------------------------


def test_base64_with_and_without_padding():
    # ME is 21 bytes, a multiple of 3, so its base64 has no "=" at all; one more
    # character after it makes the encoder add padding
    assert not b64(ME).endswith("=")
    assert_removed(f"https://login.evil.test/#{b64(ME)}", ("base64",))
    padded = b64(ME + "?")
    assert padded.endswith("=")
    assert_removed(f"https://login.evil.test/#{padded}", ("base64",))
    assert_removed(f"https://login.evil.test/?id={padded.rstrip('=')}", ("base64",))


@pytest.mark.parametrize("prefix", ['{"email":"', '{"e":"', '{"mail":"'])
def test_base64_inside_encoded_json_at_every_offset(prefix):
    # The three prefixes put the address at byte 1, 2 and 0 of a group of 3: each one
    # changes how the address itself is written in base64
    blob = b64(prefix + ME + '","id":7}')
    assert_removed(f"https://t.shop.test/open?data={blob}", ("base64",))


def test_url_safe_base64_and_percent_encoded_base64():
    odd = AddressRedactor(["me?victim@example.org"])  # its base64 contains a "/"
    standard = b64("me?victim@example.org")
    assert "/" in standard
    url_safe = standard.replace("/", "_").rstrip("=")
    assert odd.redact(f"https://x.test/?e={url_safe}").forms == ("base64",)
    encoded = standard.replace("/", "%2F").replace("=", "%3D")
    assert odd.redact(f"https://x.test/?e={encoded}").forms == ("base64",)


# --- hex --------------------------------------------------------------------------------


def test_hex_of_the_address_is_removed():
    hexed = ME.encode().hex()
    assert_removed(f"https://t.shop.test/open?e={hexed}", ("hex",))
    assert_removed(f"https://t.shop.test/open?e={hexed.upper()}", ("hex",))
    assert_removed(f"https://{hexed}.track-mail.test/pixel.gif", ("hex",))  # in a host name


# --- hashes ----------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["md5", "sha1", "sha256"])
def test_hash_of_the_address_is_removed(name):
    digest = hexdigest(name, ME)
    assert_removed(f"https://t.shop.test/open?eh={digest}", (name,))
    assert_removed(f"https://t.shop.test/open?eh={digest.upper()}", (name,))


# --- several forms, several addresses, nothing else touched ------------------------------


def test_every_form_in_one_url():
    url = (
        f"https://t.shop.test/c?a={ME}&b=me.victim%40example.org&c={b64(ME)}"
        f"&d={hexdigest('md5', ME)}&e={hexdigest('sha1', ME)}&f={hexdigest('sha256', ME)}"
    )
    assert_removed(url, ("plain", "percent-encoded", "base64", "md5", "sha1", "sha256"))


def test_several_addresses():
    two = AddressRedactor([ME, "Colleague@Example.org", "not an address"])
    assert two.addresses == ["colleague@example.org", ME]  # cleaned, sorted, junk dropped
    result = two.redact(f"https://x.test/?to={ME}&cc=colleague%40example.org")
    assert result.value == f"https://x.test/?to={REDACTED}&cc={REDACTED}"
    assert result.forms == ("percent-encoded", "plain")  # in the order the patterns ran


def test_other_addresses_and_tokens_are_left_alone():
    for url in (
        "https://x.test/?e=me.victim2@example.org",  # a different address
        "https://x.test/?e=other@example.org",
        f"https://x.test/?token={b64('something else entirely')}",
        f"https://x.test/?eh={hexdigest('md5', 'other@example.org')}",
        "https://x.test/?e=me.victim@example.com",  # same name, other domain
    ):
        assert not redactor.contains(url), url
        assert redactor.redact(url).value == url
        assert redactor.redact(url).changed is False


def test_no_addresses_changes_nothing():
    empty = AddressRedactor([])
    assert empty.contains(f"https://x.test/?e={ME}") is False
    assert empty.redact(f"https://x.test/?e={ME}").forms == ()


# --- which addresses, and the fragment ---------------------------------------------------


def test_addresses_to_hide_covers_config_recipients_and_forwarded_emails():
    inner = ParsedEmail(path=Path("inner.eml"), recipients=["nimal@example.org"])
    outer = ParsedEmail(
        path=Path("outer.eml"),
        to=["soc@example.org"],
        recipients=["soc@example.org", "Delivered@Example.org"],
        forwarded=[inner],
    )
    hidden = addresses_to_hide(outer, configured=[" Me.Victim@Example.org ", "", "junk"])
    assert hidden == {ME, "soc@example.org", "delivered@example.org", "nimal@example.org"}


def test_without_fragment():
    assert without_fragment(f"https://login.evil.test/verify#{ME}") == (
        "https://login.evil.test/verify"
    )
    assert without_fragment("https://x.test/a?b=1") == "https://x.test/a?b=1"
    assert without_fragment("https://x.test/#a#b") == "https://x.test/"
