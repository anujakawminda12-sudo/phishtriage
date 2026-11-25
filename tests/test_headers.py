from pathlib import Path

import pytest

from phishtriage.headers import (
    Clause,
    check_display_name_spoof,
    check_dkim_alignment,
    check_dkim_missing,
    check_multiple_from,
    check_reply_to_mismatch,
    check_return_path_mismatch,
    get_domain,
    lex_clauses,
    mentions_brand,
    org_domain,
    parse_auth_results,
    run_header_checks,
    sent_via_platform,
    split_clauses,
)
from phishtriage.models import DkimSignature, ParsedEmail
from phishtriage.parser import parse_eml

# A test marked @todo is expected to fail with NotImplementedError until you write the
# function. Once your code makes it pass, pytest reports XPASS(strict) as a failure:
# that is your signal to delete the @todo line above that test.
todo = pytest.mark.xfail(
    raises=NotImplementedError,
    strict=True,
    reason="TODO: write the function, then delete this @todo marker",
)

# A test marked @upgrade checks new behaviour for a function that already works.
# The old code runs and gives the old answer, so the test fails with an AssertionError
# (not NotImplementedError). Same signal as @todo: XPASS(strict) means delete the marker.
upgrade = pytest.mark.xfail(
    strict=True,
    reason="Week 2 upgrade: change the check as its TODO (week 2) note says, then delete @upgrade",
)


def make_email(**fields) -> ParsedEmail:
    """A hand-built email for unit tests: only the fields a check needs."""
    return ParsedEmail(path=Path("test.eml"), **fields)


# --- done for you: these should pass straight away -----------------------------------


def test_get_domain():
    assert get_domain("alice@Mail.Example.com") == "mail.example.com"
    assert get_domain("<bob@example.org>") == "example.org"
    assert get_domain("@example.net") == "example.net"
    assert get_domain("") == ""


def test_auth_results_phish_uses_top_header_only(fixtures):
    email = parse_eml(fixtures / "phish_paypal_spoof.eml")
    auth = parse_auth_results(email.auth_results_headers)
    assert auth.found
    assert auth.authserv_id == "mx.google.com"
    assert auth.spf == "softfail"
    assert auth.dkim == "none"
    assert auth.dmarc == "fail"
    assert auth.header_from == "paypal.com"
    assert auth.smtp_mailfrom == "bounce@mailer-7731.test"
    assert auth.ignored_headers == 1  # the forged "all pass" header lower down


def test_auth_results_legit(fixtures):
    auth = parse_auth_results(parse_eml(fixtures / "legit_newsletter.eml").auth_results_headers)
    assert (auth.spf, auth.dkim, auth.dmarc) == ("pass", "pass", "pass")
    assert auth.dkim_domains == ["example.com"]


def test_auth_results_trusted_ids_skips_forged_header_on_top():
    forged = "evil.test; spf=pass smtp.mailfrom=paypal.com; dmarc=pass header.from=paypal.com"
    real = "mx.google.com; spf=fail smtp.mailfrom=x@evil.test; dmarc=fail header.from=paypal.com"
    auth = parse_auth_results([forged, real], trusted_ids=("mx.google.com",))
    assert auth.authserv_id == "mx.google.com"
    assert auth.spf == "fail"
    assert auth.dmarc == "fail"


def test_auth_results_missing():
    auth = parse_auth_results([])
    assert not auth.found
    assert auth.spf == auth.dkim == auth.dmarc == "unknown"


def test_run_header_checks_flags_auth_failures(fixtures):
    _, findings, _ = run_header_checks(parse_eml(fixtures / "phish_paypal_spoof.eml"))
    rules = {f.rule for f in findings}
    assert {"spf_softfail", "dkim_none", "dmarc_fail", "extra_auth_results"} <= rules


def test_run_header_checks_clean_on_legit(fixtures):
    _, findings, _ = run_header_checks(parse_eml(fixtures / "legit_newsletter.eml"))
    assert findings == []


# --- Week 1 sender checks ------------------------------------------------------------


def test_reply_to_mismatch_flagged():
    email = make_email(from_addr="service@paypal.com", reply_to="support@paypa1-secure.test")
    finding = check_reply_to_mismatch(email)
    assert finding is not None
    assert finding.rule == "reply_to_mismatch"


def test_reply_to_same_domain_or_missing_is_fine():
    assert check_reply_to_mismatch(make_email(from_addr="a@example.com", reply_to="")) is None
    same = make_email(from_addr="a@example.com", reply_to="help@example.com")
    assert check_reply_to_mismatch(same) is None


def test_return_path_mismatch_flagged():
    email = make_email(from_addr="service@paypal.com", return_path="bounce@mailer-7731.test")
    finding = check_return_path_mismatch(email)
    assert finding is not None
    assert finding.rule == "return_path_mismatch"


def test_return_path_same_domain_is_fine():
    email = make_email(from_addr="news@example.com", return_path="bounce@example.com")
    assert check_return_path_mismatch(email) is None


def test_display_name_spoof_flagged():
    email = make_email(from_name="PayPal Security", from_addr="alerts@paypa1-secure.test")
    finding = check_display_name_spoof(email)
    assert finding is not None
    assert finding.rule == "display_name_spoof"


def test_display_name_real_brand_domain_is_fine():
    real = make_email(from_name="PayPal", from_addr="service@paypal.com")
    sub = make_email(from_name="PayPal", from_addr="service@mail.paypal.com")
    person = make_email(from_name="Alice", from_addr="alice@gmail.com")
    assert check_display_name_spoof(real) is None
    assert check_display_name_spoof(sub) is None
    assert check_display_name_spoof(person) is None


def test_display_name_brand_inside_lookalike_domain_is_flagged():
    # "paypal" appears in the domain, but it is not paypal.com or a subdomain of it
    email = make_email(from_name="PayPal", from_addr="alerts@paypal-secure-login.test")
    assert check_display_name_spoof(email) is not None


# --- Week 2 step 1: compare registered domains, not exact domains --------------------


def test_org_domain():
    assert org_domain("bounce@em8448.mail.capcut.com") == "capcut.com"
    assert org_domain("Alice <alice@Mail.Example.co.uk>") == "example.co.uk"
    assert org_domain("") == ""


def test_return_path_subdomain_of_same_org_is_fine():
    # Two of the week 1 false positives from the real samples
    linkedin = make_email(
        from_addr="newsletters-noreply@linkedin.com", return_path="s-2ri3t@bounce.linkedin.com"
    )
    lumosity = make_email(
        from_addr="newsletter@notifications.lumosity.com",
        return_path="postmaster@cio141988.notifications.lumosity.com",
    )
    assert check_return_path_mismatch(linkedin) is None
    assert check_return_path_mismatch(lumosity) is None


def test_return_path_different_org_still_flagged():
    # A mailing service is a different organisation, so this one stays (low weight in week 4)
    email = make_email(from_addr="learn@eccouncil.org", return_path="bounce-113@d33c.emsend3.com")
    assert check_return_path_mismatch(email) is not None


def test_reply_to_subdomain_is_fine():
    email = make_email(from_addr="service@paypal.com", reply_to="help@support.paypal.com")
    assert check_reply_to_mismatch(email) is None


def test_reply_to_lookalike_on_same_suffix_is_flagged():
    # "Compare the last two labels" would see co.uk == co.uk and miss this.
    # The Public Suffix List knows co.uk is one suffix, so the owners differ.
    email = make_email(from_addr="billing@acme.co.uk", reply_to="billing@acme-invoices.co.uk")
    assert check_reply_to_mismatch(email) is not None


def test_display_name_brand_domain_as_attacker_subdomain_is_flagged():
    # Classic trick: the real brand domain used as a subdomain of the attacker's domain
    email = make_email(from_name="PayPal", from_addr="service@paypal.com.secure-login.test")
    assert check_display_name_spoof(email) is not None


# --- Week 2 step 2: whole-word brands and "via" platforms ----------------------------


def test_mentions_brand_whole_words_only():
    assert mentions_brand("paypal security", "paypal")
    assert mentions_brand("paypal-support", "paypal")
    assert mentions_brand("paypal_support", "paypal")
    assert mentions_brand("microsoft365 team", "microsoft")
    assert not mentions_brand("pineapple express", "apple")
    assert not mentions_brand("snapple", "apple")
    assert not mentions_brand("alice", "paypal")


def test_sent_via_platform():
    linkedin = make_email(
        from_name="Google Cloud via LinkedIn", from_addr="newsletters-noreply@linkedin.com"
    )
    drive = make_email(
        from_name="Alice Perera (via Google Drive)",
        from_addr="drive-shares-dm-noreply@google.com",
    )
    fake = make_email(from_name="PayPal via LinkedIn", from_addr="alerts@paypa1-secure.test")
    unknown = make_email(from_name="PayPal via SecureMail", from_addr="alerts@securemail.test")
    plain = make_email(from_name="PayPal Security", from_addr="service@paypal.com")
    assert sent_via_platform(linkedin)
    assert sent_via_platform(drive)
    assert not sent_via_platform(fake)
    assert not sent_via_platform(unknown)
    assert not sent_via_platform(plain)


def test_display_name_brand_inside_another_word_is_fine():
    email = make_email(from_name="Pineapple Express", from_addr="orders@pineapple-express.test")
    assert check_display_name_spoof(email) is None


def test_display_name_via_real_platform_is_fine():
    # The week 1 false positive from the real samples
    email = make_email(
        from_name="Google Cloud via LinkedIn", from_addr="newsletters-noreply@linkedin.com"
    )
    assert check_display_name_spoof(email) is None


def test_display_name_via_fake_platform_is_flagged():
    # Says "via LinkedIn" but LinkedIn did not send it, so the brand check still runs
    email = make_email(from_name="PayPal via LinkedIn", from_addr="alerts@paypa1-secure.test")
    finding = check_display_name_spoof(email)
    assert finding is not None
    assert "paypal" in finding.detail


def test_display_name_brand_followed_by_digits_is_flagged():
    # Guards against using \b: "microsoft365" must still count as "microsoft"
    email = make_email(from_name="Microsoft365 Support", from_addr="it@m365-support.test")
    assert check_display_name_spoof(email) is not None


# --- Week 2 step 3: checks run on a forwarded email on its own ------------------------


def test_header_checks_on_forwarded_email(fixtures):
    outer = parse_eml(fixtures / "forwarded_phish.eml")
    _, outer_findings, _ = run_header_checks(outer)
    auth, inner_findings, _ = run_header_checks(outer.forwarded[0])

    # Nimal's own forward is clean
    assert outer_findings == []
    # The phish inside passes SPF/DKIM/DMARC (the attacker owns micros0ft-support.test),
    # so only the sender checks catch it
    assert (auth.spf, auth.dkim, auth.dmarc) == ("pass", "pass", "pass")
    rules = {f.rule for f in inner_findings}
    assert rules == {"display_name_spoof", "return_path_mismatch"}


def test_reply_to_mismatch_checks_every_reply_to_address():
    # the real company first, the phisher second: a reply still goes to both
    email = make_email(
        from_addr="service@paypal.com",
        reply_to="service@paypal.com",
        reply_to_all=["service@paypal.com", "refunds@paypa1-help.test"],
    )
    finding = check_reply_to_mismatch(email)
    assert finding is not None
    assert "refunds@paypa1-help.test" in finding.detail
    same_org = make_email(
        from_addr="hello@secops.group",
        reply_to_all=["hello@secops.group", "cert@secops.group"],
    )
    assert check_reply_to_mismatch(same_org) is None


# --- Week 3 step 2: a From header with several addresses ------------------------------


def test_multiple_from_addresses_flagged():
    email = make_email(
        from_addr="service@paypal.com", from_all=["service@paypal.com", "attacker@evil.test"]
    )
    finding = check_multiple_from(email)
    assert finding is not None
    assert finding.rule == "multiple_from_addresses"
    assert "the checks use the first, service@paypal.com" in finding.detail
    assert "attacker@evil.test" in finding.detail


def test_single_from_address_is_fine():
    assert check_multiple_from(make_email(from_all=["service@paypal.com"])) is None
    assert check_multiple_from(make_email()) is None  # no From at all: nothing to compare


def test_second_from_address_no_longer_hides_a_display_name_spoof(tmp_path):
    # Week 2 read no From address here: the spoof was missed, and Reply-To and Return-Path
    # (both the same organisation as the real sender) were wrongly flagged against a blank
    path = tmp_path / "two_from.eml"
    path.write_text(
        'From: "PayPal Security" <alerts@paypa1-secure.test>, other@else.test\n'
        "Reply-To: help@paypa1-secure.test\nReturn-Path: <bounce@paypa1-secure.test>\n"
        "Subject: Verify\n\nhello\n",
        encoding="utf-8",
    )
    _, findings, _ = run_header_checks(parse_eml(path))
    rules = {finding.rule for finding in findings}
    assert rules == {"no_auth_results", "display_name_spoof", "multiple_from_addresses"}


# --- Week 4, step 2: Microsoft's format, every DKIM signature, compauth ------------------

# Microsoft's servers start the header with the first result: there is no server name.
# Shape from Microsoft's documentation; names and IP changed to test values.
MICROSOFT_PHISH = (
    "spf=softfail (sender IP is 203.0.113.77) smtp.mailfrom=micros0ft-account.test; "
    "dkim=none (message not signed) header.d=none;dmarc=fail action=none "
    "header.from=micros0ft-account.test;compauth=fail reason=001"
)
MICROSOFT_PASS = (
    "spf=pass (sender IP is 198.51.100.20) smtp.mailfrom=news.shop.test; "
    "dkim=pass (signature was verified) header.d=shop.test;dmarc=pass action=none "
    "header.from=shop.test;compauth=pass reason=100"
)


def test_microsoft_format_keeps_the_spf_result():
    """Week 1-3 skipped the first part as a server name, losing "spf=softfail"."""
    auth = parse_auth_results([MICROSOFT_PHISH])
    assert auth.found
    assert auth.authserv_id is None  # not "spf=softfail"
    assert auth.spf == "softfail"
    assert auth.smtp_mailfrom == "micros0ft-account.test"
    assert auth.dkim == "none"
    assert auth.dmarc == "fail"
    assert auth.header_from == "micros0ft-account.test"


def test_microsoft_header_d_none_is_not_a_domain():
    auth = parse_auth_results([MICROSOFT_PHISH])
    assert auth.dkim_signatures == [DkimSignature("none", "")]
    assert auth.dkim_domains == []  # week 3 gave ["none"]
    assert auth.dkim_pass_domains == []


def test_microsoft_compauth_is_read():
    phish = parse_auth_results([MICROSOFT_PHISH])
    assert (phish.compauth, phish.compauth_reason) == ("fail", "001")
    passed = parse_auth_results([MICROSOFT_PASS])
    assert (passed.compauth, passed.compauth_reason) == ("pass", "100")
    assert passed.dkim_pass_domains == ["shop.test"]


def test_compauth_without_a_reason_code():
    auth = parse_auth_results(["spf=pass smtp.mailfrom=a.test; compauth=softpass"])
    assert (auth.compauth, auth.compauth_reason) == ("softpass", "")


def test_compauth_is_unknown_in_other_servers_headers(fixtures):
    auth = parse_auth_results(parse_eml(fixtures / "legit_newsletter.eml").auth_results_headers)
    assert (auth.compauth, auth.compauth_reason) == ("unknown", "")


def test_microsoft_format_through_the_parser(fixtures):
    """The fixture folds the header over 4 lines, as real Outlook mail does."""
    email = parse_eml(fixtures / "phish_microsoft_format.eml")
    auth, findings, _ = run_header_checks(email)
    assert (auth.spf, auth.dkim, auth.dmarc, auth.compauth) == ("softfail", "none", "fail", "fail")
    assert auth.authserv_id is None
    rules = {finding.rule for finding in findings}
    assert {"spf_softfail", "dkim_none", "dmarc_fail", "display_name_spoof"} <= rules
    assert "no_auth_results" not in rules
    assert "extra_auth_results" not in rules


def test_a_header_without_a_server_name_never_matches_trusted_ids():
    """trusted_ids needs a name to compare; Microsoft's header has none, so it is skipped."""
    auth = parse_auth_results([MICROSOFT_PASS], trusted_ids=("mx.google.com",))
    assert not auth.found
    assert auth.ignored_headers == 1


def test_trusted_ids_skips_a_microsoft_style_header_on_top():
    real = "mx.google.com; spf=fail smtp.mailfrom=x@evil.test; dmarc=fail header.from=paypal.com"
    auth = parse_auth_results([MICROSOFT_PASS, real], trusted_ids=("mx.google.com",))
    assert auth.authserv_id == "mx.google.com"
    assert (auth.spf, auth.dmarc) == ("fail", "fail")


def test_every_dkim_signature_is_kept_with_its_own_result():
    header = (
        "mx.google.com; dkim=pass header.i=@esp.test header.s=s1; "
        "dkim=fail (bad signature) header.d=PayPal.com.; dkim=pass header.d=esp.test; "
        "spf=pass smtp.mailfrom=bounce@esp.test; dmarc=fail header.from=paypal.com"
    )
    auth = parse_auth_results([header])
    assert auth.dkim_signatures == [
        DkimSignature("pass", "esp.test"),
        DkimSignature("fail", "paypal.com"),  # lower-case, trailing dot removed
        DkimSignature("pass", "esp.test"),
    ]
    assert auth.dkim == "pass"  # one pass is enough for the overall result, as before
    assert auth.dkim_domains == ["esp.test", "paypal.com", "esp.test"]
    assert auth.dkim_pass_domains == ["esp.test"]  # each once: the From domain did not pass


def test_a_dkim_result_with_no_domain():
    auth = parse_auth_results(["mx.google.com; dkim=none; spf=none"])
    assert auth.dkim_signatures == [DkimSignature("none", "")]
    assert auth.dkim == "none"


@pytest.mark.parametrize(
    ("header", "server", "spf"),
    [
        ("mx.example.org; spf=pass smtp.mailfrom=a.test", "mx.example.org", "pass"),
        ("MX.Example.ORG 1; spf=fail smtp.mailfrom=a.test", "mx.example.org", "fail"),
        ("mx.example.org;spf=softfail smtp.mailfrom=a.test", "mx.example.org", "softfail"),
        ("spf=pass smtp.mailfrom=a.test", None, "pass"),
        ("  SPF = Fail (sender IP is 203.0.113.1) smtp.mailfrom=a.test", None, "fail"),
        ("dmarc=fail header.from=a.test; spf=neutral", None, "neutral"),
        # a ";" inside a comment must not split the clause
        (
            "mx.example.org (filter; v2); spf=pass (ok; really) smtp.mailfrom=a.test",
            "mx.example.org",
            "pass",
        ),
        ("mx.example.org; none", "mx.example.org", "unknown"),  # checked, nothing to say
        ("", "", "unknown"),
    ],
)
def test_server_name_or_none(header, server, spf):
    auth = parse_auth_results([header])
    assert auth.found
    assert auth.authserv_id == server
    assert auth.spf == spf


def test_an_attached_comment_does_not_hide_the_result():
    """Yahoo writes "dmarc=pass(p=REJECT)" with no space before the comment."""
    auth = parse_auth_results(["mta.example.org; dmarc=fail(p=REJECT) header.from=a.test"])
    assert auth.dmarc == "fail"
    assert auth.header_from == "a.test"


# --- Week 4, step 2: comments are read the way RFC 5322 defines them --------------------


@pytest.mark.parametrize(
    ("header", "clauses"),
    [
        ("a; b; c", ["a", "b", "c"]),
        ("a; spf=pass (ok; fine) x=1", ["a", "spf=pass   x=1"]),
        # nested: only the last ")" ends the outer comment
        ("a; spf=pass (one (two; three) four; five) x=1", ["a", "spf=pass   x=1"]),
        # an escaped ")" does not end the comment, an escaped "(" does not open one
        (r"a; spf=pass (x\); dkim=pass) y=1", ["a", "spf=pass   y=1"]),
        (r"a; spf=pass (x\(; dkim=pass) y=1", ["a", "spf=pass   y=1"]),
        # inside quotes, ";" and "(" are ordinary characters
        (
            'a; spf=fail smtp.mailfrom="odd;(name"@x.test',
            ["a", 'spf=fail smtp.mailfrom="odd;(name"@x.test'],
        ),
        (r'a; p="say \"hi;\"" q=1', ["a", r'p="say \"hi;\"" q=1']),
        # quotes inside a comment are not special: the comment still ends at ")"
        ('a; spf=pass (domain of "x) y=1', ["a", "spf=pass   y=1"]),
        # a comment separates words like a space
        ("a; spf=pass(ok)x=1", ["a", "spf=pass x=1"]),
        # unfinished comment or quote: runs to the end of the header
        ("a; spf=pass (never closed; dkim=pass", ["a", "spf=pass"]),
        ('a; p="never closed; dkim=pass', ["a", 'p="never closed; dkim=pass']),
        # a ")" with no "(" before it is just a character
        ("a; x=1) y=2", ["a", "x=1) y=2"]),
        ("", [""]),
    ],
)
def test_split_clauses(header, clauses):
    assert split_clauses(header) == clauses


def test_text_in_a_comment_cannot_add_a_dkim_pass():
    """The attacker chooses the envelope address that Gmail quotes in its SPF comment.

    With the week 1-3 regex, an escaped ")" in it ended the comment early, and
    ";dkim=pass header.d=paypal.com;" was read as a passing PayPal signature.
    """
    header = (
        r"mx.google.com; spf=softfail (google.com: domain of x\);dkim=pass "
        r"header.d=paypal.com;\(@evil.test does not designate 203.0.113.9 as permitted "
        "sender) smtp.mailfrom=evil.test; dkim=none; dmarc=fail header.from=paypal.com"
    )
    auth = parse_auth_results([header])
    assert auth.dkim_signatures == [DkimSignature("none", "")]
    assert auth.dkim == "none"
    assert auth.dkim_pass_domains == []
    assert auth.spf == "softfail"
    assert auth.smtp_mailfrom == "evil.test"


def test_a_nested_comment_keeps_the_rest_of_the_clause():
    header = "mx.example.org; spf=pass (a (nested) comment; still inside) smtp.mailfrom=a.test"
    auth = parse_auth_results([header])
    assert auth.spf == "pass"
    assert auth.smtp_mailfrom == "a.test"  # week 3: None


def test_a_semicolon_in_a_comment_keeps_the_rest_of_the_clause():
    header = "mx.example.org (filter; v2); spf=pass (ok; really) smtp.mailfrom=a.test"
    auth = parse_auth_results([header])
    assert auth.authserv_id == "mx.example.org"
    assert auth.smtp_mailfrom == "a.test"


def test_a_quoted_envelope_address_is_read_whole():
    header = (
        'mx.example.org; spf=fail smtp.mailfrom="odd;name"@Evil.test; dmarc=fail header.from=a.test'
    )
    auth = parse_auth_results([header])
    assert auth.smtp_mailfrom == "odd;name@evil.test"
    assert get_domain(auth.smtp_mailfrom) == "evil.test"
    assert auth.dmarc == "fail"


# --- Week 4, step 3: comments are kept, and the sender IP is read from them -------------


def test_lex_clauses_keeps_each_clauses_comments():
    clauses = lex_clauses(r"mx.example.org (v1); spf=pass (one (two) three) x=1 (a\) b); dkim=none")
    assert clauses == [
        Clause("mx.example.org", ("v1",)),
        Clause("spf=pass   x=1", ("one (two) three", "a) b")),
        Clause("dkim=none", ()),
    ]


def test_lex_clauses_drops_an_unfinished_comment():
    assert lex_clauses("a; spf=pass (sender IP is 203.0.113.9") == [
        Clause("a"),
        Clause("spf=pass"),
    ]


@pytest.mark.parametrize(
    ("header", "sender_ip"),
    [
        # Microsoft: the whole comment
        ("spf=softfail (sender IP is 203.0.113.77) smtp.mailfrom=a.test", "203.0.113.77"),
        ("spf=none (sender IP is 2001:DB8::0:25) smtp.mailfrom=a.test", "2001:db8::25"),
        # Google: pass, softfail and fail end with "... as permitted sender"
        (
            "mx.google.com; spf=pass (google.com: domain of b@a.test designates "
            "198.51.100.4 as permitted sender) smtp.mailfrom=b@a.test",
            "198.51.100.4",
        ),
        (
            "mx.google.com; spf=fail (google.com: domain of b@a.test does not designate "
            "198.51.100.5 as permitted sender) smtp.mailfrom=b@a.test",
            "198.51.100.5",
        ),
        # Google neutral: the IP comes first
        (
            "mx.google.com; spf=neutral (google.com: 198.51.100.6 is neither permitted nor "
            "denied by best guess record for domain of b@a.test) smtp.mailfrom=b@a.test",
            "198.51.100.6",
        ),
        # Google none: no IP in the comment
        (
            "mx.google.com; spf=none (google.com: b@a.test does not designate permitted "
            "sender hosts) smtp.mailfrom=b@a.test",
            "",
        ),
        # properties: iprev, and Fastmail's smtp.remote-ip
        ("mx.example.org; iprev=pass policy.iprev=198.51.100.7; spf=pass", "198.51.100.7"),
        ("mx.example.org; iprev=pass smtp.remote-ip=198.51.100.8; spf=pass", "198.51.100.8"),
        # a property beats a comment
        (
            "mx.example.org; spf=pass (sender IP is 192.0.2.1); iprev=pass policy.iprev=192.0.2.2",
            "192.0.2.2",
        ),
        # written in brackets, as some servers do
        ("mx.example.org; iprev=pass policy.iprev=[IPv6:2001:DB8::9]; spf=pass", "2001:db8::9"),
        ("mx.example.org; iprev=pass smtp.remote-ip=[198.51.100.9]; spf=pass", "198.51.100.9"),
        # not an IP
        ("spf=pass (sender IP is unknown) smtp.mailfrom=a.test", ""),
        ("mx.example.org; iprev=fail policy.iprev=mail.a.test", ""),
        # only the SPF clause's comment counts
        ("mx.example.org; dkim=pass (sender IP is 192.0.2.3) header.d=a.test", ""),
        ("mx.example.org; spf=pass smtp.mailfrom=a.test", ""),
    ],
)
def test_sender_ip_from_the_trusted_header(header, sender_ip):
    assert parse_auth_results([header]).sender_ip == sender_ip


def test_sender_ip_cannot_be_planted_in_the_envelope_address():
    """The attacker chooses the envelope address that Google quotes in the comment."""
    header = (
        'mx.google.com; spf=softfail (google.com: domain of "designates 8.8.8.8 as permitted '
        'sender"@evil.test does not designate 203.0.113.9 as permitted sender) '
        "smtp.mailfrom=evil.test"
    )
    assert parse_auth_results([header]).sender_ip == "203.0.113.9"


def test_sender_ip_comes_only_from_the_trusted_header():
    forged_below = "evil.test; spf=pass (sender IP is 192.0.2.99) smtp.mailfrom=paypal.com"
    real = (
        "mx.google.com; spf=none (google.com: a@b.test does not designate permitted sender hosts)"
    )
    assert parse_auth_results([real, forged_below]).sender_ip == ""


# --- Week 4, step 3: dkim_missing and dkim_not_aligned -----------------------------------


def test_dkim_missing_when_the_trusted_header_has_no_dkim_result():
    auth = parse_auth_results(["mx.google.com; spf=pass smtp.mailfrom=a.test; dmarc=none"])
    finding = check_dkim_missing(make_email(from_addr="x@a.test"), auth)
    assert finding is not None
    assert finding.rule == "dkim_missing"


@pytest.mark.parametrize(
    "headers",
    [
        ["mx.google.com; dkim=none; spf=pass"],  # dkim_none says it already
        ["mx.google.com; dkim=pass header.d=a.test"],
        [],  # no trusted header: no_auth_results says it already
    ],
)
def test_no_dkim_missing_when_dkim_was_reported_or_nothing_was_trusted(headers):
    assert check_dkim_missing(make_email(from_addr="x@a.test"), parse_auth_results(headers)) is None


@pytest.mark.parametrize(
    ("from_addr", "dkim", "aligned"),
    [
        ("service@paypal.com", "dkim=pass header.d=paypal.com", True),
        ("service@paypal.com", "dkim=pass header.d=e.paypal.com", True),  # same organisation
        ("service@mail.paypal.com", "dkim=pass header.i=@paypal.com", True),
        ("service@paypal.com", "dkim=pass header.d=esp.test", False),
        ("service@paypal.com", "dkim=pass header.d=esp.test; dkim=fail header.d=paypal.com", False),
        (
            "service@paypal.com",
            "dkim=fail header.d=paypal.com; dkim=pass header.d=paypal.com",
            True,
        ),
        ("service@paypal.com", "dkim=pass", False),  # passed, but for which domain?
        ("service@paypal.com", "dkim=pass header.d=paypal.com.evil.test", False),
        ("alerts@a.github.io", "dkim=pass header.d=b.github.io", False),  # two different sites
    ],
)
def test_dkim_alignment(from_addr, dkim, aligned):
    auth = parse_auth_results([f"mx.google.com; {dkim}; spf=pass"])
    finding = check_dkim_alignment(make_email(from_addr=from_addr), auth)
    assert (finding is None) is aligned
    if finding:
        assert finding.rule == "dkim_not_aligned"


def test_dkim_not_aligned_names_who_signed():
    auth = parse_auth_results(
        ["mx.google.com; dkim=pass header.d=ESP.test; dkim=pass header.d=b.test"]
    )
    finding = check_dkim_alignment(make_email(from_addr="service@paypal.com"), auth)
    assert finding.detail == "DKIM passed for esp.test, b.test, not for the From domain paypal.com"
    unnamed = check_dkim_alignment(
        make_email(from_addr="service@paypal.com"), parse_auth_results(["mx.google.com; dkim=pass"])
    )
    assert "a domain the header does not name" in unnamed.detail


@pytest.mark.parametrize(
    ("from_addr", "header"),
    [
        ("service@paypal.com", "mx.google.com; dkim=fail header.d=esp.test"),  # dkim_fail
        ("service@paypal.com", "mx.google.com; dkim=none"),  # dkim_none
        ("", "mx.google.com; dkim=pass header.d=esp.test"),  # no From address to compare
    ],
)
def test_no_alignment_finding_when_dkim_did_not_pass_or_there_is_no_from(from_addr, header):
    assert (
        check_dkim_alignment(make_email(from_addr=from_addr), parse_auth_results([header])) is None
    )


def test_run_header_checks_adds_the_dkim_findings_after_the_results(tmp_path):
    path = tmp_path / "esp_signed.eml"
    path.write_text(
        "Authentication-Results: mx.google.com; dkim=pass header.d=esp.test; "
        "spf=softfail smtp.mailfrom=b@esp.test; dmarc=fail header.from=paypal.com\n"
        "From: PayPal <service@paypal.com>\nSubject: Hi\n\nhello\n",
        encoding="utf-8",
    )
    _, findings, _ = run_header_checks(parse_eml(path))
    assert [finding.rule for finding in findings][:3] == [
        "spf_softfail",
        "dmarc_fail",
        "dkim_not_aligned",
    ]
