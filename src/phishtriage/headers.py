"""Header and authentication checks.

Done for you:   get_domain, org_domain, parse_auth_results, run_header_checks, VIA_RE
Your week 1:    check_reply_to_mismatch, check_return_path_mismatch, check_display_name_spoof
Your week 2:    step 1: the three sender checks compare registered domains (org_domain)
                step 2: mentions_brand and sent_via_platform, used by check_display_name_spoof
Week 3:         step 2: check_multiple_from
Week 4:         step 2: parse_auth_results reads Microsoft's format (no server name first),
                keeps every DKIM signature with its own result, and reads compauth=
                step 3: the sender IP (AuthResults.sender_ip), check_dkim_missing and
                check_dkim_alignment
"""

from __future__ import annotations

import ipaddress
import re
from typing import NamedTuple

from .domains import registered_domain
from .models import AuthResults, DkimSignature, Finding, ParsedEmail

# Brand names an attacker might put in a display name, and the domains that brand really
# sends from. Extend this list as you meet new brands in your samples.
# List registered domains only (paypal.com, not mail.paypal.com): the check compares the
# sender's registered domain with these.
BRAND_DOMAINS: dict[str, tuple[str, ...]] = {
    "paypal": ("paypal.com",),
    "microsoft": ("microsoft.com", "office.com", "outlook.com"),
    "apple": ("apple.com", "icloud.com"),
    "amazon": ("amazon.com",),
    "google": ("google.com",),
    "netflix": ("netflix.com",),
    "dhl": ("dhl.com",),
    "docusign": ("docusign.com", "docusign.net"),
}

# Platforms that send email on behalf of their users or advertisers, with a display name
# such as "Google Cloud via LinkedIn" or "Alice Perera (via Google Drive)".
# Key: the platform name as it appears after "via", lower-case.
# Value: the registered domains that platform really sends from.
PLATFORM_DOMAINS: dict[str, tuple[str, ...]] = {
    "linkedin": ("linkedin.com",),
    "google drive": ("google.com",),
    "google docs": ("google.com",),
    "google sheets": ("google.com",),
    "google slides": ("google.com",),
    "docusign": ("docusign.net", "docusign.com"),
    "dropbox": ("dropbox.com",),
}

# "<someone> via <platform>" or "<someone> (via <platform>)". Done for you.
#   (?P<name>...)  is a named group, read back with match["name"]
#                  (Java: matcher.group("name"))
#   .+?            means "as few characters as possible", so "who" stops at the first " via "
#   \(? and \)?    allow optional brackets around "via <platform>"
VIA_RE = re.compile(r"^(?P<who>.+?)\s+\(?via\s+(?P<platform>[^()]+?)\)?$", re.IGNORECASE)

# Results that count as a red flag for each method.
FLAGGED_RESULTS = {
    "spf": {"fail", "softfail"},
    "dkim": {"fail", "none"},
    "dmarc": {"fail"},
}

# One result: "spf=pass", "dkim=none", "compauth=fail" (compauth: Microsoft only)
_RESULT = re.compile(r"^(spf|dkim|dmarc|compauth|iprev)\s*=\s*([a-z]+)", re.IGNORECASE)
# A property and its value. The value may contain "quoted text" ("odd name"@evil.test).
_PROPERTY = re.compile(
    r"\b(header\.from|header\.d|header\.i|smtp\.mailfrom|smtp\.remote-ip|policy\.iprev)"
    r"\s*=\s*((?:\"[^\"]*\"|[^\s\"])+)",
    re.IGNORECASE,
)
# Properties some servers use for the IP address they received the email from (week 4,
# step 3), e.g. "iprev=pass policy.iprev=203.0.113.9" or "smtp.remote-ip=203.0.113.9"
_SENDER_IP_PROPERTIES = ("smtp.remote-ip", "policy.iprev")
# Where the SPF comment names that IP. Each pattern is tied to the start or the end of the
# comment, because the middle can quote the sender's envelope address, which the attacker
# chooses ("designates 8.8.8.8 as permitted sender"@evil.test would fool a free search).
_SPF_COMMENT_IP = (
    # Microsoft: "sender IP is 203.0.113.9" (the whole comment)
    re.compile(r"^sender ip is (?P<ip>\S+)$", re.IGNORECASE),
    # Google pass, fail and softfail: "... designates 203.0.113.9 as permitted sender"
    re.compile(r"\bdesignates? (?P<ip>\S+) as permitted sender$", re.IGNORECASE),
    # Google neutral: "google.com: 203.0.113.9 is neither permitted nor denied by ..."
    re.compile(r"^(?:[\w.-]+:\s*)?(?P<ip>\S+) is neither permitted nor denied\b", re.IGNORECASE),
)
_REASON = re.compile(r"\breason\s*=\s*(\d+)", re.IGNORECASE)  # "compauth=fail reason=001"
# Microsoft writes "header.d=none" when there is no signature: that is not a domain
_NO_DOMAIN = {"", "none"}


def get_domain(address: str) -> str:
    """'alice@Mail.Example.com' or '<alice@x.com>' or '@x.com' -> lower-case domain."""
    _, _, domain = address.rpartition("@")
    return domain.strip(" <>").lower()


def org_domain(address: str) -> str:
    """'bounce@em8448.mail.capcut.com' -> 'capcut.com': the registered domain of an address.

    Two addresses with the same org_domain were sent by the same organisation, even if
    they use different subdomains (mail.capcut.com and em8448.mail.capcut.com).
    """
    return registered_domain(get_domain(address))


def mentions_brand(name: str, brand: str) -> bool:
    """True if `brand` appears in `name` as a whole word. Both are already lower-case.

        mentions_brand("paypal security", "paypal")       -> True
        mentions_brand("paypal-support", "paypal")        -> True
        mentions_brand("microsoft365 team", "microsoft")  -> True   (a digit ends the word)
        mentions_brand("pineapple express", "apple")      -> False  (inside another word)

    Why not the regex word boundary (backslash b)? Python counts digits and "_" as word
    characters, so it would miss "microsoft365" and "paypal_support". Here only letters count.

    How it works: the regex has three parts.
        (?<![a-z])        "not preceded by a letter"   (negative lookbehind)
        re.escape(brand)  the brand itself, with any "." or "+" made safe for a regex
        (?![a-z])         "not followed by a letter"   (negative lookahead)
    For "apple" the pattern is (?<![a-z])apple(?![a-z]). re.search() returns a Match
    object or None, so bool(...) turns it into True or False.
    """
    pattern = rf"(?<![a-z]){re.escape(brand)}(?![a-z])"
    return bool(re.search(pattern, name))


def sent_via_platform(email: ParsedEmail) -> bool:
    """True if the display name says "<someone> via <platform>" AND that platform sent it.

        "Google Cloud via LinkedIn" <newsletters-noreply@linkedin.com>      -> True
        "Alice Perera (via Google Drive)" <drive-shares-dm-noreply@google.com> -> True
        "PayPal via LinkedIn" <alerts@paypa1-secure.test>    -> False (LinkedIn did not send it)
        "PayPal via SecureMail" <alerts@securemail.test>     -> False (unknown platform)
        "PayPal Security" <service@paypal.com>               -> False (no "via")

    How it works:
      1. Try VIA_RE on the display name. No "via" -> not a platform email.
      2. Look up the platform's real domains (lower-case key). An unknown platform gets
         an empty tuple, like map.getOrDefault(key, List.of()) in Java.
      3. True only if the sender's registered domain is one of them. The "via" text is
         written by whoever sent the email, so it is never trusted on its own.
    """
    match = VIA_RE.match(email.from_name.strip())
    if match is None:
        return False
    platform_domains = PLATFORM_DOMAINS.get(match["platform"].lower(), ())
    return org_domain(email.from_addr) in platform_domains


def parse_auth_results(headers: list[str], trusted_ids: tuple[str, ...] = ()) -> AuthResults:
    """Read SPF, DKIM and DMARC from the one Authentication-Results header we trust.

    Each mail server adds its headers to the TOP of an email, so the first
    Authentication-Results header is the one written by your own receiving server.
    Headers further down could have been written by the attacker, so they are
    counted in `ignored_headers` but never used.

    trusted_ids: if given, e.g. ("mx.google.com",), only a header written by one of those
    servers is used. Use this when your samples come from a server that does not add
    its own header, so a forged one cannot end up on top. A header with no server name
    in it (Microsoft's format, below) can never match, so it is never trusted this way.

    Two formats (week 4, step 2):
        mx.google.com; spf=pass ...; dkim=pass ...      RFC 8601: the server's name first
        spf=pass (sender IP is 203.0.113.9) ...; ...    Microsoft: straight to the results
    Week 1 always skipped the first part as the server's name, so Microsoft's SPF result
    was thrown away and "spf=pass" was taken for the name of the server.
    """
    result = AuthResults()
    chosen = None
    for value in headers:
        authserv_id, _ = _split_header(value)
        if not trusted_ids or authserv_id in trusted_ids:
            chosen = value
            break

    if chosen is None:
        result.ignored_headers = len(headers)
        return result

    result.found = True
    result.ignored_headers = len(headers) - 1
    result.authserv_id, clauses = _split_header(chosen)

    ip_from_property = ip_from_comment = ""
    for clause in clauses:
        match = _RESULT.match(clause.text)
        if not match:
            continue
        method, verdict = match.group(1).lower(), match.group(2).lower()
        props = {
            key.lower(): value.replace('"', "").strip("<>").rstrip(".").lower()
            for key, value in _PROPERTY.findall(clause.text)
        }
        for key in _SENDER_IP_PROPERTIES:
            ip_from_property = ip_from_property or _valid_ip(props.get(key, ""))

        if method == "spf":
            result.spf = verdict
            result.smtp_mailfrom = props.get("smtp.mailfrom")
            ip_from_comment = ip_from_comment or _ip_in_spf_comments(clause.comments)
        elif method == "dkim":
            domain = props.get("header.d") or get_domain(props.get("header.i", ""))
            domain = "" if domain in _NO_DOMAIN else domain
            result.dkim_signatures.append(DkimSignature(verdict, domain))
        elif method == "dmarc":
            result.dmarc = verdict
            result.header_from = props.get("header.from")
        elif method == "compauth":
            result.compauth = verdict
            reason = _REASON.search(clause.text)
            result.compauth_reason = reason.group(1) if reason else ""

    verdicts = [signature.result for signature in result.dkim_signatures]
    if verdicts:  # an email can carry several DKIM signatures; one pass is enough
        result.dkim = "pass" if "pass" in verdicts else verdicts[0]
    # A property is written for machines, so it beats a comment written for people
    result.sender_ip = ip_from_property or ip_from_comment
    return result


def _ip_in_spf_comments(comments: tuple[str, ...]) -> str:
    """The IP address named in an SPF comment, or "" if there is none."""
    for comment in comments:
        for pattern in _SPF_COMMENT_IP:
            if (match := pattern.search(comment)) and (ip := _valid_ip(match["ip"])):
                return ip
    return ""


def _valid_ip(value: str) -> str:
    """'203.0.113.9' -> '203.0.113.9'; '[IPv6:2001:DB8::0:1]' -> '2001:db8::1'; 'x' -> ''.

    ipaddress.ip_address() both checks the value and writes it one standard way, so the
    same address always compares equal (Java: InetAddress.getByName() for literals).
    """
    value = value.strip("[]")
    if value.lower().startswith("ipv6:"):
        value = value[5:]
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return ""


def _split_header(value: str) -> tuple[str | None, list[Clause]]:
    """Split one Authentication-Results header into (server name, result clauses).

        "mx.google.com; spf=pass smtp.mailfrom=a.test; dkim=none"
            -> ("mx.google.com", ["spf=pass smtp.mailfrom=a.test", "dkim=none"])
        "mx.example.org 1; spf=pass ..."        (an optional version number after the name)
            -> ("mx.example.org", ["spf=pass ..."])
        "spf=fail (sender IP is 203.0.113.9) smtp.mailfrom=a.test;dkim=none"   (Microsoft)
            -> (None, ["spf=fail   smtp.mailfrom=a.test", "dkim=none"])
    (The clauses are shown as their text here; each also keeps its comments.)

    A server name never contains "=", so a first part that reads like "spf=..." is a
    result, not a name: that is how Microsoft's format is recognised.
    """
    clauses = lex_clauses(value)
    first = clauses[0].text
    if _RESULT.match(first):
        return None, clauses
    words = first.split()
    return (words[0].lower() if words else ""), clauses[1:]


class Clause(NamedTuple):
    """One ";"-separated part of a header (Java: a record).

    text:     the part without its comments, e.g. "spf=pass   smtp.mailfrom=a.test"
    comments: what the comments in it said, e.g. ("sender IP is 203.0.113.9",)
    """

    text: str
    comments: tuple[str, ...] = ()


def split_clauses(value: str) -> list[str]:
    """Split a header at each ";" and drop every (comment), as RFC 5322 reads them.

        'a; spf=pass (ok; fine) smtp.mailfrom=x.test'  -> ['a', 'spf=pass   smtp.mailfrom=x.test']

    Why not a regular expression (weeks 1-3 used one)? Three rules need a memory of what
    came before, which a regex cannot keep well:
        (a (b) c)    comments can sit inside comments: only the last ")" ends the outer one
        \\)           a backslash makes the next character ordinary, even ")" or "("
        "a;b"        inside quotes (outside a comment), ";" and "(" are just characters

    Why it matters: the SPF comment can quote the sender's envelope address, which the
    attacker chooses. With the old regex, an address with an escaped ")" in it ended the
    comment early, and text after it such as ";dkim=pass header.d=paypal.com;" was read as
    a real result written by your mail server.

    It is a small state machine (Java: a hand-written lexer, one char at a time). A comment
    becomes a space, so the words on each side of it stay apart. An unfinished comment
    or quote runs to the end of the header.
    """
    return [clause.text for clause in lex_clauses(value)]


def lex_clauses(value: str) -> list[Clause]:
    """split_clauses(), keeping what each comment said (week 4, step 3).

    The comments are dropped from the text, so nothing in them can be read as a result,
    but one of them is still useful: in the SPF comment, your mail server writes the IP
    address it received the email from. A comment that is never closed is not kept.
    """
    clauses: list[Clause] = []
    text: list[str] = []  # the clause so far, without comments
    comments: list[str] = []  # the finished comments of this clause
    comment: list[str] = []  # the comment being read
    depth = 0  # how many comments we are inside: 0 means "in the header text"
    quoted = False  # inside "..." in the header text
    escaped = False  # the previous character was a backslash
    for char in value:
        if escaped:
            escaped = False
            (comment if depth else text).append(char)
        elif char == "\\" and (depth or quoted):
            escaped = True
            if not depth:
                text.append(char)  # quoted text keeps its backslashes
        elif depth:
            depth += {"(": 1, ")": -1}.get(char, 0)
            if depth:
                comment.append(char)
            else:  # the outer comment has just ended
                comments.append("".join(comment).strip())
                comment = []
        elif quoted:
            text.append(char)
            quoted = char != '"'
        elif char == '"':
            quoted = True
            text.append(char)
        elif char == "(":
            depth = 1
            text.append(" ")  # a comment separates words like a space
        elif char == ";":
            clauses.append(Clause("".join(text).strip(), tuple(comments)))
            text, comments = [], []
        else:
            text.append(char)
    clauses.append(Clause("".join(text).strip(), tuple(comments)))
    return clauses


# --- Week 4, step 3: DKIM missing, and DKIM not aligned with From ---------------------


def check_dkim_missing(email: ParsedEmail, auth: AuthResults) -> Finding | None:
    """Flag a trusted header that has no DKIM result at all.

    Microsoft writes "dkim=none" for an unsigned email (that is the dkim_none finding).
    Other servers may just leave DKIM out, which week 3 showed as "unknown" with no
    finding. Both mean the same thing: no signature was checked. The proposal's scoring
    row "DKIM fail, missing or not aligned" covers this one.
    No trusted header at all is a different finding (no_auth_results).
    """
    if auth.found and auth.dkim == "unknown":
        return Finding(
            "dkim_missing",
            "The trusted Authentication-Results header has no DKIM result: no signature "
            "was checked",
        )
    return None


def check_dkim_alignment(email: ParsedEmail, auth: AuthResults) -> Finding | None:
    """Flag DKIM that passed, but only for a domain that is not the From organisation.

    A valid signature proves who signed the email, not who wrote the From line. Anyone
    can sign with their own domain (evil.test) and put paypal.com in From. DMARC calls a
    signature "aligned" when the signing domain and the From domain share one
    organisation (relaxed alignment): mail.paypal.com and paypal.com are aligned.

        From paypal.com, DKIM pass for paypal.com              -> None (aligned)
        From paypal.com, DKIM pass for e.paypal.com            -> None (same organisation)
        From paypal.com, DKIM pass for esp.test only           -> Finding
        From paypal.com, DKIM pass for esp.test, fail for paypal.com -> Finding

    Genuine bulk mail is sometimes signed only by its mailing service, so this is weak
    evidence on its own (the proposal gives the whole DKIM row 10 points).
    When DKIM did not pass, dkim_fail, dkim_none or dkim_missing already says so.
    """
    from_org = org_domain(email.from_addr)
    if auth.dkim != "pass" or not from_org:
        return None
    signers = auth.dkim_pass_domains
    if any(registered_domain(domain) == from_org for domain in signers):
        return None
    who = ", ".join(signers) if signers else "a domain the header does not name"
    return Finding("dkim_not_aligned", f"DKIM passed for {who}, not for the From domain {from_org}")


# --- YOUR WEEK 1 TASKS ---------------------------------------------------------------


def check_reply_to_mismatch(email: ParsedEmail) -> Finding | None:
    """Flag an email whose Reply-To organisation differs from its From organisation.

        From service@paypal.com, Reply-To support@paypa1-secure.test  -> Finding
        From service@paypal.com, Reply-To help@support.paypal.com     -> None (same org)
        No Reply-To header                                            -> None

    Week 1 compared exact domains. Week 2 compares registered domains (org_domain), so a
    subdomain of the same organisation no longer counts as a mismatch. Every Reply-To
    address is checked (the gate found "Reply-To: a@x, b@y"): a phisher can put the real
    company first and their own address second, and the reply still goes to both.
    """
    # 1. No Reply-To header at all? Nothing to compare.
    reply_addresses = email.reply_to_all or ([email.reply_to] if email.reply_to else [])
    if not reply_addresses:
        return None

    from_domain = org_domain(email.from_addr)
    for reply_to in reply_addresses:
        # 2. Registered domain of each address (help@support.paypal.com -> paypal.com).
        # 3. Same organisation: nothing suspicious, look at the next address.
        if org_domain(reply_to) == from_domain:
            continue
        # 4. Different organisation: red flag.
        return Finding(
            rule="reply_to_mismatch",
            detail=f"Reply-To {reply_to} differs from From {email.from_addr}",
        )
    return None


def check_return_path_mismatch(email: ParsedEmail) -> Finding | None:
    """Flag an email whose Return-Path (envelope sender) organisation differs from From.

    Same idea as check_reply_to_mismatch. Since week 2, bounce addresses on a subdomain of
    the sender (bounce.linkedin.com for linkedin.com) are fine. Mailing services such as
    emsend3.com are still reported: they are a different organisation, so newsletters
    trigger this legitimately and it gets a low weight in week 4.
    """
    # 1. No Return-Path header at all? Nothing to compare.
    if not email.return_path:
        return None

    # 2. Get the registered domain of each address.
    return_domain = org_domain(email.return_path)
    from_domain = org_domain(email.from_addr)

    # 3. Same organisation: nothing suspicious.
    if return_domain == from_domain:
        return None

    # 4. Different domain: red flag.
    return Finding(
        rule="return_path_mismatch",
        detail=f"Return-Path {email.return_path} differs from From {email.from_addr}",
    )


def check_display_name_spoof(
    email: ParsedEmail, brands: dict[str, tuple[str, ...]] = BRAND_DOMAINS
) -> Finding | None:
    """Flag a brand name in the display name when the sender is not that brand's domain.

        "PayPal Security" <alerts@paypa1-secure.test>  -> Finding (brand, wrong domain)
        "PayPal" <service@paypal.com>                  -> None    (real domain)
        "PayPal" <service@mail.paypal.com>             -> None    (subdomain of real domain)
        "Alice" <alice@gmail.com>                      -> None    (no brand)

    For each brand in `brands` that appears in the display name as a whole word, the
    sender's registered domain must be one of that brand's domains. Otherwise it is a
    display-name spoof.

        "Google Cloud via LinkedIn" <newsletters-noreply@linkedin.com>  -> None (platform)
        "PayPal via LinkedIn" <alerts@paypa1-secure.test>               -> Finding
        "Pineapple Express" <orders@pineapple-express.test>             -> None (whole words)
    """
    # 0. A genuine platform email ("Google Cloud via LinkedIn" from linkedin.com):
    #    the platform is the sender; the name before "via" is its customer.
    if sent_via_platform(email):
        return None

    # 1. Lower-case the display name so "PayPal" and "paypal" match.
    #    Keep the full sender domain too, for the finding's detail message.
    name = email.from_name.lower()
    domain = get_domain(email.from_addr)

    # 2. Check each brand in the list.
    for brand, real_domains in brands.items():
        # 2a. Brand not in the display name as a whole word? Skip to the next brand.
        if not mentions_brand(name, brand):
            continue

        # 2b. Is the sender's registered domain one of the brand's real domains?
        #     mail.paypal.com -> paypal.com (fine); evilpaypal.com stays evilpaypal.com.
        if org_domain(email.from_addr) in real_domains:
            return None  # genuine sender

        # 2c. Brand in the name, but the domain isn't theirs: red flag.
        return Finding(
            rule="display_name_spoof",
            detail=f'Display name "{email.from_name}" claims {brand}, but sender is {domain}',
        )

    # 3. No brand in the display name at all.
    return None


# --- WEEK 3 --------------------------------------------------------------------------


def check_multiple_from(email: ParsedEmail) -> Finding | None:
    """Flag a From header that holds more than one address.

        From: "PayPal Security" <alerts@paypa1-secure.test>, other@else.test  -> Finding
        From: "PayPal" <service@paypal.com>                                    -> None

    RFC 5322 allows several From addresses (with a Sender header), but real senders almost
    never do it, and mail apps usually show only the first. Before week 3 the parser read
    such a header as having no address at all: the display-name check then saw an empty
    name and missed the spoof above, and the Reply-To and Return-Path checks compared
    against a blank From. Now the first address is used for every check, and this finding
    names the rest.
    """
    if len(email.from_all) < 2:
        return None
    others = ", ".join(email.from_all[1:])
    return Finding(
        rule="multiple_from_addresses",
        detail=(
            f"From has {len(email.from_all)} addresses: the checks use the first, "
            f"{email.from_all[0]}; also listed: {others}"
        ),
    )


# --- runs everything -----------------------------------------------------------------

SENDER_CHECKS = (
    check_reply_to_mismatch,
    check_return_path_mismatch,
    check_display_name_spoof,
    check_multiple_from,
)


def run_header_checks(email: ParsedEmail) -> tuple[AuthResults, list[Finding], list[str]]:
    """Run every header check. Returns (auth results, findings, names of checks not written yet)."""
    findings: list[Finding] = []
    not_written: list[str] = []

    auth = parse_auth_results(email.auth_results_headers)
    if auth.found:
        for method, flagged in FLAGGED_RESULTS.items():
            verdict = getattr(auth, method)
            if verdict in flagged:
                detail = f"{method.upper()} result: {verdict}"
                findings.append(Finding(f"{method}_{verdict}", detail))
        for auth_check in (check_dkim_missing, check_dkim_alignment):
            if finding := auth_check(email, auth):
                findings.append(finding)
    else:
        detail = "No trusted Authentication-Results header: SPF/DKIM/DMARC unknown"
        findings.append(Finding("no_auth_results", detail))
    if auth.ignored_headers:
        findings.append(
            Finding(
                "extra_auth_results",
                f"{auth.ignored_headers} more Authentication-Results header(s) lower down were "
                "ignored (normal after forwarding, suspicious otherwise)",
            )
        )

    for check in SENDER_CHECKS:
        try:
            finding = check(email)
        except NotImplementedError:
            not_written.append(check.__name__)
            continue
        if finding:
            findings.append(finding)

    return auth, findings, not_written
