"""Data classes shared by every PhishTriage module.

Each stage of the pipeline takes one of these objects and returns another, so every
stage can be tested on its own with hand-built inputs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class Attachment:
    """One attachment. Its bytes are hashed and typed: it is never opened or run."""

    filename: str
    content_type: str  # the type the email declares, e.g. "application/pdf"
    size: int
    md5: str
    sha1: str
    sha256: str
    # Week 2 step 8, filled in by attachments.inspect_bytes():
    detected_type: str = ""  # the real type, from the content (libmagic); "" if unknown
    archive_members: list[str] = field(default_factory=list)  # names inside a ZIP
    encrypted: bool = False  # a password-protected ZIP


@dataclass(frozen=True)
class DkimSignature:
    """One dkim= result in the trusted header (Java: a record). Week 4, step 2.

    An email can carry several DKIM signatures, for example one from the company and one
    from its mailing service. Each is kept with its own result, so a later check can ask
    "did a signature from the From domain pass?" instead of "did any signature pass?".
    """

    result: str  # pass, fail, none, neutral, policy, temperror or permerror
    domain: str  # the signing domain (header.d, or the domain of header.i); "" if none given


@dataclass(frozen=True)
class SenderIP:
    """The IP address the email came from: the server that handed it to your mail system.

    address: e.g. "203.0.113.9"
    source:  "Authentication-Results" when your mail server wrote it down (certain), or
             "Received hop N" when it was read from the Received chain (less certain)
    Week 4, step 3. Only this IP counts for the proposal's AbuseIPDB scoring rule.
    """

    address: str
    source: str

    @property
    def certain(self) -> bool:
        return self.source == "Authentication-Results"


@dataclass
class AuthResults:
    """SPF / DKIM / DMARC results read from an Authentication-Results header."""

    spf: str = "unknown"
    dkim: str = "unknown"  # "pass" if any signature passed, else the first result
    dmarc: str = "unknown"
    dkim_signatures: list[DkimSignature] = field(default_factory=list)
    header_from: str | None = None
    smtp_mailfrom: str | None = None
    # The name of the server that wrote the header, e.g. "mx.google.com". None when the
    # header starts straight with a result ("spf=pass ..."), as Microsoft's servers write it.
    authserv_id: str | None = None
    # Microsoft's own "composite authentication" verdict and its reason code (week 4,
    # step 2). Kept as a fact for the report: "unknown" when the header has no compauth=.
    compauth: str = "unknown"
    compauth_reason: str = ""
    # The IP address your mail server says it received the email from (week 4, step 3),
    # from its SPF comment or an iprev property; "" if the header does not say
    sender_ip: str = ""
    found: bool = False  # True if a trusted Authentication-Results header was used
    ignored_headers: int = 0  # other Authentication-Results headers that were not trusted

    @property
    def dkim_domains(self) -> list[str]:
        """Every signing domain, passing or not, in header order (Java: a computed getter)."""
        return [signature.domain for signature in self.dkim_signatures if signature.domain]

    @property
    def dkim_pass_domains(self) -> list[str]:
        """The signing domains whose signature passed, each once."""
        passed = (s.domain for s in self.dkim_signatures if s.result == "pass" and s.domain)
        return list(dict.fromkeys(passed))


@dataclass
class ParsedEmail:
    """Everything the later stages need, pulled out of a raw .eml file."""

    path: Path
    subject: str = ""
    from_name: str = ""  # the display name of the first From address
    from_addr: str = ""  # the first From address: the one the sender checks use
    # Every From address (week 3, step 2). Normally just one. A second one used to make the
    # parser read no From address at all, which hid display-name spoofs.
    from_all: list[str] = field(default_factory=list)
    reply_to: str = ""  # the first Reply-To address
    # Every Reply-To address: "Reply-To: a@x.test, b@y.test" sends a reply to both
    reply_to_all: list[str] = field(default_factory=list)
    return_path: str = ""
    to: list[str] = field(default_factory=list)
    # Everyone the email was delivered to (week 3, step 2): To, Cc, Delivered-To and
    # X-Original-To. The last two are added by the receiving mail server, so they name you
    # even when you were in Bcc and To says "undisclosed-recipients".
    recipients: list[str] = field(default_factory=list)
    date: str = ""
    message_id: str = ""
    received: list[str] = field(default_factory=list)  # top (newest hop) first
    auth_results_headers: list[str] = field(default_factory=list)  # top first
    text_body: str = ""
    html_body: str = ""
    attachments: list[Attachment] = field(default_factory=list)
    defects: list[str] = field(default_factory=list)  # parsing problems, kept for the report
    # Emails attached as message/rfc822 ("forward as attachment"), each parsed on its own
    forwarded: list[ParsedEmail] = field(default_factory=list)
    depth: int = 0  # 0 = the .eml file itself, 1 = forwarded inside it, 2 = inside that, ...


@dataclass
class Finding:
    """One red flag. Points are added in week 4, from scoring.yaml, using the rule name.

    rule:    a short name, e.g. "vt_flagged"; scoring.yaml gives each one its points
    detail:  one line for the report, e.g. "paypa1-login[.]com: VirusTotal says 5 of 95 ..."
    facts:   week 4, step 7: the numbers behind the finding, for the scoring to apply its
             thresholds to, e.g. {"service": "virustotal", "kind": "url", "malicious": 5}.
             Empty for most findings; filled for the enrichment ones. Only numbers,
             true/false and fixed words go in, never a URL or other value from the email,
             so a report that shows the facts can never contain a live link.
             (Java: an optional Map<String, Object> component of a record.)
    """

    rule: str
    detail: str
    facts: dict[str, Any] = field(default_factory=dict)


@dataclass
class IOC:
    """One indicator of compromise (a URL, domain, IP, ...), found once or many times.

    Duplicates are merged: `sources` lists every place it was seen, without repeats, and
    `count` says how many times it was seen in total.
    """

    kind: str  # "url" for now; "domain", "ip", "email" are added in step 7
    value: str  # the normalised value, used for de-duplication and (week 3) lookups
    sources: list[str] = field(default_factory=list)  # e.g. ["text", "html:a[href]"]
    count: int = 0
    allowlisted: bool = False  # week 2 step 9: skip the week 3 lookup (NOT "safe")
