# PhishTriage report

PhishTriage 0.1.0, generated 2026-11-24T14:14:33Z (UTC).
Scoring: built-in scoring.yaml, SHA-256 `77c8089435bc8c70f6ad79a74e98004b65a64cf2c9255bccfe9adc2ed190bcf3`.
Headers and content only: no reputation lookups.
Every link, address, domain and IP is defanged: nothing in this report can be clicked.

## Summary

Worst first; each file has its own section below.

| File | Verdict | Decided by |
| --- | --- | --- |
| legit_newsletter.eml | **LIKELY BENIGN 0/100** | the email itself |

## legit_newsletter.eml

**LIKELY BENIGN 0/100**

### The email

| Field | Value |
| --- | --- |
| Verdict | **LIKELY BENIGN 0/100** |
| Based on | headers and content only: not enriched (--enrich adds reputation lookups) |
| From | `Example Store <news[@]example[.]com>` |
| Reply-To | - |
| Return-Path | `bounce[@]example[.]com` |
| Subject | Your November newsletter |
| Date | Tue, 17 Nov 2026 17:15:00 +0000 |
| Message-ID | `<20261117171500[.]12345[@]example[.]com>` |
| Received hops | 1 |
| Sender IP | `192[.]0[.]2[.]10 (from Authentication-Results)` |
| IOCs found | 1 URL, 2 domains, 1 IP, 2 email addresses |
| Authentication | SPF pass, DKIM pass, DMARC pass (from mx\[.]google\[.]com) |

#### IOCs (defanged)

| Type | Value | Seen | Found in | Looked up |
| --- | --- | --- | --- | --- |
| URL | `hxxps://www[.]example[.]com/offers` | 2 | text, html:a\[href] | skip (allowlisted) |
| domain | `www[.]example[.]com` | 1 | url | skip (allowlisted) |
| domain | `example[.]com` | 3 | email address, header:Message-ID | skip (allowlisted) |
| IP | `192[.]0[.]2[.]10` | 2 | sender IP, header:Received (hop 1) | yes |
| email address | `news[@]example[.]com` | 1 | header:From | skip (allowlisted) |
| email address | `bounce[@]example[.]com` | 1 | header:Return-Path | skip (allowlisted) |

#### Findings

None so far.
