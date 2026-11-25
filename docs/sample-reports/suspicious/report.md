# PhishTriage report

PhishTriage 0.1.0, generated 2026-11-24T14:14:20Z (UTC).
Scoring: built-in scoring.yaml, SHA-256 `77c8089435bc8c70f6ad79a74e98004b65a64cf2c9255bccfe9adc2ed190bcf3`.
Headers and content only: no reputation lookups.
Every link, address, domain and IP is defanged: nothing in this report can be clicked.

## Summary

Worst first; each file has its own section below.

| File | Verdict | Decided by |
| --- | --- | --- |
| phish_open_redirect.eml | **SUSPICIOUS 35/100** | the email itself |

## phish_open_redirect.eml

**SUSPICIOUS 35/100**

### The email

| Field | Value |
| --- | --- |
| Verdict | **SUSPICIOUS 35/100** |
| Based on | headers and content only: not enriched (--enrich adds reputation lookups) |
| ATT\&CK | T1566.002 Phishing: Spearphishing Link |
| From | `DocuSign <dse[@]docusign-notice[.]test>` |
| Reply-To | - |
| Return-Path | - |
| Subject | Please review and sign: Contract_2026.pdf |
| Date | Mon, 23 Nov 2026 09:00:00 +0000 |
| Message-ID | `<9f2c4b[@]docusign-notice[.]test>` |
| Received hops | 1 |
| Sender IP | `203[.]0[.]113[.]88 (from Authentication-Results)` |
| IOCs found | 7 URLs, 6 domains, 1 IP, 1 email address |
| Authentication | SPF pass, DKIM pass, DMARC pass (from mx\[.]example\[.]org) |

#### Reasons

| Points | Reason | Rules | Why it added nothing |
| --- | --- | --- | --- |
| +15 | The sender's domain uses a brand's name but is not one of the brand's | brand_in_sender_domain | - |
| +15 | The sender's name claims a brand that did not send the email | display_name_spoof | - |
| +5 | A link hides where it goes (URL shortener or open redirect) | open_redirect | - |

#### IOCs (defanged)

| Type | Value | Seen | Found in | Looked up |
| --- | --- | --- | --- | --- |
| URL | `hxxps://www[.]example[.]com/url?q=hxxps://docs-review[.]test/view/7781&sa=D` | 2 | text, html:a\[href] | yes |
| URL | `hxxps://docs-review[.]test/view/7781` | 2 | text (inside a link to www\[.]example\[.]com), html:a\[href] (inside a link to www\[.]example\[.]com) | yes |
| URL | `hxxps://click[.]docusign-notice[.]test/track?url=hxxps://docusign-notice[.]test/help` | 1 | text | yes |
| URL | `hxxps://docusign-notice[.]test/help` | 2 | text (inside a link to click\[.]docusign-notice\[.]test), html:a\[href] (inside a link to click\[.]docusign-notice\[.]test) | yes |
| URL | `hxxps://images[.]example[.]org/proxy?src=hxxps://cdn[.]example[.]net/logo[.]png` | 1 | html:img\[src] | yes |
| URL | `hxxps://cdn[.]example[.]net/logo[.]png` | 1 | html:img\[src] (inside a link to images\[.]example\[.]org) | skip (allowlisted) |
| URL | `hxxps://click[.]docusign-notice[.]test/track?url=https%3A%2F%2Fdocusign-notice[.]test%2Fhelp` | 1 | html:a\[href] | yes |
| domain | `www[.]example[.]com` | 1 | url | skip (allowlisted) |
| domain | `docs-review[.]test` | 1 | url | yes |
| domain | `click[.]docusign-notice[.]test` | 2 | url | yes |
| domain | `docusign-notice[.]test` | 3 | url, email address, header:Message-ID | yes |
| domain | `images[.]example[.]org` | 1 | url | skip (allowlisted) |
| domain | `cdn[.]example[.]net` | 1 | url | skip (allowlisted) |
| IP | `203[.]0[.]113[.]88` | 2 | sender IP, header:Received (hop 1) | yes |
| email address | `dse[@]docusign-notice[.]test` | 1 | header:From | yes |

#### Findings

- `display_name_spoof`: Display name "DocuSign" claims docusign, but sender is docusign-notice\[.]test
- `brand_in_sender_domain`: From domain docusign-notice\[.]test uses the name docusign but is not docusign's (docusign\[.]com, docusign\[.]net)
- `open_redirect`: 1 link on one site forwards to another, e.g. www\[.]example\[.]com forwards to docs-review\[.]test
