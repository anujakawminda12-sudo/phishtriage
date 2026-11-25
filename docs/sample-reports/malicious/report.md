# PhishTriage report

PhishTriage 0.1.0, generated 2026-11-24T14:14:04Z (UTC).
Scoring: built-in scoring.yaml, SHA-256 `77c8089435bc8c70f6ad79a74e98004b65a64cf2c9255bccfe9adc2ed190bcf3`.
Headers and content only: no reputation lookups.
Every link, address, domain and IP is defanged: nothing in this report can be clicked.

## Summary

Worst first; each file has its own section below.

| File | Verdict | Decided by |
| --- | --- | --- |
| phish_paypal_spoof.eml | **MALICIOUS 100/100** | the email itself |

## phish_paypal_spoof.eml

**MALICIOUS 100/100**

### The email

| Field | Value |
| --- | --- |
| Verdict | **MALICIOUS 100/100** |
| Based on | headers and content only: not enriched (--enrich adds reputation lookups) |
| ATT\&CK | T1566.001 Phishing: Spearphishing Attachment, T1566.002 Phishing: Spearphishing Link |
| From | `PayPal Security <service[@]paypal[.]com>` |
| Reply-To | `support[@]paypa1-secure[.]test` |
| Return-Path | `bounce[@]mailer-7731[.]test` |
| Subject | Your account has been suspended |
| Date | Wed, 18 Nov 2026 10:41:00 +0000 |
| Message-ID | `<a8f3e2[@]mailer-7731[.]test>` |
| Received hops | 1 |
| Sender IP | `203[.]0[.]113[.]45 (from Authentication-Results)` |
| IOCs found | 2 URLs, 4 domains, 1 IP, 3 email addresses |
| Authentication | SPF softfail, DKIM none, DMARC fail (from mx\[.]google\[.]com) |

#### Reasons

| Points | Reason | Rules | Why it added nothing |
| --- | --- | --- | --- |
| +25 | The From domain failed DMARC | dmarc_fail | - |
| +20 | The sender's domain imitates a brand | lookalike_sender_domain | - |
| +20 | An attachment is a risky type, or is not what its name says | attachment_risky_type | - |
| +15 | A link's text shows one site, but the link goes to another | link_text_mismatch | - |
| +15 | Replies would go to a different organisation than the sender's | reply_to_mismatch | - |
| +10 | The sending server is not allowed to send for the sender's domain (SPF) | spf_softfail | - |
| +10 | DKIM failed, is missing, or was not signed by the sender's own domain | dkim_none | - |
| +5 | The text pushes for quick action or asks for a login, password or payment | urgency_wording, credential_request_wording | - |
| +5 | Bounces go to a different organisation than the sender's (Return-Path) | return_path_mismatch | - |
| 0 | More Authentication-Results headers further down (normal after forwarding) | extra_auth_results | - |

#### Attachments

| Name | Declared type | Real type | Size | SHA-256 |
| --- | --- | --- | --- | --- |
| Account_Review.html | text/html | text/html | 78 | `f679d22f749f5153d0f27088521142f6a55bed15164881b416da0e07e6d54950` |

#### IOCs (defanged)

| Type | Value | Seen | Found in | Looked up |
| --- | --- | --- | --- | --- |
| URL | `hxxps://www[.]paypal[.]com/signin` | 2 | text, html:text | yes |
| URL | `hxxp://paypa1-secure[.]test/login` | 1 | html:a\[href] | yes |
| domain | `www[.]paypal[.]com` | 1 | url | yes |
| domain | `paypa1-secure[.]test` | 2 | url, email address | yes |
| domain | `paypal[.]com` | 1 | email address | yes |
| domain | `mailer-7731[.]test` | 2 | email address, header:Message-ID | yes |
| IP | `203[.]0[.]113[.]45` | 2 | sender IP, header:Received (hop 1) | yes |
| email address | `service[@]paypal[.]com` | 1 | header:From | yes |
| email address | `support[@]paypa1-secure[.]test` | 1 | header:Reply-To | yes |
| email address | `bounce[@]mailer-7731[.]test` | 1 | header:Return-Path | yes |

#### Findings

- `spf_softfail`: SPF result: softfail
- `dkim_none`: DKIM result: none
- `dmarc_fail`: DMARC result: fail
- `extra_auth_results`: 1 more Authentication-Results header(s) lower down were ignored (normal after forwarding, suspicious otherwise)
- `reply_to_mismatch`: Reply-To support\[@]paypa1-secure\[.]test differs from From service\[@]paypal\[.]com
- `return_path_mismatch`: Return-Path bounce\[@]mailer-7731\[.]test differs from From service\[@]paypal\[.]com
- `lookalike_sender_domain`: Reply-To domain paypa1-secure\[.]test looks like paypal: look-alike characters in "paypa1" ("1" for "l")
- `link_text_mismatch`: 1 link shows one domain but goes to another, e.g. "hxxps://www\[.]paypal\[.]com/signin" goes to paypa1-secure\[.]test
- `urgency_wording`: Pressure to act quickly, in the subject and the body: "account has been suspended", "unusual activity", "within 24 hours"
- `credential_request_wording`: Asks for a login, password or payment, in the body: "verify your account"
- `attachment_risky_type`: Account_Review.html (a web page: fake login forms and HTML smuggling)
