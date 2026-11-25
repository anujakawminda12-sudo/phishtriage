# PhishTriage report

PhishTriage 0.1.0, generated 2026-11-24T03:00:00Z (UTC).
Scoring: built-in scoring.yaml, SHA-256 `77c8089435bc8c70f6ad79a74e98004b65a64cf2c9255bccfe9adc2ed190bcf3`.
Headers and content only: no reputation lookups.
Pieces of text your addresses were removed from: 1.
Every link, address, domain and IP is defanged: nothing in this report can be clicked.

## Summary

Worst first; each file has its own section below.

| File | Verdict | Decided by |
| --- | --- | --- |
| phish_paypal_spoof.eml | **MALICIOUS 100/100** | the email itself |
| forwarded_phish.eml | **SUSPICIOUS 60/100** | forwarded email 1 |
| attachments_phish.eml | **SUSPICIOUS 50/100** | the email itself |
| broken_charset.eml | **LIKELY BENIGN 0/100** | the email itself |

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

## forwarded_phish.eml

**SUSPICIOUS 60/100**, decided by forwarded email 1: a forward is judged by what it carries

### The email

| Field | Value |
| --- | --- |
| Verdict | **LIKELY BENIGN 0/100** |
| Based on | headers and content only: not enriched (--enrich adds reputation lookups) |
| From | `Nimal Perera <REDACTED>` |
| Reply-To | - |
| Return-Path | `REDACTED` |
| Subject | Fwd: Your password expires today |
| Date | Fri, 20 Nov 2026 09:15:00 +0530 |
| Message-ID | `<fwd-5521[@]example[.]org>` |
| Received hops | 1 |
| Sender IP | - |
| IOCs found | 0 URLs, 1 domain, 0 IPs, 1 email address |
| Authentication | SPF pass, DKIM pass, DMARC pass (from mx\[.]example\[.]org) |
| Forwarded emails | 1 (reported separately below) |

#### IOCs (defanged)

| Type | Value | Seen | Found in | Looked up |
| --- | --- | --- | --- | --- |
| domain | `example[.]org` | 2 | email address, header:Message-ID | skip (allowlisted) |
| email address | `REDACTED` | 2 | header:From, header:Return-Path | skip (allowlisted) |

#### Findings

None so far.

### Forwarded email 1 (level 1)

| Field | Value |
| --- | --- |
| Verdict | **SUSPICIOUS 60/100** |
| Based on | headers and content only: not enriched (--enrich adds reputation lookups) |
| ATT\&CK | T1566.002 Phishing: Spearphishing Link |
| From | `Microsoft 365 Admin <no-reply[@]micros0ft-support[.]test>` |
| Reply-To | - |
| Return-Path | `bounce[@]mailer-4410[.]test` |
| Subject | Your password expires today |
| Date | Fri, 20 Nov 2026 07:58:30 +0530 |
| Message-ID | `<pw-7781[@]micros0ft-support[.]test>` |
| Received hops | 1 |
| Sender IP | `203[.]0[.]113[.]77 (from Received hop 1, less certain)` |
| IOCs found | 2 URLs, 4 domains, 1 IP, 2 email addresses |
| Authentication | SPF pass, DKIM pass, DMARC pass (from mx\[.]example\[.]org) |

#### Reasons

| Points | Reason | Rules | Why it added nothing |
| --- | --- | --- | --- |
| +20 | The sender's domain imitates a brand | lookalike_sender_domain | - |
| +15 | A link's text shows one site, but the link goes to another | link_text_mismatch | - |
| +15 | The sender's name claims a brand that did not send the email | display_name_spoof | - |
| +5 | The text pushes for quick action or asks for a login, password or payment | urgency_wording, credential_request_wording | - |
| +5 | Bounces go to a different organisation than the sender's (Return-Path) | return_path_mismatch | - |

#### Attachments

| Name | Declared type | Real type | Size | SHA-256 |
| --- | --- | --- | --- | --- |
| Password_Policy.txt | text/plain | text/plain | 45 | `7ec0a3917dd92f9fff6a722c0311e4304c2ac6017e735f7f94f991fa1e203067` |

#### IOCs (defanged)

| Type | Value | Seen | Found in | Looked up |
| --- | --- | --- | --- | --- |
| URL | `hxxp://micros0ft-login[.]test/auth?user=nimal` | 2 | text, html:a\[href] | yes |
| URL | `hxxps://login[.]microsoftonline[.]com/keep-password` | 1 | html:text | yes |
| domain | `micros0ft-login[.]test` | 1 | url | yes |
| domain | `login[.]microsoftonline[.]com` | 1 | url | yes |
| domain | `micros0ft-support[.]test` | 2 | email address, header:Message-ID | yes |
| domain | `mailer-4410[.]test` | 1 | email address | yes |
| IP | `203[.]0[.]113[.]77` | 2 | sender IP, header:Received (hop 1) | yes |
| email address | `no-reply[@]micros0ft-support[.]test` | 1 | header:From | yes |
| email address | `bounce[@]mailer-4410[.]test` | 1 | header:Return-Path | yes |

#### Findings

- `return_path_mismatch`: Return-Path bounce\[@]mailer-4410\[.]test differs from From no-reply\[@]micros0ft-support\[.]test
- `display_name_spoof`: Display name "Microsoft 365 Admin" claims microsoft, but sender is micros0ft-support\[.]test
- `lookalike_sender_domain`: From domain micros0ft-support\[.]test looks like microsoft: look-alike characters in "micros0ft" ("0" for "o")
- `link_text_mismatch`: 1 link shows one domain but goes to another, e.g. "hxxps://login\[.]microsoftonline\[.]com/keep-password" goes to micros0ft-login\[.]test
- `urgency_wording`: Pressure to act quickly, in the subject and the body: "expires today"
- `credential_request_wording`: Asks for a login, password or payment, in the subject and the body: "password expires", "keep your current password"

## attachments_phish.eml

**SUSPICIOUS 50/100**

### The email

| Field | Value |
| --- | --- |
| Verdict | **SUSPICIOUS 50/100** |
| Based on | headers and content only: not enriched (--enrich adds reputation lookups) |
| ATT\&CK | T1566.001 Phishing: Spearphishing Attachment |
| From | `Accounts Team <accounts[@]invoice-portal[.]test>` |
| Reply-To | - |
| Return-Path | `accounts[@]invoice-portal[.]test` |
| Subject | Invoice INV-2026-1142 and payment details |
| Date | Sat, 21 Nov 2026 08:12:30 +0530 |
| Message-ID | `<inv-1142[@]invoice-portal[.]test>` |
| Received hops | 1 |
| Sender IP | `198[.]51[.]100[.]23 (from Received hop 1, less certain)` |
| IOCs found | 0 URLs, 1 domain, 1 IP, 1 email address |
| Authentication | SPF pass, DKIM pass, DMARC pass (from mx\[.]example\[.]org) |

#### Reasons

| Points | Reason | Rules | Why it added nothing |
| --- | --- | --- | --- |
| +30 | An attachment hides its real type behind a double extension | attachment_double_extension | - |
| +20 | An attachment is a risky type, or is not what its name says | attachment_risky_type, attachment_type_mismatch, attachment_encrypted_archive | - |

#### Attachments

| Name | Declared type | Real type | Size | SHA-256 |
| --- | --- | --- | --- | --- |
| Invoice_INV-2026-1142.pdf | application/pdf | text/html | 78 | `f679d22f749f5153d0f27088521142f6a55bed15164881b416da0e07e6d54950` |
| Statement.pdf.exe | application/octet-stream | text/plain | 45 | `7ec0a3917dd92f9fff6a722c0311e4304c2ac6017e735f7f94f991fa1e203067` |
| Payment_Details\[.]zip | application/zip | application/zip | 267 | `e16ad1f3fdac18c05dfc152aad74368ba80a98abd52f2d83c731b63a9059c09c` |
| Terms.txt | text/plain | text/plain | 54 | `1de02ebe63f22dee6f10ab4a52eadfc3418c4cc35e425f2a08d103488cdc42a6` |

- Inside Payment_Details\[.]zip (password-protected): Payment_Details.pdf.js

#### IOCs (defanged)

| Type | Value | Seen | Found in | Looked up |
| --- | --- | --- | --- | --- |
| domain | `invoice-portal[.]test` | 2 | email address, header:Message-ID | yes |
| IP | `198[.]51[.]100[.]23` | 2 | sender IP, header:Received (hop 1) | yes |
| email address | `accounts[@]invoice-portal[.]test` | 2 | header:From, header:Return-Path | yes |

#### Findings

- `attachment_risky_type`: Statement.pdf.exe (a program that runs when opened); Payment_Details\[.]zip contains Payment_Details.pdf.js (a script that runs when opened)
- `attachment_double_extension`: Statement.pdf.exe; Payment_Details\[.]zip contains Payment_Details.pdf.js
- `attachment_type_mismatch`: Invoice_INV-2026-1142.pdf is named .pdf but its content is text/html
- `attachment_encrypted_archive`: Payment_Details\[.]zip is password-protected, so scanners cannot check what is inside

## broken_charset.eml

**LIKELY BENIGN 0/100**

### The email

| Field | Value |
| --- | --- |
| Verdict | **LIKELY BENIGN 0/100** |
| Based on | headers and content only: not enriched (--enrich adds reputation lookups) |
| From | `  <> ` |
| Reply-To | - |
| Return-Path | - |
| Subject | Broken charset test |
| Date | - |
| Message-ID | - |
| Received hops | 0 |
| Sender IP | - |
| IOCs found | 0 URLs, 0 domains, 0 IPs, 0 email addresses |
| Authentication | SPF unknown, DKIM unknown, DMARC unknown (no trusted header) |

#### Reasons

| Points | Reason | Rules | Why it added nothing |
| --- | --- | --- | --- |
| 0 | No trusted Authentication-Results header, so SPF, DKIM and DMARC are unknown | no_auth_results | - |

#### Findings

- `no_auth_results`: No trusted Authentication-Results header: SPF/DKIM/DMARC unknown

Parsing notes: From header has no readable address, LookupError decoding text/plain part
