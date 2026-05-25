# CipherScout

CipherScout is a TLS cipher suite auditing tool built on top of SSLyze, Mozilla TLS guidelines, ciphersuite.info, and BSI TR-02102-2.

It scans TLS endpoints, evaluates accepted cipher suites, validates certificate cryptography against Mozilla recommendations, detects weak TLS configurations, and generates Markdown security reports.

---

## Features

* TLS endpoint scanning using SSLyze
* Accepted cipher suite enumeration
* BSI TR-02102-2 cipher suite comparison
* ciphersuite.info security classification
* Mozilla TLS guideline validation
* Certificate cryptography auditing
* OCSP stapling detection
* TLS version auditing
* TLS security checks:
  * Heartbleed
  * ROBOT
  * CCS Injection
  * TLS compression
  * TLS fallback SCSV
  * Extended Master Secret
  * Session renegotiation
* Elliptic curve compliance validation
* Markdown report export
* ANSI-colored terminal output

---

## Requirements

* Python 3.11+
* OpenSSL
* SSLyze

---

## Usage

### Scan a target

```bash
cipherscout example.com
```

### Scan a custom port

```bash
cipherscout example.com:8443
```

### Export Markdown report

```bash
cipherscout example.com --export-md report.md
```

### Use custom BSI PDF

```bash
cipherscout example.com --pdf ./BSI-TR-02102-2.pdf
```

### Update BSI PDF

```bash
cipherscout --update-bsi
```

### Evaluate cipher suites manually

```bash
cipherscout \
  --cipher-suites TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384
```

---

## Example Output

```text
Legend
  Orange = Mozilla intermediate configuration
  Red = Non-compliant / deprecated / insecure

Certificate Information

+----------------------------+------------------+
| Field                      | Value            |
+============================+==================+
| Public Key Algorithm       | RSAPublicKey     |
| Key Size                   | 4096             |
| Signature Algorithm        | sha256WithRSAEncryption |
| OCSP Stapling              | supported        |
+----------------------------+------------------+

Supported TLS Versions

+-----------+
| Version   |
+===========+
| TLS 1.2   |
| TLS 1.3   |
+-----------+
```

---

## Mozilla Compliance

CipherScout validates:

* Certificate algorithms
* RSA key sizes
* TLS elliptic curves
* Certificate curves
* Certificate signatures

against Mozilla's latest TLS recommendations.

Color coding:

| Color   | Meaning                               |
| ------- | ------------------------------------- |
| Default | Mozilla Modern Compliant / Secure     |
| Orange  | Mozilla Intermediate compliant        |
| Red     | Non-Compliant / Deprecated / Insecure |

---

## Report Export

Markdown reports can be exported using:

```bash
cipherscout example.com --export-md report.md
```

The generated report contains:

* Certificate information
* Supported TLS versions
* Accepted cipher suites
* Security checks
* Cipher weaknesses
* Mozilla compliance results