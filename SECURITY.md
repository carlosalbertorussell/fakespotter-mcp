# Security Policy for FakeSpotter

FakeSpotter takes the security of its forensic analysis and integrity tools seriously. As a cybersecurity specialist, I am committed to maintaining a secure environment and addressing vulnerabilities through a transparent and responsible disclosure process.

## Supported Versions

We only support the latest version of FakeSpotter. Security updates are applied to the `main` branch immediately. 

| Version | Supported |
| :--- | :--- |
| 1.0.x | ✅ Yes |

## Reporting a Vulnerability

If you discover a security vulnerability in FakeSpotter, please report it privately. **Do not create a public GitHub Issue for security vulnerabilities.**

Please send your report to **[INSERT YOUR EMAIL HERE]**.

### What to include in your report:
* **Description:** A detailed explanation of the vulnerability.
* **Impact:** What can an attacker do with this vulnerability?
* **Steps to Reproduce:** Clear, numbered instructions on how to trigger the issue.
* **Environment:** Details about your IDE (Cursor, VS Code, etc.), OS, and MCP setup.

I will acknowledge receipt of your report within 48 hours and work with you to validate and remediate the issue.

## Disclosure Policy

* I am committed to fixing security vulnerabilities as quickly as possible.
* I request that you do not disclose the vulnerability publicly until a fix has been released.
* I respect the efforts of security researchers and will provide public recognition for valid, responsibly disclosed findings.

## Security Controls in FakeSpotter

FakeSpotter is designed with the following security-first principles:
1. **Zero-Trust Input Sanitization:** All media URLs and JSON inputs are validated to prevent SSRF and injection attacks.
2. **Cryptographic Integrity:** Every forensic report is hashed (SHA-256) to ensure the evidence remains unaltered.
3. **Containerized Execution:** All operations run in an isolated, non-privileged Docker environment.
4. **No-PII by Design:** The system is engineered to process forensic data without storing personal identification information locally.

---
*Last Updated: May 2026*
