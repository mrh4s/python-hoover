# Security Policy

Python-Hoover is a WiFi security testing toolkit intended exclusively for authorized penetration testing, security research, and education. All tools in this repository are designed to be used on networks you own or have explicit written permission to test.

## Reporting a Vulnerability

If you discover a security vulnerability in the toolkit itself (e.g. in the web dashboard, REST API, or CLI tools), please report it through [GitHub Security Advisories](https://github.com/mrh4s/python-hoover/security/advisories/new). This is the preferred method as it allows private discussion before any public disclosure.

Do not open a public issue for security vulnerabilities.

## Responsible Disclosure

We ask that reporters:

- Allow a reasonable timeframe (90 days) to address the issue before any public disclosure.
- Provide sufficient detail to reproduce the vulnerability.
- Avoid exploiting the vulnerability beyond what is necessary to demonstrate it.

We will acknowledge receipt of your report within 7 days and aim to provide a fix or mitigation plan within 30 days.

## Supported Versions

Only the latest version on the `main` branch is actively maintained and receives security updates. There are no long-term support releases.

| Branch | Supported |
|--------|-----------|
| main   | Yes       |
| Others | No        |

## Scope

### In scope

Security issues in the toolkit's own code, including but not limited to:

- Command injection in the web dashboard or REST API
- CSRF bypass in the web dashboard
- Authentication or authorization bypass in the REST API or web dashboard
- Credential leaks (e.g. API tokens, session secrets logged or exposed)
- Path traversal in file handling endpoints
- Insecure default configurations that could expose the operator

### Out of scope

- Vulnerabilities in target networks discovered by the tools — that is the intended purpose of the toolkit.
- Issues that require physical access to the machine running the toolkit.
- Denial of service against the toolkit's local web interface (it is designed for single-operator use on localhost).

## Responsible Use

This toolkit must only be used for authorized security testing. Users are responsible for:

- Obtaining explicit written permission before testing any network.
- Complying with all applicable local, state, and federal laws and regulations.
- Understanding that unauthorized use may violate the Computer Fraud and Abuse Act (US) and equivalent legislation in other jurisdictions.

The authors and contributors of this project assume no liability for misuse.
