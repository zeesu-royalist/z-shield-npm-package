# Security Policy

## Reporting Security Vulnerabilities

We take the security of **Z-Shield** seriously. If you discover a security vulnerability, please disclose it responsibly so we can investigate and address it before public disclosure.

> **Important**: Please do **NOT** open public GitHub issues, pull requests, or discussions for undisclosed security vulnerabilities.

### How to Report Privately
Please submit vulnerability reports privately through one of the following channels:
1. **GitHub Private Vulnerability Reporting**: Use the "Report a vulnerability" button under the **Security** tab of the Z-Shield repository (recommended).
2. **Designated Maintainer Contact**: `md.jishan.dev@gmail.com`

You will receive an acknowledgment of your report within 48 hours, followed by regular status updates as we evaluate and remediate the issue.

---

### What to Include in a Report
To help us triage and resolve the issue quickly, please provide:
- **Description**: A clear summary of the vulnerability and its potential impact.
- **Affected Versions**: The version of Z-Shield where the vulnerability was observed.
- **Reproduction Steps**: A minimal, reproducible example (e.g., sample code, `curl` commands, or a small script demonstrating the flaw).
- **Proof of Concept**: Details on how the exploit is triggered.
- **Remediation Ideas**: Any proposed patches or mitigations, if known.

---

### Scope and Vulnerability Types

#### Vulnerabilities In Scope:
- **Log Injection / CRLF Injection (CWE-117)**: Any condition that allows unescaped newlines or control characters to forge log entries in `.jsonl` files.
- **Memory Exhaustion / DoS (CWE-400)**: Any scenario where unauthenticated incoming requests can bypass LRU bounds and cause an unbounded heap leak.
- **IP Spoofing / Header Smuggling**: Flaws in client IP resolution that allow bypassing rate limits or blocks under supported Express proxy configurations.
- **Terminal Injection**: Scenarios where untrusted log data prints executable ANSI escape sequences to developer terminals.
- **Information Disclosure (CWE-532)**: Accidental logging of request bodies, passwords, cookies, or authorization headers.

#### Out of Scope (Known Documented Limitations):
- **Cross-Process / Multi-Worker State Sharing**: In this release, counters and temporary blocks are intentionally process-local in memory. Running multiple Node.js cluster workers or server instances without a centralized distributed adapter (like Redis) will result in independent counters per process. This is a documented architectural choice, not a vulnerability.
- **Process Restarts**: In-memory counters and blocks intentionally reset when the Node.js process terminates.
- **Misconfigured Proxies**: If the host application configures Express `app.set('trust proxy', true)` while sitting directly on the public internet without a reverse proxy, client-controlled `X-Forwarded-For` headers will be trusted. This is a configuration mistake in the host application.
- **Ephemeral Filesystem Data Loss**: On platforms with ephemeral disk storage (e.g. serverless containers), local `.jsonl` files reset when containers cycle.

---

### Security Best Practices for Users
1. **Keep Node.js Updated**: Run Z-Shield on active Node.js LTS releases.
2. **Configure Proxies Safely**: Only set `trustProxy: true` if your app runs behind a properly configured reverse proxy (such as Nginx, Cloudflare, or AWS ALB) that strips spoofed headers.
3. **Restrict Log Directory Permissions**: Ensure the `.z-shield-logs` directory has restrictive read/write permissions on the host system.
