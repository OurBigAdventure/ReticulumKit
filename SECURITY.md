# Security Policy

ReticulumKit implements cryptographic networking primitives. We take security issues seriously and appreciate responsible disclosure.

## Supported versions

ReticulumKit is in active pre-1.0 development. Security fixes are applied to the latest released version and `main`. Older `0.x` tags are not maintained, so please upgrade to the latest release.

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues, discussions, or pull requests.**

Instead, report privately using one of:

- **GitHub Security Advisories:** use the [Report a vulnerability](https://github.com/J-Krush/ReticulumKit/security/advisories/new) button under the repository's **Security** tab (preferred, since it keeps the report and fix coordination in one place).
- **Email:** `jkrush@pm.me`. Use a clear subject line such as "ReticulumKit security report".

Please include:

- A description of the issue and its impact.
- Steps to reproduce, or a proof-of-concept, if available.
- The affected version or commit.
- Any suggested remediation.

## What to expect

- We aim to acknowledge your report within **5 business days**.
- We'll work with you to understand and validate the issue, and keep you updated on progress.
- Once a fix is ready, we'll coordinate a release and, with your permission, credit you in the advisory.
- Please give us a reasonable window to release a fix before any public disclosure.

## Scope

Issues that are in scope include, but are not limited to:

- Weaknesses in key generation, storage, or handling.
- Flaws in the link handshake, token encryption, or signature verification.
- Wire-parsing bugs that could lead to crashes, memory issues, or authentication bypass.
- Anything that could let a peer impersonate a destination or decrypt traffic they shouldn't.

Thank you for helping keep ReticulumKit and its users safe.
