# Security Policy

## Reporting a vulnerability

Please do **not** open a public issue for a vulnerability that would expose a real credential, private key, customer data, or a practical exploit path that should be handled privately first.

Use GitHub's private vulnerability reporting feature for this repository when available. If that channel is unavailable, open a public issue containing only a non-sensitive description that a private security report is needed; do not include exploit details or secrets.

## Scope

Security reports for this repository should concern the scanner, GitHub Action, public site, or repository configuration itself. The scanner is intentionally static and must not execute target repository code or print suspected secret values.

Reports about a repository scanned by this tool belong to that repository's owner, not here.

## Supported version

The current `v1` major tag and latest `v1.x.x` release are supported.
