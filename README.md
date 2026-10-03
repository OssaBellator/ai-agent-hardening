# AI Agent Setup & Hardening — A$149

> **Repository role:** this remains the scanner/release compatibility surface used by existing links and upstream directory submissions. The current buyer-facing project, checklist, Agent Skill, and maintained service documentation live at **[claude-code-mcp-hardening](https://github.com/OssaBellator/claude-code-mcp-hardening)**.

[![Self-test](https://github.com/OssaBellator/ai-agent-hardening/actions/workflows/self-test.yml/badge.svg)](https://github.com/OssaBellator/ai-agent-hardening/actions/workflows/self-test.yml) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)

A fixed-scope repository hardening service for developers using AI coding agents.

**Price:** A$149 one-time  
**Checkout:** https://buy.stripe.com/9B600d9Mocei2RV8c104801?client_reference_id=github_readme_hardening

## What this is

I review one software repository and tighten the operational boundaries around AI-assisted development. The goal is a safer, more recoverable workspace with explicit tool authority and a concise handoff you can actually use.

## Included

- **Repository intake audit** — current agent instructions, tool surfaces, deployment hooks, secret exposure points, and recovery gaps.
- **Credential boundary review** — identify where credentials are expected, reduce unnecessary exposure, and keep customer-owned secrets customer-owned.
- **Tool and MCP hardening** — narrow callable surfaces, inputs, and authority where practical instead of granting broad ambient access.
- **Recovery baseline** — document and verify a practical recovery path for the repository and its critical local state.
- **Verification** — run the repository-appropriate build, type, lint, test, and smoke checks that are available and record any limitations.
- **Handoff** — concise summary of changes, remaining customer actions, authority boundaries, and recovery steps.

## Scope

The fixed price covers **one primary repository** and a bounded hardening pass. Optional deployment work is included only when it is already part of the repository and can be performed with customer-authorized credentials.

This is not managed security monitoring, incident response, penetration testing, legal/compliance certification, or a guarantee that a repository is vulnerability-free.

## How it works

1. Purchase the fixed-price service.
2. Open an intake issue in this repository **without posting secrets**.
3. Share the repository through an access method you control.
4. The workspace is audited, hardened, verified, and handed back with evidence and explicit limitations.

## Before you buy

This service is a good fit when you already use tools such as coding agents, MCP servers, repository automation, deployment CLIs, or AI-assisted workflows and want clearer boundaries and recovery.

It is not a fit if you need emergency incident response, credential recovery, malware removal, or custody of private keys/recovery phrases.

## Lower-cost public-repo audit

If you only want an evidence-backed review of one **public GitHub repository**, the [A$39 repository hardening audit](https://ossabellator.github.io/ai-agent-hardening/audit.html) covers agent/tool surfaces, visible credential risks, authority boundaries, recovery signals, and prioritized remediation without implementing changes.

A [sample audit report](./sample-audit.md) shows the finding format, evidence standard, and limitations.

## Ongoing 60-day watch

If a public repository is changing quickly and a one-time audit will age out, the [A$79 60-day hardening watch](https://ossabellator.github.io/claude-code-mcp-hardening/watch.html) provides a baseline plus day-30 and day-60 read-only reports. Payment is one-time, and follow-up reports are delivered through one GitHub issue after private payment verification.

## Free static scanner

Run a dependency-free, evidence-only scan locally:

```bash
python agent_hardening_check.py /path/to/repository
```

Or install the verified v1.1.1 wheel directly from the GitHub release:

```bash
pip install https://github.com/OssaBellator/ai-agent-hardening/releases/download/v1.1.1/ai_agent_repository_hardening-1.1.1-py3-none-any.whl
ai-agent-hardening /path/to/repository
```

It inventories common agent/MCP/CI/dependency surfaces and flags a small set of high-signal configuration/credential patterns. It **does not execute target code, install dependencies, or print suspected secret values**. The scanner is a triage aid, not a security certification.

You can also [request a free public-repository scan](https://github.com/OssaBellator/ai-agent-hardening/issues/new?template=free-scan.yml) without installing anything. The hosted scan uses bounded GitHub API reads only and posts non-secret findings back to the issue.

## Install from the GitHub release

The scanner is also packaged as a dependency-free Python wheel. Until a PyPI publishing credential is configured, install the immutable GitHub Release asset directly:

```bash
python -m pip install https://github.com/OssaBellator/ai-agent-hardening/releases/download/v1.1.1/ai_agent_repository_hardening-1.1.1-py3-none-any.whl
ai-agent-hardening . --format markdown
```

## GitHub Action

Add the same static scan to CI after checkout:

```yaml
permissions:
  contents: read

steps:
  - uses: actions/checkout@v4
  - uses: OssaBellator/ai-agent-hardening@v1
```

For a fully pinned dependency, use the current release commit instead of the moving major tag: `OssaBellator/ai-agent-hardening@7c257db44232e61e944870e3af18c4e87fa51921`.

The action requires only `contents: read`; it runs the dependency-free scanner against the checked-out repository and writes the Markdown result to the GitHub Actions job summary. By default it is advisory-only. To make high-severity findings fail CI, configure:

```yaml
- uses: OssaBellator/ai-agent-hardening@v1
  with:
    fail-on: high
```

Accepted thresholds are `never` (default), `high`, `medium`, and `any`. See [example-workflow.yml](./example-workflow.yml).


## Optional GitHub Code Scanning

The action also writes a SARIF 2.1.0 report to `agent-hardening-scan.sarif` and exposes that path as the `sarif-file` output. The scanner itself still needs only `contents: read`.

If you explicitly want findings in GitHub Code Scanning, grant `security-events: write` in your workflow and upload the SARIF file after the scan:

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: actions/checkout@v4
  - id: hardening
    uses: OssaBellator/ai-agent-hardening@v1
  - uses: github/codeql-action/upload-sarif@v3
    with:
      sarif_file: ${{ steps.hardening.outputs.sarif-file }}
```

This elevated permission belongs to the caller workflow, not to the scanner itself.

## MCP security checklist

If you use MCP servers with coding agents, the [MCP Security Checklist](https://ossabellator.github.io/ai-agent-hardening/mcp-security-checklist.html) covers least privilege, tool/schema trust, sandboxing, confirmations, credential boundaries, and privileged GitHub Actions triggers with primary-source references.

## Free checklist

Use the public [AI Coding Agent Repository Hardening Checklist](https://ossabellator.github.io/ai-agent-hardening/checklist.html) before buying. It covers secrets, tool authority, recovery, verification, and irreversible actions.

## Intake / questions

Open a **Service intake / question** issue in this repository. Do not include passwords, API keys, private keys, recovery phrases, customer data, or other secrets.

**Buy the service:** https://buy.stripe.com/9B600d9Mocei2RV8c104801?client_reference_id=github_readme_hardening

## License

The scanner, GitHub Action, checklist, sample report, and repository documentation are released under the [MIT License](./LICENSE).
