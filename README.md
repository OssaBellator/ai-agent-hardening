# AI Agent Setup & Hardening — A$149

A fixed-scope repository hardening service for developers using AI coding agents.

**Price:** A$149 one-time  
**Checkout:** https://buy.stripe.com/9B600d9Mocei2RV8c104801

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

## Free static scanner

Run a dependency-free, evidence-only scan locally:

```bash
python agent_hardening_check.py /path/to/repository
```

It inventories common agent/MCP/CI/dependency surfaces and flags a small set of high-signal configuration/credential patterns. It **does not execute target code, install dependencies, or print suspected secret values**. The scanner is a triage aid, not a security certification.

## GitHub Action

Add the same static scan to CI:

```yaml
- uses: OssaBellator/ai-agent-hardening@main
```

The action requires only `contents: read`; it runs the dependency-free scanner against the checked-out repository and writes the Markdown result to the GitHub Actions job summary. See [example-workflow.yml](./example-workflow.yml).

## Free checklist

Use the public [AI Coding Agent Repository Hardening Checklist](https://ossabellator.github.io/ai-agent-hardening/checklist.html) before buying. It covers secrets, tool authority, recovery, verification, and irreversible actions.

## Intake / questions

Open a **Service intake / question** issue in this repository. Do not include passwords, API keys, private keys, recovery phrases, customer data, or other secrets.

**Buy the service:** https://buy.stripe.com/9B600d9Mocei2RV8c104801
