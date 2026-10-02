# Sample AI Agent Repository Hardening Audit

**Sample target:** `OssaBellator/ai-agent-hardening`  
**Scope:** Public GitHub repository; static evidence only  
**Execution:** No repository code executed and no dependencies installed  
**Purpose:** Demonstrate the structure and evidence standard of the A$39 audit. This sample is not a certification.

## Executive snapshot

The sample repository is a small static GitHub Pages site with no application runtime, dependency manifests, CI workflows, MCP configuration, or agent instruction files visible in the reviewed tree. No common credential/private-key patterns were found in the reviewed public files. GitHub secret scanning and push protection are enabled.

The main material hardening gap observed is governance of the default branch: `main` is not protected even though it controls live sales copy and checkout destinations.

## Evidence reviewed

- Public repository metadata and default branch.
- Public repository tree and service-intake issue template.
- Static HTML, Markdown, sitemap, and robots files.
- Common AI-agent instruction/config filenames.
- Common dependency/runtime manifests.
- Common credential/private-key patterns.
- GitHub Pages state.
- Default-branch protection state.

## Finding F-01 — Medium — Default branch is not protected

**Observed evidence:** GitHub reports `main` as the default branch and the branch-protection endpoint reports that the branch is not protected. The branch contains the Pages content and live checkout URLs.

**Why it matters:** A mistaken or unauthorized direct push by someone with write authority could change customer-facing copy or redirect a payment link without a review gate. This finding does not indicate that such a change has occurred.

**Recommended remediation:** Add a repository ruleset or branch protection appropriate to the maintenance model. At minimum, prevent force-push/deletion and consider requiring review for changes to customer-facing payment destinations.

**Limitations:** Repository administrator/account security is outside this public-repository audit.

## Positive controls

- Repository is public by design and GitHub Pages is HTTPS-enabled.
- GitHub secret scanning and push protection are enabled.
- The intake issue template explicitly warns users not to post passwords, API keys, private keys, recovery phrases, or customer data.
- No common secret/private-key patterns were found in the reviewed public files.
- No executable project/dependency manifests or CI workflows were visible, reducing code-execution surface in this specific repository.
- Payment credentials are not stored in the repository; public pages contain only Stripe-hosted checkout URLs.

## Not observed in this sample repository

No `AGENTS.md`, `CLAUDE.md`, `.cursorrules`, `.cursor/`, `.claude/`, GitHub Actions workflow, package manifest, MCP config, Dockerfile, or similar agent/runtime surface was visible in the reviewed tree.

For a real customer repository, those surfaces are the core of the audit and are analyzed as untrusted evidence rather than executed.

## Limitations

This sample repository is intentionally simple and is not representative of a complex AI-assisted codebase. The audit did not inspect private account settings, developer machines, secrets stores, production infrastructure, runtime traffic, or third-party account configuration.

## What a customer report adds

For an AI-assisted codebase, the same method produces repository-specific findings around:

- persistent agent/rules files;
- MCP/server/tool authority;
- credential exposure paths;
- CI/CD agent permissions;
- dependency and install surfaces;
- deployment and irreversible actions;
- recovery/version-control gaps;
- concrete remediation priorities.
