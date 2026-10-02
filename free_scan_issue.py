#!/usr/bin/env python3
"""
Generate a bounded static scan comment for a public GitHub repository named in
an issue body. This fetches repository metadata/tree/blob contents through the
GitHub API; it does not clone or execute target repository code.
"""
from __future__ import annotations

import base64
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict
from typing import Any

from agent_hardening_check import (
    AGENT_SURFACES,
    AUTHORITY_PATTERNS,
    MCP_NAMES,
    SECRET_PATTERNS,
    SELF_FILES,
    TEXT_SUFFIXES,
    Finding,
    line_number,
)

MAX_REPO_KB = 25_000
MAX_FILES = 60
MAX_FILE_BYTES = 256 * 1024
MAX_FINDINGS = 20
MAX_INVENTORY_ITEMS = 20
USER_AGENT = "ai-agent-hardening-free-scan/1"

REPO_URL = re.compile(
    r"https://github\.com/(?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+?)(?:\.git)?(?:[/?#\s]|$)",
    re.I,
)


def api_get(path: str, token: str | None) -> dict[str, Any]:
    req = urllib.request.Request(
        "https://api.github.com" + path,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": USER_AGENT,
            **({"Authorization": f"Bearer {token}"} if token else {}),
        },
    )
    with urllib.request.urlopen(req, timeout=15) as response:
        return json.loads(response.read().decode("utf-8"))


def extract_repo(body: str) -> tuple[str, str]:
    match = REPO_URL.search(body or "")
    if not match:
        raise ValueError("No public GitHub repository URL was found in the issue body.")
    return match.group("owner"), match.group("repo")


def is_candidate(path: str) -> bool:
    p = path.replace("\\", "/")
    name = p.rsplit("/", 1)[-1]
    if name in SELF_FILES:
        return False
    suffix = "." + name.rsplit(".", 1)[-1].lower() if "." in name else ""
    return (
        p in AGENT_SURFACES
        or name in AGENT_SURFACES
        or ".cursor/" in p
        or ".claude/" in p
        or name in MCP_NAMES
        or ("mcp" in name.lower() and suffix in {".json", ".jsonc", ".yaml", ".yml", ".toml"})
        or p.startswith(".github/workflows/")
        or name in {
            "package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock",
            "pyproject.toml", "requirements.txt", "poetry.lock", "Cargo.toml",
            "Cargo.lock", "go.mod", "go.sum", ".env", ".env.example",
        }
        or suffix in TEXT_SUFFIXES
    )


def markdown_path(path: str) -> str:
    """Make an untrusted Git path safe inside inline-code Markdown."""
    return path.replace("\r", " ").replace("\n", " ").replace("\t", " ").replace("`", "ˋ")


def priority(path: str) -> tuple[int, str]:
    p = path.replace("\\", "/")
    name = p.rsplit("/", 1)[-1]
    if p in AGENT_SURFACES or name in AGENT_SURFACES or ".cursor/" in p or ".claude/" in p:
        return (0, p)
    if name in MCP_NAMES or "mcp" in name.lower():
        return (1, p)
    if p.startswith(".github/workflows/"):
        return (2, p)
    if name in {
        "package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock",
        "pyproject.toml", "requirements.txt", "poetry.lock", "Cargo.toml",
        "Cargo.lock", "go.mod", "go.sum", ".env", ".env.example",
    }:
        return (3, p)
    return (4, p)


def scan_public_repo(owner: str, repo: str, token: str | None) -> dict[str, Any]:
    meta = api_get(f"/repos/{owner}/{repo}", token)
    if meta.get("private"):
        raise ValueError("The repository is private. Free scans are limited to public GitHub repositories.")
    if int(meta.get("size") or 0) > MAX_REPO_KB:
        raise ValueError(f"The repository is larger than the free-scan limit ({MAX_REPO_KB // 1000} MB reported GitHub size).")

    default_branch = str(meta.get("default_branch") or "main")
    ref = api_get(
        f"/repos/{owner}/{repo}/git/ref/heads/{urllib.parse.quote(default_branch, safe='')}",
        token,
    )
    commit_sha = ref["object"]["sha"]
    commit = api_get(f"/repos/{owner}/{repo}/git/commits/{commit_sha}", token)
    tree_sha = commit["tree"]["sha"]
    tree = api_get(f"/repos/{owner}/{repo}/git/trees/{tree_sha}?recursive=1", token)
    if tree.get("truncated"):
        raise ValueError("GitHub truncated the repository tree; the free scanner will not claim a partial tree is complete.")

    blobs = [
        item for item in tree.get("tree", [])
        if item.get("type") == "blob"
        and isinstance(item.get("path"), str)
        and int(item.get("size") or 0) <= MAX_FILE_BYTES
        and is_candidate(item["path"])
    ]
    blobs.sort(key=lambda item: priority(item["path"]))
    selected = blobs[:MAX_FILES]

    inventory = {
        "agent_instruction_files": [],
        "mcp_config_files": [],
        "workflow_files": [],
        "dependency_manifests": [],
    }
    manifests = {
        "package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock",
        "pyproject.toml", "requirements.txt", "poetry.lock", "Cargo.toml",
        "Cargo.lock", "go.mod", "go.sum",
    }
    findings: list[Finding] = []

    for item in selected:
        path = item["path"].replace("\\", "/")
        name = path.rsplit("/", 1)[-1]
        if path in AGENT_SURFACES or name in AGENT_SURFACES or ".cursor/" in path or ".claude/" in path:
            inventory["agent_instruction_files"].append(path)
        if name in MCP_NAMES or ("mcp" in name.lower() and any(name.lower().endswith(x) for x in (".json", ".jsonc", ".yaml", ".yml", ".toml"))):
            inventory["mcp_config_files"].append(path)
        if path.startswith(".github/workflows/") and path.lower().endswith((".yml", ".yaml")):
            inventory["workflow_files"].append(path)
        if name in manifests:
            inventory["dependency_manifests"].append(path)

        blob = api_get(f"/repos/{owner}/{repo}/git/blobs/{item['sha']}", token)
        if blob.get("encoding") != "base64":
            continue
        try:
            raw = base64.b64decode(blob.get("content", ""), validate=False)
            text = raw.decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue

        for kind, pattern in SECRET_PATTERNS.items():
            match = pattern.search(text)
            if match and len(findings) < MAX_FINDINGS:
                findings.append(Finding(
                    "high", kind, path, line_number(text, match.start()),
                    "A credential/private-key pattern is present in tracked text. The value is intentionally not displayed.",
                    "Remove the credential from version control, rotate it if real, and use a scoped secret store.",
                ))
        for kind, pattern in AUTHORITY_PATTERNS.items():
            for match in pattern.finditer(text):
                if len(findings) >= MAX_FINDINGS:
                    break
                severity = "high" if kind == "agent-permission-bypass" else "medium"
                recommendation = {
                    "agent-permission-bypass": "Avoid permission-bypass modes by default; use explicit bounded tool authority.",
                    "workflow-write-all": "Replace write-all with the minimum GitHub Actions permissions required by the job.",
                    "pull-request-target": "Review pull_request_target carefully; never execute untrusted PR code with elevated secrets/tokens.",
                }[kind]
                findings.append(Finding(
                    severity, kind, path, line_number(text, match.start()),
                    f"Static configuration signal detected: {kind}.",
                    recommendation,
                ))

    for key in inventory:
        inventory[key] = sorted(set(inventory[key]))

    findings.sort(key=lambda x: ({"high": 0, "medium": 1, "low": 2}.get(x.severity, 9), x.path, x.line or 0))
    return {
        "target": f"https://github.com/{owner}/{repo}",
        "default_branch": default_branch,
        "commit_sha": commit_sha,
        "repo_size_kb": int(meta.get("size") or 0),
        "candidate_files": len(blobs),
        "files_scanned": len(selected),
        "candidate_files_omitted": max(0, len(blobs) - len(selected)),
        "inventory": inventory,
        "findings": [asdict(f) for f in findings],
        "summary": {
            "high": sum(f.severity == "high" for f in findings),
            "medium": sum(f.severity == "medium" for f in findings),
            "total": len(findings),
        },
    }


def render(report: dict[str, Any]) -> str:
    s = report["summary"]
    lines = [
        "## Free static repository scan",
        "",
        f"**Target:** {report['target']}",
        f"**Default branch commit:** `{report['commit_sha'][:12]}`",
        f"**Scanned:** {report['files_scanned']} candidate files"
        + (f" ({report['candidate_files_omitted']} additional candidate files omitted by the free-scan cap)" if report["candidate_files_omitted"] else ""),
        "",
        f"**Findings:** {s['high']} high, {s['medium']} medium ({s['total']} total)",
        "",
        "### Inventory",
    ]
    for key, values in report["inventory"].items():
        label = key.replace("_", " ").title()
        lines.append(f"- **{label}:** {len(values)}")
        for value in values[:MAX_INVENTORY_ITEMS]:
            lines.append(f"  - `{markdown_path(value)}`")
        if len(values) > MAX_INVENTORY_ITEMS:
            lines.append(f"  - … {len(values) - MAX_INVENTORY_ITEMS} more")

    lines += ["", "### Findings"]
    if not report["findings"]:
        lines.append("No configured static patterns matched in the bounded scan. This does **not** mean the repository is secure.")
    for finding in report["findings"]:
        loc = f"`{markdown_path(finding['path'])}`" + (f":{finding['line']}" if finding["line"] else "")
        lines += [
            "",
            f"**{finding['severity'].upper()} — {finding['kind']}**",
            f"- Location: {loc}",
            f"- Evidence: {finding['evidence']}",
            f"- Recommendation: {finding['recommendation']}",
        ]

    lines += [
        "",
        "### Limits",
        "- Static public-repository evidence only; requester code was not executed and dependencies were not installed.",
        f"- Files larger than {MAX_FILE_BYTES // 1024} KiB are skipped and at most {MAX_FILES} candidate files are fetched.",
        "- Pattern matches are review signals, not proof of exploitability or compromise.",
        "- No suspected credential value is printed.",
        "",
        "**Need contextual review?** The A$39 human-reviewed public-repository audit adds evidence interpretation and prioritized remediation. The free scan above remains yours whether or not you buy anything.",
        "",
        "- Audit details and sample report: https://ossabellator.github.io/ai-agent-hardening/audit.html",
        "- Buy the A$39 audit: https://buy.stripe.com/eVq14h2jW92678b63T04802",
    ]
    return "\n".join(lines) + "\n"


def error_comment(message: str) -> str:
    return (
        "## Free static repository scan\n\n"
        f"I could not run the bounded scan: {message}\n\n"
        "Free scans require a public GitHub repository URL and intentionally avoid private access or target-code execution.\n"
    )


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: free_scan_issue.py <github-event-json>", file=sys.stderr)
        return 2
    try:
        event = json.loads(open(sys.argv[1], "r", encoding="utf-8").read())
        body = str(event.get("issue", {}).get("body") or "")
        owner, repo = extract_repo(body)
        report = scan_public_repo(owner, repo, os.environ.get("GITHUB_TOKEN"))
        sys.stdout.write(render(report))
        return 0
    except (ValueError, KeyError, urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as exc:
        sys.stdout.write(error_comment(str(exc)))
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
