#!/usr/bin/env python3
"""
Static AI-agent repository hardening scanner.

Evidence-only: this tool never executes target repository code, installs
dependencies, reads environment credentials, or prints suspected secret values.
"""
from __future__ import annotations

import argparse
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

MAX_FILE_BYTES = 2 * 1024 * 1024
TEXT_SUFFIXES = {
    ".md", ".txt", ".json", ".jsonc", ".yaml", ".yml", ".toml",
    ".ini", ".cfg", ".conf", ".env", ".ps1", ".sh", ".py", ".js",
    ".mjs", ".cjs", ".ts", ".tsx", ".jsx",
}
SELF_FILES = {"agent_hardening_check.py", "test_agent_hardening_check.py"}
SKIP_DIRS = {
    ".git", "node_modules", ".venv", "venv", "__pycache__", "dist",
    "build", "target", ".next", ".cache",
}

AGENT_SURFACES = {
    "AGENTS.md",
    "CLAUDE.md",
    ".cursorrules",
    ".github/copilot-instructions.md",
    ".windsurfrules",
    ".aider.conf.yml",
    ".aider.conf.yaml",
}
MCP_NAMES = {
    "mcp.json",
    ".mcp.json",
    "mcp-config.json",
    "mcp.config.json",
}
SECRET_PATTERNS = {
    "private-key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "github-token": re.compile(r"\b(?:ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"),
    "aws-access-key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "stripe-secret-key": re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{12,}\b"),
}
AUTHORITY_PATTERNS = {
    "agent-permission-bypass": re.compile(r"dangerously[-_]skip[-_]permissions|--dangerously-skip-permissions", re.I),
    "workflow-write-all": re.compile(r"(?m)^\s*permissions\s*:\s*write-all\s*$", re.I),
    "pull-request-target": re.compile(r"(?m)^\s*pull_request_target\s*:", re.I),
}


@dataclass(frozen=True)
class Finding:
    severity: str
    kind: str
    path: str
    line: int | None
    evidence: str
    recommendation: str


def rel(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def iter_files(root: Path) -> Iterable[Path]:
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if path.name in SELF_FILES:
            continue
        parts = set(path.relative_to(root).parts)
        if parts & SKIP_DIRS:
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        yield path


def read_text(path: Path) -> str | None:
    if path.suffix.lower() not in TEXT_SUFFIXES and path.name not in AGENT_SURFACES and path.name not in MCP_NAMES:
        return None
    try:
        return path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return None


def line_number(text: str, start: int) -> int:
    return text.count("\n", 0, start) + 1


def scan(root: Path) -> dict:
    root = root.resolve()
    findings: list[Finding] = []
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

    for path in iter_files(root):
        rp = rel(root, path)
        if rp in AGENT_SURFACES or path.name in AGENT_SURFACES or ".cursor/" in rp or ".claude/" in rp:
            inventory["agent_instruction_files"].append(rp)
        if path.name in MCP_NAMES or "mcp" in path.name.lower() and path.suffix.lower() in {".json", ".jsonc", ".yaml", ".yml", ".toml"}:
            inventory["mcp_config_files"].append(rp)
        if rp.startswith(".github/workflows/") and path.suffix.lower() in {".yml", ".yaml"}:
            inventory["workflow_files"].append(rp)
        if path.name in manifests:
            inventory["dependency_manifests"].append(rp)

        text = read_text(path)
        if text is None:
            continue

        for kind, pattern in SECRET_PATTERNS.items():
            match = pattern.search(text)
            if match:
                findings.append(Finding(
                    "high", kind, rp, line_number(text, match.start()),
                    "A credential/private-key pattern is present in tracked text. The value is intentionally not displayed.",
                    "Remove the credential from version control, rotate it if real, and use a scoped secret store.",
                ))

        for kind, pattern in AUTHORITY_PATTERNS.items():
            for match in pattern.finditer(text):
                severity = "high" if kind == "agent-permission-bypass" else "medium"
                recommendation = {
                    "agent-permission-bypass": "Avoid permission-bypass modes by default; use explicit bounded tool authority.",
                    "workflow-write-all": "Replace write-all with the minimum GitHub Actions permissions required by the job.",
                    "pull-request-target": "Review pull_request_target carefully; never execute untrusted PR code with elevated secrets/tokens.",
                }[kind]
                findings.append(Finding(
                    severity, kind, rp, line_number(text, match.start()),
                    f"Static configuration signal detected: {kind}.",
                    recommendation,
                ))

    for key in inventory:
        inventory[key] = sorted(set(inventory[key]))

    findings.sort(key=lambda x: ({"high": 0, "medium": 1, "low": 2}.get(x.severity, 9), x.path, x.line or 0))
    return {
        "schema_version": 1,
        "target": str(root),
        "execution": "static-evidence-only",
        "inventory": inventory,
        "findings": [asdict(f) for f in findings],
        "summary": {
            "high": sum(f.severity == "high" for f in findings),
            "medium": sum(f.severity == "medium" for f in findings),
            "low": sum(f.severity == "low" for f in findings),
            "total": len(findings),
        },
        "limitations": [
            "No target code was executed and no dependencies were installed.",
            "Pattern matches are review signals, not proof of exploitability or compromise.",
            "The scan does not inspect private account settings, runtime traffic, developer machines, or external secret stores.",
        ],
    }


def markdown(report: dict) -> str:
    s = report["summary"]
    lines = [
        "# AI Agent Repository Hardening Scan",
        "",
        f"**Target:** `{report['target']}`",
        "",
        f"**Findings:** {s['high']} high, {s['medium']} medium, {s['low']} low ({s['total']} total)",
        "",
        "## Inventory",
    ]
    inv = report["inventory"]
    for key, values in inv.items():
        label = key.replace("_", " ").title()
        lines.append(f"- **{label}:** {len(values)}")
        for value in values[:20]:
            lines.append(f"  - `{value}`")
        if len(values) > 20:
            lines.append(f"  - … {len(values)-20} more")
    lines += ["", "## Findings"]
    if not report["findings"]:
        lines.append("No configured static patterns matched. This is not a security certification.")
    for f in report["findings"]:
        loc = f"`{f['path']}`" + (f":{f['line']}" if f["line"] else "")
        lines += [
            "",
            f"### {f['severity'].upper()} - {f['kind']}",
            f"- **Location:** {loc}",
            f"- **Evidence:** {f['evidence']}",
            f"- **Recommendation:** {f['recommendation']}",
        ]
    lines += ["", "## Limitations"]
    lines += [f"- {x}" for x in report["limitations"]]
    lines += [
        "",
        "---",
        "For a human-reviewed, evidence-backed public-repository audit:",
        "https://ossabellator.github.io/ai-agent-hardening/audit.html",
    ]
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Static AI-agent repository hardening scanner")
    parser.add_argument("path", nargs="?", default=".", help="Repository directory")
    parser.add_argument("--format", choices=("json", "markdown"), default="markdown")
    args = parser.parse_args()
    root = Path(args.path)
    if not root.is_dir():
        parser.error("path must be a directory")
    report = scan(root)
    print(json.dumps(report, indent=2) if args.format == "json" else markdown(report), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
