#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path

IGNORED_DIRS = {".git", "node_modules", "dist", "build", "coverage", "logs", "__pycache__"}
INSTRUCTION_NAMES = {
    "AGENTS.md",
    "CLAUDE.md",
    "GEMINI.md",
    "KIMI.md",
    "COPILOT.md",
    ".cursorrules",
    ".windsurfrules",
}
SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2, "none": 99}
SECRET_PATTERNS = (
    re.compile(r"sk-[A-Za-z0-9_-]{20,}"),
    re.compile(r"ghp_[A-Za-z0-9_]{20,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{20,}"),
    re.compile(r"-----BEGIN (RSA|OPENSSH|EC|DSA) PRIVATE KEY-----"),
)
SECRET_ACTION = re.compile(r"\b(print|echo|show|display|commit|upload|send|exfiltrate)\b.{0,80}\b(secrets?|tokens?|passwords?|api keys?|private keys?|cookies?)\b", re.I)
DESTRUCTIVE = re.compile(r"\brm\s+-(?:[a-z]*f[a-z]*r|[a-z]*r[a-z]*f)\b|\brm\s+-rf\b|\brm\s+-fr\b", re.I)
NETWORK_TERMS = ("curl", "wget", "scp", "sftp", "rsync", "Invoke-WebRequest")
MACHINE_PATHS = (
    re.compile("/" + "Users" + r"/[^/\s]+"),
    re.compile("/" + "home" + r"/[^/\s]+"),
    re.compile(r"[A-Za-z]:\\" + "Users" + r"\\[^\\\s]+"),
)
OVERWRITE_WITHOUT_INTENT = re.compile(r"\b(always|automatically|by default)\b.{0,80}\b(overwrite|replace|rewrite|modify files|edit files)\b", re.I)
SAFETY_PHRASES = (
    ("local-only behavior", ("local-only", "no network requests", "do not send")),
    ("no telemetry", ("no telemetry", "no analytics", "no tracking")),
    ("secret handling", ("do not expose secrets", "never share secrets", "do not print secrets", "rotate")),
)


@dataclass(frozen=True)
class Finding:
    severity: str
    path: str
    message: str


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    root = Path(args.path).expanduser().resolve()
    findings = scan(root)
    print_report(findings)
    threshold = SEVERITY_RANK[args.fail_on]
    return 1 if any(SEVERITY_RANK[item.severity] <= threshold for item in findings) else 0


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Audit AI coding-agent instruction files.")
    parser.add_argument("path", nargs="?", default=".")
    parser.add_argument("--fail-on", choices=sorted(SEVERITY_RANK), default="high")
    return parser.parse_args(argv)


def scan(root: Path) -> list[Finding]:
    if not root.exists():
        return [Finding("high", root.as_posix(), "path does not exist")]
    findings: list[Finding] = []
    files = candidate_files(root)
    if not files:
        return [Finding("low", display(root, root), "no agent instruction files found")]
    for path in files:
        findings.extend(audit_file(root, path))
    return sorted(findings, key=lambda item: (SEVERITY_RANK[item.severity], item.path, item.message))


def candidate_files(root: Path) -> list[Path]:
    if root.is_file():
        return [root] if is_instruction_file(root) else []
    files: list[Path] = []
    for current, dirnames, filenames in os.walk(root):
        dirnames[:] = [name for name in dirnames if name not in IGNORED_DIRS]
        for filename in filenames:
            path = Path(current) / filename
            if is_instruction_file(path):
                files.append(path)
    return sorted(files)


def is_instruction_file(path: Path) -> bool:
    return path.name in INSTRUCTION_NAMES or path.name.endswith(".mdc")


def audit_file(root: Path, path: Path) -> list[Finding]:
    relative = display(root, path)
    text = path.read_text(encoding="utf-8", errors="replace")
    lowered = text.lower()
    findings: list[Finding] = []

    for pattern in SECRET_PATTERNS:
        if pattern.search(text):
            findings.append(Finding("high", relative, "secret-shaped value found"))
    if SECRET_ACTION.search(text):
        findings.append(Finding("high", relative, "instruction may expose or transmit secrets"))
    if DESTRUCTIVE.search(text):
        findings.append(Finding("high", relative, "destructive recursive shell command found"))
    if any(term in text for term in NETWORK_TERMS):
        findings.append(Finding("medium", relative, "network transfer command appears in instructions"))
    if any(pattern.search(text) for pattern in MACHINE_PATHS):
        findings.append(Finding("medium", relative, "machine-specific path found"))
    if OVERWRITE_WITHOUT_INTENT.search(text):
        findings.append(Finding("medium", relative, "instruction suggests file overwrite without explicit user intent"))

    for label, choices in SAFETY_PHRASES:
        if not any(choice in lowered for choice in choices):
            findings.append(Finding("low", relative, f"missing safety language: {label}"))
    return findings


def display(root: Path, target: Path) -> str:
    try:
        return target.relative_to(root).as_posix()
    except ValueError:
        return target.as_posix()


def print_report(findings: list[Finding]) -> None:
    if not findings:
        print("agentsmd-action: no findings")
        return
    print(f"agentsmd-action: {len(findings)} finding(s)")
    for finding in findings:
        print(f"- {finding.severity}: {finding.path}: {finding.message}")


if __name__ == "__main__":
    raise SystemExit(main())
