# Secure Code Reviewer Installation

This folder is a local Codex plugin. It contains one skill named `secure-code-reviewer`.

## Option 1: Use As A Skill Folder

Copy or sync `skills/secure-code-reviewer` into your Codex skills directory:

```powershell
Copy-Item -Recurse -Force .\skills\secure-code-reviewer "$env:USERPROFILE\.codex\skills\secure-code-reviewer"
```

Restart Codex, then invoke:

```text
Use $secure-code-reviewer to review this project for security risks.
```

## Option 2: Use As A Local Plugin

Copy or sync this whole `secure-code-reviewer` folder into your local plugin directory, then add it through your personal or team marketplace workflow.

The plugin manifest is at:

```text
.codex-plugin/plugin.json
```

## Scanner Usage

From a project root, run:

```powershell
python path\to\secure-code-reviewer\skills\secure-code-reviewer\scripts\security_scan.py . --format markdown --output security-review.md
```

Optional read-only package data:

```powershell
npm audit --json > audit.json
npm outdated --json > outdated.json
python path\to\security_scan.py . --audit-json audit.json --outdated-json outdated.json
```

Do not run `npm audit fix --force`, forced upgrades, lockfile rewrites, or major framework updates until the report and plan are approved.
