---
name: secure-code-reviewer
description: Use when reviewing Node.js, Angular, Ionic Angular, React/Vite, Express, NestJS, or JavaScript/TypeScript monorepo projects for security risks, hardcoded secrets, auth/token issues, unsafe frontend/backend code patterns, risky package scripts, npm/pnpm/yarn audit findings, outdated dependencies, or safe dependency maintenance.
---

# Secure Code Reviewer

## Overview

Perform a conservative security review before changing code. The first pass is read-only, produces a professional report, and asks the user to approve a safe fix plan and execution approach before implementation starts.

## Non-Negotiable Safety Rules

- Never expose full secret values; report only variable names, file paths, and masked evidence.
- Never run destructive commands, forced upgrades, dependency update commands, lockfile rewrites, file deletion, or framework major upgrades without explicit approval.
- Never begin code changes after the initial report. Ask the user to approve the plan and choose an execution approach first.
- Preserve existing behavior, routes, pages, auth flows, mock data, environment separation, and project structure unless the user approves a specific security change.
- Stop and ask before changing auth flow, production environment config, data persistence, package major versions, or anything marked `High` or `Requires approval`.

## Workflow

1. Detect the project type from `package.json`, lockfiles, `angular.json`, `ionic.config.json`, `vite.config.*`, `nest-cli.json`, backend entrypoints, `src/environments/*`, and frontend/backend folder names.
2. Run a read-only scan. Prefer the bundled helper:

```bash
python skills/secure-code-reviewer/scripts/security_scan.py <project-root> --format markdown
```

3. Optionally run safe package-manager inspection commands when available. Capture JSON to files and pass them to the scanner; do not run update/fix commands.

```bash
npm audit --json
npm outdated --json
pnpm audit --json
pnpm outdated --format json
yarn npm audit --json
```

4. Manually review important files after the helper scan: package manifests, lockfiles, Angular/Ionic services, API clients, auth services, HTTP interceptors, route guards, environment files, backend auth/middleware/CORS/upload/database/logging code, and risky scripts.
5. Produce a report before changes. Read `references/report-format.md` and use the required tables.
6. Create a safe incremental fix plan. Each step must include what changes, why, files affected, tests, rollback idea, and risk level.
7. Ask: "Do you want me to start fixing these issues?" Then ask: "Which approach do you prefer: inline approach or subagent approach?"
8. Implement only after approval. Start with safe fixes, test after each logical group, and stop before high-risk work.
9. After approved fixes, produce the completion report from `references/report-format.md`.

## Read-Only Scanner

Use `scripts/security_scan.py` for deterministic discovery and static checks. The script:

- Detects npm, pnpm, yarn, frameworks, monorepo structure, frontend/backend shape, and test/build scripts.
- Scans source for hardcoded secrets, unsafe DOM APIs, sanitizer bypasses, token storage risks, insecure API URLs, CORS risks, weak JWT handling, SQL/command injection patterns, unsafe uploads, sensitive logging, risky package scripts, deprecated dependencies, and Angular/Ionic/Capacitor version mismatches.
- Parses optional audit/outdated JSON if supplied with `--audit-json` or `--outdated-json`.
- Emits Markdown or JSON and never modifies the target project.

Useful invocations:

```bash
python skills/secure-code-reviewer/scripts/security_scan.py . --format markdown --output security-review.md
python skills/secure-code-reviewer/scripts/security_scan.py . --audit-json audit.json --outdated-json outdated.json
python skills/secure-code-reviewer/scripts/security_scan.py . --format json --output security-review.json
```

## Manual Review Checklist

Read `references/security-review-checklist.md` before finalizing findings. Use it to classify severity, distinguish safe fixes from risky ones, and avoid common blind spots in Angular/Ionic/React frontends and Express/NestJS backends.

Prioritize findings in this order:

1. Exposed secrets, auth bypass, injection, unsafe uploads, production CORS/auth misconfiguration.
2. Vulnerable direct dependencies with safe patch/minor fixes.
3. Frontend XSS and token handling risks.
4. Backend hardening gaps such as Helmet, rate limiting, validation, and sensitive logging.
5. Deprecated packages, version skew, and high-risk package scripts.

## Fix Planning

Separate fixes into:

- `Safe fixes`: minimal code/config changes with low behavior risk and clear tests.
- `Requires approval`: major upgrades, auth-flow changes, production config changes, secret rotation, database/query rewrites, file upload policy changes, and anything with uncertain compatibility.

For each plan step include:

- What will change
- Why it is needed
- Files affected
- How to test
- Rollback idea
- Risk level

## Execution Approaches

When the user approves fixes, ask them to choose:

| Approach | Use When | Rules |
| --- | --- | --- |
| Inline approach | Scope is small or changes are tightly coupled. | Fix issues one by one, safest first, with tests/builds after each group. |
| Subagent approach | Project is large, monorepo-style, or has separate dependency/frontend/backend/secrets/testing tracks. | Read `references/subagent-prompts.md`, dispatch focused agents, then merge findings and fixes through the main report. |

The main agent remains responsible for final decisions, secret redaction, user approvals, and preserving behavior.

## Completion

After approved fixes, run available safe checks such as build, test, lint, typecheck, and targeted smoke checks. Report commands that could not run and why. End with the Security Fix Completion Report from `references/report-format.md` and recommend one next security improvement without continuing automatically.
