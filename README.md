# Secure Code Reviewer

A Codex plugin and skill for conservative security review and safe dependency maintenance across Node.js, Angular, Ionic Angular, React/Vite, Express, NestJS, and monorepo-style JavaScript/TypeScript projects.

Use this repository when you want Codex to audit a JavaScript or TypeScript project before changing it. The skill is designed for client-facing or internal engineering reports: it detects the project shape, runs a read-only static review, summarizes package risk, separates safe fixes from approval-gated work, and asks before implementing anything.

## What It Does

- Detects project type, package manager, frameworks, monorepo shape, and available test/build commands.
- Performs a read-only security scan before any code changes.
- Reviews package vulnerabilities, outdated dependencies, risky package scripts, unsafe frontend/backend patterns, secrets, auth/token risks, CORS, JWT, upload, logging, SQL injection, and command injection risks.
- Produces a professional table-based security report and fix plan.
- Asks for approval before making changes.
- Supports inline and subagent-style review/fix workflows.

## Codex Plugin Install

Add this repository as a Codex plugin marketplace:

```bash
codex plugin marketplace add abhayjaniit/secure-code-reviewer
```

Then install the plugin from the marketplace name declared in `.agents/plugins/marketplace.json`:

```bash
codex plugin add secure-code-reviewer@secure-code-reviewer-marketplace
```

Restart Codex or open a new thread after installation so the new skill metadata is loaded.

## Direct Skill Install

Codex also supports installing skills directly from GitHub through `$skill-installer`:

```text
Use $skill-installer to install https://github.com/abhayjaniit/secure-code-reviewer/tree/main/plugins/secure-code-reviewer/skills/secure-code-reviewer
```

Restart Codex after installation.

## About `skill add`

`skill add` or `npx skill add` is not the Codex-native install command for this GitHub-hosted skill/plugin. For Codex, use one of these:

- Plugin marketplace install: `codex plugin marketplace add abhayjaniit/secure-code-reviewer`, then `codex plugin add secure-code-reviewer@secure-code-reviewer-marketplace`
- Direct skill install via `$skill-installer` and the GitHub skill path above

If you want an npm-based installer later, publish a separate npm package with a bin command such as:

```bash
npx @abhayjaniit/secure-code-reviewer add
```

That would be an additional npm distribution layer, not required for Codex plugin or skill installation.

## What The Skill Reviews

- Project detection: npm, pnpm, yarn, Angular, Ionic Angular, React, Vite, Express, NestJS, Capacitor, frontend/backend layout, monorepos, and test/build scripts.
- Dependencies: audit output, outdated packages, deprecated packages, risky lifecycle scripts, Angular/Ionic/Capacitor version skew, and major-upgrade risk.
- Frontend security: XSS patterns, Angular sanitizer bypasses, token storage, route guards, frontend-only admin checks, environment files, and API URL handling.
- Backend security: CORS, Helmet/security headers, rate limiting, JWT secrets, auth middleware, password handling, SQL injection, command injection, file uploads, and sensitive logging.
- Secrets/config: hardcoded API keys, exposed JWT secrets, passwords, tokens, private keys, and unsafe environment configuration.

## Usage

From inside a project, ask Codex:

```text
Use $secure-code-reviewer to review this project for security risks.
```

For dependency-focused work:

```text
Use $secure-code-reviewer to review package vulnerabilities and plan safe dependency updates.
```

## Read-Only Scanner

The skill includes a deterministic scanner:

```bash
python plugins/secure-code-reviewer/skills/secure-code-reviewer/scripts/security_scan.py . --format markdown --output security-review.md
```

Optional package-manager JSON can be supplied after running safe read-only commands:

```bash
npm audit --json > audit.json
npm outdated --json > outdated.json
python plugins/secure-code-reviewer/skills/secure-code-reviewer/scripts/security_scan.py . --audit-json audit.json --outdated-json outdated.json
```

Do not run forced fixes, major upgrades, or lockfile rewrites until the report and plan are approved.

## Report Shape

The first pass produces:

- Project Summary
- Issues Found
- Package Update Review
- Safe Fixes Available
- Fixes Requiring Approval
- Recommended Fix Plan

After approved fixes, the skill produces a Security Fix Completion Report with files changed, checks run, remaining issues, manual verification steps, and a recommended next step.

## Repository Layout

```text
.agents/plugins/marketplace.json
plugins/secure-code-reviewer/
  .codex-plugin/plugin.json
  INSTALL.md
  skills/secure-code-reviewer/
    SKILL.md
    agents/openai.yaml
    references/report-format.md
    references/security-review-checklist.md
    references/subagent-prompts.md
    scripts/security_scan.py
```

## Safety Model

The first run is read-only. The skill reports all findings, classifies severity, explains impact, suggests fixes, and asks whether to continue before making any changes.

The skill must not expose full secrets, run forced package updates, delete user code, rewrite project structure, change production config, or make framework major upgrades without explicit approval.
