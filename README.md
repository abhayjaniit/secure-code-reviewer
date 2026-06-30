# Secure Code Reviewer

Secure Code Reviewer is a Codex plugin for reviewing JavaScript and TypeScript projects before making security-related changes.

It is designed for Node.js, Angular, Ionic Angular, React/Vite, Express, NestJS, and full-stack or monorepo projects.

## Install In The Codex App

1. Open the Codex app.
2. Open **Plugins**.
3. Choose the option to add a plugin from a GitHub repository.
4. Paste this repository URL:

```text
https://github.com/abhayjaniit/secure-code-reviewer
```

5. Install or enable **Secure Code Reviewer**.
6. Start a new Codex thread so the plugin is loaded.

## Use The Plugin

Open the project you want to review in Codex, then ask:

```text
Use $secure-code-reviewer to review this project for security risks.
```

For dependency-focused review:

```text
Use $secure-code-reviewer to review package vulnerabilities and plan safe dependency updates.
```

For a full-stack project:

```text
Use $secure-code-reviewer to review this frontend/backend project and create a safe fix plan.
```

## What To Expect

The first review is read-only. The plugin reports issues, explains impact, recommends fixes, and asks before making code changes.

It checks for:

- vulnerable or outdated packages
- risky package scripts
- hardcoded secrets
- unsafe frontend patterns
- auth and token handling risks
- API connection risks
- CORS, JWT, upload, logging, SQL injection, and command injection risks
- unsafe or high-risk dependency upgrades

After the report, you can choose whether Codex should continue with fixes.
