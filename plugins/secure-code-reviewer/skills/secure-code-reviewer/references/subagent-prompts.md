# Subagent Prompts

Use these prompts only after the user chooses the subagent approach. Give each subagent the project path, the initial report if available, and its focused task. Tell every subagent not to print full secret values.

## Dependency Security Subagent

```text
Use $secure-code-reviewer to review dependency security for this project. Focus on package manifests, lockfiles, audit/outdated output, risky package scripts, deprecated packages, and safe patch/minor updates. Do not modify files. Flag major upgrades and lockfile rewrites as requiring approval. Return findings in the Security Review Report table format.
```

## Frontend Security Subagent

```text
Use $secure-code-reviewer to review frontend security. Focus on Angular, Ionic Angular, React, Vite, API services, auth services, interceptors, route guards, environment files, XSS risks, sanitizer bypasses, token storage, insecure API URLs, and frontend-only admin checks. Do not modify files. Return findings with severity, impact, recommended fixes, and breaking risk.
```

## Backend Security Subagent

```text
Use $secure-code-reviewer to review backend security. Focus on Express/NestJS auth, JWT configuration, middleware, CORS, Helmet, rate limiting, validation, SQL/command injection, file uploads, password handling, and sensitive logging. Do not modify files. Return findings with severity, impact, recommended fixes, and breaking risk.
```

## Secrets And Config Subagent

```text
Use $secure-code-reviewer to review secrets and configuration. Focus on hardcoded secrets, .env files, environment examples, API keys, JWT secrets, private keys, production config leaks, and config separation. Never print full secret values. Do not modify files. Return masked findings and approval-required remediation steps.
```

## Test And Regression Subagent

```text
Use $secure-code-reviewer to identify safe validation commands and regression risks. Focus on build, test, lint, typecheck, start commands, affected workflows, manual checks, and rollback ideas for proposed fixes. Do not modify files. Return a test plan grouped by fix risk.
```
