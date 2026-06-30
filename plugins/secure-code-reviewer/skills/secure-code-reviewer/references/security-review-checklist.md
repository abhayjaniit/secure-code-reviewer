# Security Review Checklist

Use this checklist after the scanner output and before finalizing the report. Prefer evidence from files and commands over assumptions.

## Project Detection

- Package manager: `package-lock.json` means npm, `pnpm-lock.yaml` means pnpm, `yarn.lock` means yarn; confirm with `packageManager` when present.
- Frameworks: detect Angular, Ionic Angular, React, Vite, Express, NestJS, Capacitor, and monorepo tooling such as workspaces, Nx, Turbo, Lerna, `apps/`, `packages/`, `frontend/`, and `backend/`.
- Commands: record available `test`, `build`, `lint`, `typecheck`, `e2e`, and backend start scripts.

## Dependency Review

- Parse audit output before suggesting package changes.
- Prefer patch/minor security fixes when compatible with the lockfile.
- Mark major framework upgrades, Angular/Ionic/Capacitor version jumps, Node engine changes, and lockfile rewrites as `Requires approval`.
- Flag deprecated or abandoned packages such as `request`, `node-sass`, `gulp-util`, `bower`, `protractor`, `tslint`, and `@angular/http`.
- Review lifecycle scripts (`preinstall`, `install`, `postinstall`, `prepare`) and scripts containing `curl`, `wget`, `powershell`, `Invoke-WebRequest`, `iex`, `rm -rf`, `sudo`, `eval`, `node -e`, `bash -c`, or `sh -c`.

## Frontend Review

- XSS: `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `dangerouslySetInnerHTML`, and unsanitized template rendering.
- Angular sanitizer bypass: every `DomSanitizer.bypassSecurityTrust*` call needs a narrow justification and trusted input source.
- Token storage: localStorage/sessionStorage token storage is usually medium risk; prefer httpOnly secure cookies where feasible.
- Auth routing: admin or protected pages need backend authorization and appropriate route guards. Frontend-only role checks are not sufficient.
- API handling: avoid production `http://` URLs, hardcoded API hosts, missing auth header handling, and weak 401/403 behavior.
- Ionic/Capacitor: confirm plugin versions are aligned and native APIs are not exposing secrets in logs or storage.

## Backend Review

- CORS: avoid wildcard origins, `origin: true`, and credentialed broad origins in production.
- Headers: Express/NestJS APIs should usually use Helmet or equivalent security headers.
- Rate limiting: public auth, upload, password reset, and write endpoints should have rate limiting or throttling.
- Auth/JWT: secrets must come from environment/secret manager, be strong, and never be logged. Stop before changing auth flow.
- Passwords: use mature hashing such as bcrypt, argon2, or scrypt; never compare or store plaintext passwords.
- Injection: parameterize SQL/ORM queries; review string concatenation or template literals in database calls.
- Command execution: avoid `exec`, `execSync`, and shell commands built from request data.
- Uploads: require file size limits, content type validation, extension checks, storage isolation, and malware scanning when applicable.
- Logging: redact passwords, tokens, cookies, authorization headers, JWTs, API keys, reset links, and PII.

## Severity Heuristics

| Severity | Use For |
| --- | --- |
| Critical | Active secret exposure, auth bypass, remote code execution, command injection, high-confidence SQL injection, public production credentials. |
| High | JWT secret weaknesses, broad production CORS with credentials, unsafe uploads, vulnerable direct dependencies with known exploitability, plaintext password handling. |
| Medium | XSS-prone frontend patterns, token storage risks, missing backend hardening, risky lifecycle scripts, insecure API URL handling. |
| Low | Deprecated packages, version skew, minor hardening gaps, incomplete examples. |
| Info | Observations, skipped checks, or manual review reminders. |

## Fix Safety

- Safe: local validation, redaction, headers with low compatibility risk, patch version updates, test-only improvements.
- Low: minor dependency updates, focused config hardening, route guard additions where backend authorization already exists.
- Medium: middleware ordering changes, auth interceptor changes, storage migration, upload validation changes.
- High: database query rewrites, broad dependency upgrades, CORS/auth changes affecting production clients.
- Requires approval: secret rotation, major upgrades, production environment changes, auth flow changes, data model changes.
