#!/usr/bin/env python3
"""Read-only security scanner for Node.js-family projects.

The scanner performs deterministic project detection and static checks. It does
not install packages, run package managers, update lockfiles, or modify files.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable


EXCLUDED_DIRS = {
    ".angular",
    ".cache",
    ".git",
    ".next",
    ".nuxt",
    ".output",
    ".turbo",
    ".vercel",
    "build",
    "coverage",
    "dist",
    "node_modules",
    "out",
    "tmp",
}

TEXT_EXTENSIONS = {
    ".cjs",
    ".conf",
    ".config",
    ".css",
    ".env",
    ".html",
    ".ini",
    ".js",
    ".json",
    ".jsx",
    ".md",
    ".mjs",
    ".ts",
    ".tsx",
    ".txt",
    ".yaml",
    ".yml",
}

MAX_FILE_BYTES = 512_000
MAX_STATIC_ISSUES = 150


@dataclass
class Issue:
    severity: str
    category: str
    location: str
    issue: str
    impact: str
    recommended_fix: str
    breaking_risk: str


@dataclass
class PackageUpdate:
    package: str
    current: str
    wanted: str
    latest: str
    severity_risk: str
    update_type: str
    suggested_action: str


def read_text(path: Path) -> str | None:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def load_json(path: Path) -> Any | None:
    text = read_text(path)
    if text is None:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def rel(root: Path, path: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def iter_files(root: Path) -> Iterable[Path]:
    for current, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDED_DIRS]
        for filename in filenames:
            yield Path(current) / filename


def iter_text_files(root: Path) -> Iterable[Path]:
    for path in iter_files(root):
        if path.suffix.lower() in TEXT_EXTENSIONS or path.name.startswith(".env"):
            yield path


def find_package_jsons(root: Path) -> list[Path]:
    return sorted(path for path in iter_files(root) if path.name == "package.json")


def dependency_map(package_data: dict[str, Any]) -> dict[str, str]:
    deps: dict[str, str] = {}
    for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        value = package_data.get(key)
        if isinstance(value, dict):
            deps.update({str(k): str(v) for k, v in value.items()})
    return deps


def detect_package_manager(root: Path, package_data: dict[str, Any]) -> str:
    package_manager = str(package_data.get("packageManager", "")).lower()
    if (root / "pnpm-lock.yaml").exists() or package_manager.startswith("pnpm"):
        return "pnpm"
    if (root / "yarn.lock").exists() or package_manager.startswith("yarn"):
        return "yarn"
    if (root / "package-lock.json").exists() or package_manager.startswith("npm"):
        return "npm"
    return "unknown"


def detect_frameworks(root: Path, all_deps: dict[str, str]) -> list[str]:
    frameworks: set[str] = set()
    if "@angular/core" in all_deps or (root / "angular.json").exists():
        frameworks.add("Angular")
    if "@ionic/angular" in all_deps or (root / "ionic.config.json").exists():
        frameworks.add("Ionic Angular")
    if "react" in all_deps:
        frameworks.add("React")
    if "vite" in all_deps or any(root.glob("vite.config.*")):
        frameworks.add("Vite")
    if "express" in all_deps:
        frameworks.add("Express")
    if "@nestjs/core" in all_deps or (root / "nest-cli.json").exists():
        frameworks.add("NestJS")
    if "@capacitor/core" in all_deps:
        frameworks.add("Capacitor")
    if "next" in all_deps:
        frameworks.add("Next.js")
    return sorted(frameworks)


def detect_project_shape(root: Path, root_package: dict[str, Any], package_jsons: list[Path], frameworks: list[str]) -> tuple[str, str]:
    monorepo_markers = [
        root / "pnpm-workspace.yaml",
        root / "nx.json",
        root / "turbo.json",
        root / "lerna.json",
    ]
    workspaces = root_package.get("workspaces")
    folder_markers = [root / "apps", root / "packages", root / "frontend", root / "backend"]
    is_monorepo = bool(workspaces) or any(path.exists() for path in monorepo_markers) or len(package_jsons) > 1
    is_monorepo = is_monorepo or any(path.exists() for path in folder_markers)

    frontend_frameworks = {"Angular", "Ionic Angular", "React", "Vite", "Next.js"}
    backend_frameworks = {"Express", "NestJS"}
    has_frontend = bool(frontend_frameworks.intersection(frameworks))
    has_backend = bool(backend_frameworks.intersection(frameworks))

    if has_frontend and has_backend:
        stack = "full-stack"
    elif has_frontend:
        stack = "frontend-only"
    elif has_backend:
        stack = "backend-only"
    else:
        stack = "nodejs/unknown"

    project_type = f"{'monorepo ' if is_monorepo else ''}{stack}".strip()
    return project_type, stack


def collect_scripts(package_jsons: list[Path], root: Path) -> dict[str, str]:
    scripts: dict[str, str] = {}
    for package_json in package_jsons:
        data = load_json(package_json)
        if not isinstance(data, dict):
            continue
        package_name = data.get("name") or rel(root, package_json.parent)
        package_scripts = data.get("scripts", {})
        if not isinstance(package_scripts, dict):
            continue
        for name, command in package_scripts.items():
            if name in {"build", "test", "test:ci", "lint", "typecheck", "e2e", "start", "start:dev"}:
                scripts[f"{package_name}:{name}"] = str(command)
    return scripts


def add_issue(issues: list[Issue], issue: Issue) -> None:
    if len(issues) < MAX_STATIC_ISSUES:
        issues.append(issue)


def scan_package_scripts(package_jsons: list[Path], root: Path, issues: list[Issue]) -> None:
    risky_terms = [
        "curl ",
        "wget ",
        "powershell",
        "invoke-webrequest",
        " iwr ",
        " iex ",
        "rm -rf",
        "sudo ",
        "chmod 777",
        "eval ",
        "node -e",
        "bash -c",
        "sh -c",
    ]
    lifecycle = {"preinstall", "install", "postinstall", "prepare"}
    for package_json in package_jsons:
        data = load_json(package_json)
        if not isinstance(data, dict):
            continue
        scripts = data.get("scripts", {})
        if not isinstance(scripts, dict):
            continue
        for name, command_value in scripts.items():
            command = str(command_value)
            lowered = f" {command.lower()} "
            if name in lifecycle and any(term in lowered for term in risky_terms):
                add_issue(
                    issues,
                    Issue(
                        "Medium",
                        "Package scripts",
                        f"{rel(root, package_json)} scripts.{name}",
                        "Lifecycle package script contains high-risk shell/network behavior.",
                        "Install-time scripts can execute before review and may create supply-chain risk.",
                        "Review the script, remove unnecessary shell/network behavior, and document any required install hook.",
                        "Requires approval",
                    ),
                )
            elif any(term in lowered for term in risky_terms):
                add_issue(
                    issues,
                    Issue(
                        "Low",
                        "Package scripts",
                        f"{rel(root, package_json)} scripts.{name}",
                        "Package script contains shell/network behavior that should be reviewed.",
                        "Risky scripts can delete files, download code, or execute commands unexpectedly.",
                        "Confirm the command is necessary and safe before running it in CI or locally.",
                        "Low",
                    ),
                )


def major(version: str) -> int | None:
    match = re.search(r"(\d+)\.", str(version))
    if not match:
        return None
    return int(match.group(1))


def scan_dependency_metadata(root: Path, package_jsons: list[Path], all_deps: dict[str, str], frameworks: list[str], issues: list[Issue]) -> None:
    deprecated = {
        "@angular/http": "Angular HTTP was removed; use HttpClient and supported Angular packages.",
        "bower": "Bower is deprecated and no longer appropriate for modern dependency management.",
        "gulp-util": "gulp-util is deprecated and split into maintained packages.",
        "node-sass": "node-sass is deprecated; use sass/dart-sass.",
        "protractor": "Protractor is deprecated; migrate E2E coverage deliberately.",
        "request": "request is deprecated; use a maintained HTTP client.",
        "tslint": "TSLint is deprecated; use ESLint tooling.",
    }
    for dep, reason in deprecated.items():
        if dep in all_deps:
            add_issue(
                issues,
                Issue(
                    "Low",
                    "Dependencies",
                    "package.json",
                    f"Deprecated or abandoned dependency detected: {dep}.",
                    reason,
                    "Plan a compatible migration and test affected code paths.",
                    "Medium",
                ),
            )

    angular_majors = {
        dep: major(version)
        for dep, version in all_deps.items()
        if dep.startswith("@angular/") and major(version) is not None
    }
    if len(set(angular_majors.values())) > 1:
        add_issue(
            issues,
            Issue(
                "Medium",
                "Dependencies",
                "package.json",
                "Angular package major versions are not aligned.",
                "Mismatched Angular majors can break builds, routing, templates, and security patch adoption.",
                "Align Angular packages through an approved framework update plan.",
                "Requires approval",
            ),
        )

    capacitor_majors = {
        dep: major(version)
        for dep, version in all_deps.items()
        if dep.startswith("@capacitor/") and major(version) is not None
    }
    if len(set(capacitor_majors.values())) > 1:
        add_issue(
            issues,
            Issue(
                "Medium",
                "Dependencies",
                "package.json",
                "Capacitor package major versions are not aligned.",
                "Version skew can break native builds and plugin behavior.",
                "Align Capacitor packages through an approved mobile update plan.",
                "Requires approval",
            ),
        )

    backend_present = bool({"Express", "NestJS"}.intersection(frameworks))
    if backend_present and "helmet" not in all_deps and "@fastify/helmet" not in all_deps:
        add_issue(
            issues,
            Issue(
                "Medium",
                "Backend hardening",
                "package.json",
                "Backend framework detected without Helmet dependency.",
                "Missing security headers can increase exposure to browser-assisted attacks.",
                "Add and configure Helmet or an equivalent security-header middleware after compatibility review.",
                "Low",
            ),
        )
    if backend_present and "express-rate-limit" not in all_deps and "@nestjs/throttler" not in all_deps:
        add_issue(
            issues,
            Issue(
                "Medium",
                "Backend hardening",
                "package.json",
                "Backend framework detected without an obvious rate-limiting dependency.",
                "Public auth and write endpoints may be easier to brute force or abuse.",
                "Add targeted rate limiting or throttling for public and sensitive endpoints.",
                "Medium",
            ),
        )


Pattern = tuple[re.Pattern[str], str, str, str, str, str, str]


def static_patterns() -> list[Pattern]:
    flags = re.IGNORECASE
    return [
        (
            re.compile(r"(api[_-]?key|secret|token|password|private[_-]?key|jwt[_-]?secret)\s*[:=]\s*['\"][^'\"\n]{8,}['\"]", flags),
            "High",
            "Secrets",
            "Possible hardcoded secret or credential.",
            "Secrets in source can be copied, logged, committed, or reused by attackers.",
            "Move the value to a secret manager or environment variable and rotate it if it was real.",
            "Requires approval",
        ),
        (
            re.compile(r"AKIA[0-9A-Z]{16}"),
            "Critical",
            "Secrets",
            "Possible AWS access key in source.",
            "Cloud credentials in source can allow unauthorized account access.",
            "Revoke and rotate the key, then replace it with environment-based configuration.",
            "Requires approval",
        ),
        (
            re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
            "Critical",
            "Secrets",
            "Private key material appears in source.",
            "Private keys in source can allow impersonation or unauthorized access.",
            "Remove the key, rotate affected credentials, and store secrets outside the repository.",
            "Requires approval",
        ),
        (
            re.compile(r"\b(innerHTML|outerHTML)\s*="),
            "Medium",
            "Frontend XSS",
            "Direct HTML assignment detected.",
            "Direct HTML assignment can create XSS when data is user-controlled.",
            "Use safe text binding or sanitize trusted HTML at a narrow boundary.",
            "Medium",
        ),
        (
            re.compile(r"\binsertAdjacentHTML\s*\("),
            "Medium",
            "Frontend XSS",
            "insertAdjacentHTML usage detected.",
            "Injecting HTML strings can create XSS when data is user-controlled.",
            "Use DOM-safe rendering or sanitize trusted HTML at a narrow boundary.",
            "Medium",
        ),
        (
            re.compile(r"dangerouslySetInnerHTML"),
            "Medium",
            "Frontend XSS",
            "React dangerouslySetInnerHTML usage detected.",
            "Rendering raw HTML can create XSS when content is not strictly trusted.",
            "Avoid raw HTML rendering or sanitize content and document the trust boundary.",
            "Medium",
        ),
        (
            re.compile(r"bypassSecurityTrust(Html|Style|Script|Url|ResourceUrl)"),
            "High",
            "Angular sanitizer",
            "Angular DomSanitizer bypass detected.",
            "Sanitizer bypass disables Angular protections and can lead to XSS.",
            "Remove the bypass or constrain it to audited trusted input with tests.",
            "High",
        ),
        (
            re.compile(r"(localStorage|sessionStorage)\.(setItem|getItem)\s*\([^)]*(token|jwt|auth|session)", flags),
            "Medium",
            "Auth/token storage",
            "Token-like value stored or read from web storage.",
            "Web storage tokens are exposed to XSS and browser extension access.",
            "Prefer httpOnly secure cookies or reduce token lifetime and XSS exposure.",
            "Medium",
        ),
        (
            re.compile(r"document\.cookie"),
            "Low",
            "Auth/token storage",
            "Direct cookie access detected.",
            "Client-readable cookies can expose tokens unless carefully scoped.",
            "Confirm cookies use Secure, SameSite, and httpOnly where applicable.",
            "Low",
        ),
        (
            re.compile(r"['\"]http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])[^'\"]+['\"]", flags),
            "Medium",
            "API connection",
            "Non-localhost HTTP URL detected.",
            "Plain HTTP can expose tokens and API traffic to interception.",
            "Use HTTPS for production API URLs and keep environment-specific values out of source.",
            "Low",
        ),
        (
            re.compile(r"cors\s*\(\s*\)|origin\s*:\s*['\"]\*['\"]|origin\s*:\s*true", flags),
            "High",
            "CORS",
            "Broad CORS configuration detected.",
            "Overly broad CORS can expose APIs to unintended origins, especially with credentials.",
            "Restrict origins per environment and test known clients.",
            "Medium",
        ),
        (
            re.compile(r"jwt\.sign\s*\([^,]+,\s*['\"][^'\"]{4,}['\"]|secret\s*:\s*['\"][^'\"]{4,}['\"]", flags),
            "High",
            "JWT/auth",
            "Literal JWT/auth secret detected.",
            "Hardcoded JWT secrets can allow token forgery if disclosed.",
            "Read secrets from environment/secret manager and rotate any real secret.",
            "Requires approval",
        ),
        (
            re.compile(r"\b(exec|execSync)\s*\([^)]*(req\.|request\.|params|query|body)", flags),
            "Critical",
            "Command injection",
            "Shell execution appears to use request-controlled data.",
            "Request-controlled shell commands can allow remote code execution.",
            "Remove shell execution or strictly allowlist arguments without invoking a shell.",
            "High",
        ),
        (
            re.compile(r"\b(query|execute|raw)\s*\(\s*`[^`]*\$\{", flags),
            "High",
            "SQL injection",
            "Database call appears to use template interpolation.",
            "Interpolated SQL can allow injection when values are user-controlled.",
            "Use parameterized queries or ORM bindings.",
            "Medium",
        ),
        (
            re.compile(r"\b(query|execute|raw)\s*\([^)]*\+\s*(req\.|request\.|params|query|body)", flags),
            "High",
            "SQL injection",
            "Database call appears to concatenate request data.",
            "String-built SQL can allow injection.",
            "Use parameterized queries or ORM bindings.",
            "Medium",
        ),
        (
            re.compile(r"console\.(log|warn|error|info|debug)\s*\([^)]*(password|token|secret|authorization|cookie|jwt)", flags),
            "Medium",
            "Sensitive logging",
            "Logging statement references sensitive data.",
            "Logs can persist credentials and expose them to broader audiences.",
            "Redact sensitive fields before logging and add regression coverage where practical.",
            "Low",
        ),
        (
            re.compile(r"\bmulter\s*\("),
            "Medium",
            "File upload",
            "Multer upload handling detected; verify limits and file filtering.",
            "Uploads without limits or validation can enable denial of service or unsafe file handling.",
            "Require size limits, file filters, storage isolation, and downstream scanning where needed.",
            "Medium",
        ),
        (
            re.compile(r"role\s*={0,2}={0,1}\s*['\"]admin['\"]|isAdmin", flags),
            "Low",
            "Authorization",
            "Frontend/admin role check detected; verify backend enforcement.",
            "Frontend-only admin checks can be bypassed by direct API calls.",
            "Confirm every privileged backend endpoint enforces authorization.",
            "Medium",
        ),
    ]


def scan_static_files(root: Path, issues: list[Issue]) -> int:
    reviewed = 0
    patterns = static_patterns()
    for path in iter_text_files(root):
        text = read_text(path)
        if text is None:
            continue
        reviewed += 1
        if path.name.endswith(".lock") or path.name in {"package-lock.json", "yarn.lock", "pnpm-lock.yaml"}:
            continue
        documentation_only = path.suffix.lower() in {".md", ".txt"}
        for line_number, line in enumerate(text.splitlines(), start=1):
            if len(issues) >= MAX_STATIC_ISSUES:
                return reviewed
            for regex, severity, category, title, impact, fix, risk in patterns:
                if documentation_only and category != "Secrets":
                    continue
                if regex.search(line):
                    add_issue(
                        issues,
                        Issue(
                            severity,
                            category,
                            f"{rel(root, path)}:{line_number}",
                            title,
                            impact,
                            fix,
                            risk,
                        ),
                    )
                    break
    return reviewed


def parse_version_tuple(version: str) -> tuple[int, int, int] | None:
    match = re.search(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?", str(version))
    if not match:
        return None
    return tuple(int(part or 0) for part in match.groups())


def update_type(current: str, target: str) -> str:
    current_tuple = parse_version_tuple(current)
    target_tuple = parse_version_tuple(target)
    if not current_tuple or not target_tuple:
        return "Hold/manual review"
    if target_tuple[0] > current_tuple[0]:
        return "Major"
    if target_tuple[1] > current_tuple[1]:
        return "Minor"
    if target_tuple[2] > current_tuple[2]:
        return "Patch"
    return "Hold/manual review"


def parse_outdated(path: Path | None) -> list[PackageUpdate]:
    if path is None:
        return []
    data = load_json(path)
    if data is None:
        return []
    rows: list[PackageUpdate] = []
    items: Iterable[Any]
    if isinstance(data, dict):
        if isinstance(data.get("data"), list):
            items = data["data"]
        else:
            items = [{"name": name, **value} for name, value in data.items() if isinstance(value, dict)]
    elif isinstance(data, list):
        items = data
    else:
        items = []
    for item in items:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or item.get("package") or item.get("dependency") or "unknown")
        current = str(item.get("current") or item.get("from") or "")
        wanted = str(item.get("wanted") or item.get("to") or item.get("latest") or "")
        latest = str(item.get("latest") or wanted or "")
        kind = update_type(current, latest)
        risk = "Requires approval" if kind == "Major" else ("Low" if kind in {"Patch", "Minor"} else "Hold/manual review")
        action = "Review manually before updating." if kind in {"Major", "Hold/manual review"} else "Candidate for approved safe update with tests."
        rows.append(PackageUpdate(name, current, wanted, latest, risk, kind, action))
    return rows


def parse_audit(path: Path | None) -> list[PackageUpdate]:
    if path is None:
        return []
    data = load_json(path)
    if data is None:
        return []
    rows: list[PackageUpdate] = []
    vulnerabilities = data.get("vulnerabilities") if isinstance(data, dict) else None
    if isinstance(vulnerabilities, dict):
        for name, vuln in vulnerabilities.items():
            if not isinstance(vuln, dict):
                continue
            severity = str(vuln.get("severity", "unknown")).capitalize()
            fix_available = vuln.get("fixAvailable")
            action = "Apply approved security fix and test."
            if fix_available is False:
                action = "No automatic fix available; review advisory manually."
            elif isinstance(fix_available, dict) and fix_available.get("isSemVerMajor"):
                action = "Security fix appears to require a major update; approval required."
            rows.append(
                PackageUpdate(
                    str(name),
                    str(vuln.get("range", "")),
                    "",
                    "",
                    severity,
                    "Security fix",
                    action,
                )
            )
    advisories = data.get("advisories") if isinstance(data, dict) else None
    if isinstance(advisories, dict):
        for advisory in advisories.values():
            if not isinstance(advisory, dict):
                continue
            rows.append(
                PackageUpdate(
                    str(advisory.get("module_name", "unknown")),
                    str(advisory.get("vulnerable_versions", "")),
                    "",
                    str(advisory.get("patched_versions", "")),
                    str(advisory.get("severity", "unknown")).capitalize(),
                    "Security fix",
                    "Apply an approved patched version if compatible.",
                )
            )
    return rows


def risk_score(severity: str) -> int:
    return {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Info": 1}.get(severity, 0)


def overall_risk(issues: list[Issue], package_updates: list[PackageUpdate]) -> str:
    max_issue = max([risk_score(issue.severity) for issue in issues] or [0])
    package_risk = 0
    for row in package_updates:
        package_risk = max(package_risk, risk_score(row.severity_risk))
    score = max(max_issue, package_risk)
    if score >= 5:
        return "Critical"
    if score == 4:
        return "High"
    if score == 3:
        return "Medium"
    if score == 2:
        return "Low"
    return "Info"


def table(headers: list[str], rows: list[list[str]]) -> str:
    def clean(value: Any) -> str:
        text = str(value) if value is not None else ""
        return text.replace("|", "\\|").replace("\n", "<br>")

    out = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for row in rows:
        out.append("| " + " | ".join(clean(cell) for cell in row) + " |")
    return "\n".join(out)


def generate_safe_fixes(issues: list[Issue]) -> list[list[str]]:
    rows: list[list[str]] = []
    counter = 1
    for issue in issues:
        if issue.breaking_risk in {"Safe", "Low"} and counter <= 12:
            rows.append([f"FIX-{counter:03d}", issue.recommended_fix, issue.location, issue.breaking_risk, "Run targeted tests/build for affected area."])
            counter += 1
    if not rows:
        rows.append(["-", "No clearly safe automatic fixes identified by the read-only scan.", "-", "-", "-"])
    return rows


def generate_approval_fixes(issues: list[Issue], package_updates: list[PackageUpdate]) -> list[list[str]]:
    rows: list[list[str]] = []
    counter = 1
    for issue in issues:
        if issue.breaking_risk in {"Medium", "High", "Requires approval"} and counter <= 12:
            rows.append([f"APPROVAL-{counter:03d}", issue.recommended_fix, f"{issue.category} change may affect behavior or requires secret/config action.", issue.breaking_risk])
            counter += 1
    for update in package_updates:
        if update.update_type in {"Major", "Hold/manual review"} and counter <= 12:
            rows.append([f"APPROVAL-{counter:03d}", f"Review {update.package} update.", "Major/manual dependency update can break compatibility.", update.severity_risk])
            counter += 1
    if not rows:
        rows.append(["-", "No approval-gated fixes identified by the read-only scan.", "-", "-"])
    return rows


def plan_from_findings(issues: list[Issue], package_updates: list[PackageUpdate]) -> str:
    steps: list[str] = []
    if any(issue.category == "Secrets" for issue in issues):
        steps.append(
            "1. **Handle secret findings**\n"
            "   - What will change: Remove hardcoded secret material and replace it with environment/secret-manager references.\n"
            "   - Why it is needed: Source-controlled secrets can allow unauthorized access.\n"
            "   - Files affected: See `Secrets` findings above.\n"
            "   - How to test: Run build/tests and manually verify environment variables are present.\n"
            "   - Rollback idea: Restore previous config references only after confirming rotated credentials are safe.\n"
            "   - Risk level: Requires approval"
        )
    if package_updates or any(issue.category in {"Dependencies", "Package scripts"} for issue in issues):
        steps.append(
            f"{len(steps) + 1}. **Review dependency updates**\n"
            "   - What will change: Review risky scripts and deprecated packages; apply approved patch/minor security updates first; hold major upgrades for separate approval.\n"
            "   - Why it is needed: Vulnerable dependencies and install-time scripts can expose known attack paths or supply-chain risk.\n"
            "   - Files affected: package manifests and lockfiles after approval.\n"
            "   - How to test: Run install, build, test, lint/typecheck if available.\n"
            "   - Rollback idea: Revert package and lockfile changes.\n"
            "   - Risk level: Low to Requires approval"
        )
    if any(issue.category.startswith("Frontend") or issue.category in {"Angular sanitizer", "Auth/token storage", "API connection"} for issue in issues):
        steps.append(
            f"{len(steps) + 1}. **Fix frontend security risks**\n"
            "   - What will change: Replace unsafe rendering, review sanitizer bypasses, and harden token/API handling.\n"
            "   - Why it is needed: Frontend risks can expose users to XSS or token leakage.\n"
            "   - Files affected: See frontend findings above.\n"
            "   - How to test: Run frontend tests/build and manually verify protected routes and API calls.\n"
            "   - Rollback idea: Revert the focused component/service changes.\n"
            "   - Risk level: Medium"
        )
    if any(issue.category in {"Backend hardening", "CORS", "JWT/auth", "SQL injection", "Command injection", "File upload", "Sensitive logging"} for issue in issues):
        steps.append(
            f"{len(steps) + 1}. **Fix backend security risks**\n"
            "   - What will change: Harden CORS/headers/rate limits, auth secrets, injection points, uploads, and sensitive logs.\n"
            "   - Why it is needed: Backend issues can expose data or server execution paths.\n"
            "   - Files affected: See backend findings above.\n"
            "   - How to test: Run backend tests/build and smoke-test auth/API endpoints.\n"
            "   - Rollback idea: Revert middleware/config changes as a group.\n"
            "   - Risk level: Medium to High"
        )
    if not steps:
        steps.append(
            "1. **Confirm clean scan and run validation**\n"
            "   - What will change: No code changes recommended by this read-only scan.\n"
            "   - Why it is needed: Validate that no hidden security findings were missed.\n"
            "   - Files affected: None.\n"
            "   - How to test: Run available build/test/lint commands.\n"
            "   - Rollback idea: Not applicable.\n"
            "   - Risk level: Safe"
        )
    return "\n\n".join(steps)


def generate_markdown(result: dict[str, Any]) -> str:
    summary = result["summary"]
    issues = result["issues"]
    package_updates = result["package_updates"]
    commands = result["commands"]
    issue_rows = [
        [
            f"SCR-{index:03d}",
            issue["severity"],
            issue["category"],
            issue["location"],
            issue["issue"],
            issue["impact"],
            issue["recommended_fix"],
            issue["breaking_risk"],
        ]
        for index, issue in enumerate(issues, start=1)
    ]
    if not issue_rows:
        issue_rows = [["-", "Info", "Static scan", "-", "No issues detected by the static scanner.", "Manual review is still recommended.", "Run audit/outdated checks and review critical auth/config files.", "Safe"]]

    package_rows = [
        [
            row["package"],
            row["current"],
            row["wanted"],
            row["latest"],
            row["severity_risk"],
            row["update_type"],
            row["suggested_action"],
        ]
        for row in package_updates
    ]
    if not package_rows:
        package_rows = [["-", "-", "-", "-", "Info", "Hold/manual review", "No audit/outdated JSON was provided or no package update findings were parsed."]]

    return "\n\n".join(
        [
            "# Security Review Report",
            "## Project Summary",
            table(
                ["Item", "Value"],
                [
                    ["Project type", summary["project_type"]],
                    ["Package manager", summary["package_manager"]],
                    ["Frameworks detected", ", ".join(summary["frameworks"]) or "None detected"],
                    ["Frontend/backend detected", summary["stack"]],
                    ["Overall risk level", summary["overall_risk"]],
                    ["Files reviewed", str(summary["files_reviewed"])],
                    ["Commands used", ", ".join(commands) or "Static scanner only"],
                ],
            ),
            "## Issues Found",
            table(["ID", "Severity", "Category", "File/Location", "Issue", "Impact", "Recommended Fix", "Breaking Risk"], issue_rows),
            "## Package Update Review",
            table(["Package", "Current", "Wanted", "Latest", "Severity/Risk", "Update Type", "Suggested Action"], package_rows),
            "## Safe Fixes Available",
            table(["Fix ID", "Description", "Files affected", "Risk", "Test needed"], generate_safe_fixes([Issue(**issue) for issue in issues])),
            "## Fixes Requiring Approval",
            table(["Fix ID", "Description", "Reason approval is needed", "Risk"], generate_approval_fixes([Issue(**issue) for issue in issues], [PackageUpdate(**row) for row in package_updates])),
            "## Recommended Fix Plan",
            plan_from_findings([Issue(**issue) for issue in issues], [PackageUpdate(**row) for row in package_updates]),
        ]
    )


def build_result(root: Path, audit_json: Path | None, outdated_json: Path | None) -> dict[str, Any]:
    root = root.resolve()
    package_jsons = find_package_jsons(root)
    root_package_path = root / "package.json"
    root_package = load_json(root_package_path) if root_package_path.exists() else {}
    if not isinstance(root_package, dict):
        root_package = {}

    all_deps: dict[str, str] = {}
    for package_json in package_jsons:
        data = load_json(package_json)
        if isinstance(data, dict):
            all_deps.update(dependency_map(data))

    frameworks = detect_frameworks(root, all_deps)
    project_type, stack = detect_project_shape(root, root_package, package_jsons, frameworks)
    package_manager = detect_package_manager(root, root_package)
    issues: list[Issue] = []

    scan_package_scripts(package_jsons, root, issues)
    scan_dependency_metadata(root, package_jsons, all_deps, frameworks, issues)
    reviewed = scan_static_files(root, issues)

    package_updates = parse_audit(audit_json) + parse_outdated(outdated_json)
    commands = ["static scanner"]
    if audit_json:
        commands.append(f"parsed audit JSON: {audit_json}")
    if outdated_json:
        commands.append(f"parsed outdated JSON: {outdated_json}")

    scripts = collect_scripts(package_jsons, root)
    return {
        "summary": {
            "root": str(root),
            "project_type": project_type,
            "package_manager": package_manager,
            "frameworks": frameworks,
            "stack": stack,
            "overall_risk": overall_risk(issues, package_updates),
            "files_reviewed": reviewed,
            "package_json_files": [rel(root, path) for path in package_jsons],
            "available_scripts": scripts,
        },
        "commands": commands,
        "issues": [asdict(issue) for issue in issues],
        "package_updates": [asdict(row) for row in package_updates],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only security scanner for Node.js-family projects.")
    parser.add_argument("project_root", nargs="?", default=".", help="Project root to scan.")
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown", help="Output format.")
    parser.add_argument("--output", help="Write output to this file instead of stdout.")
    parser.add_argument("--audit-json", help="Path to npm/pnpm/yarn audit JSON output.")
    parser.add_argument("--outdated-json", help="Path to npm/pnpm/yarn outdated JSON output.")
    args = parser.parse_args(argv)

    root = Path(args.project_root)
    if not root.exists() or not root.is_dir():
        print(f"Project root does not exist or is not a directory: {root}", file=sys.stderr)
        return 2

    audit_json = Path(args.audit_json) if args.audit_json else None
    outdated_json = Path(args.outdated_json) if args.outdated_json else None
    result = build_result(root, audit_json, outdated_json)
    output = json.dumps(result, indent=2) if args.format == "json" else generate_markdown(result)

    if args.output:
        Path(args.output).write_text(output + "\n", encoding="utf-8")
    else:
        print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
