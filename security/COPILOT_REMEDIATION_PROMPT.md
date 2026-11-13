# GitHub Copilot prompt: repository remediation

Work in one repository at a time. Investigate and safely remediate findings from the audit report and prioritised queue. Do not make scanners green by suppressing warnings.

## Operating rules

1. Inspect architecture, manifests, lockfiles, tests, CI and deployment configuration before editing.
2. Reproduce each finding on the current branch. Use its ID, scanner, advisory/rule, file, line, package, installed/fixed version and evidence.
3. Confirm whether vulnerable packages are shipped and whether affected code paths are reachable. Distinguish direct and transitive dependencies.
4. For source alerts, trace untrusted input to sensitive sinks. Document validation, authorization and trust boundaries.
5. Rank by real-world impact: internet exposure, authentication, privileges, data sensitivity, exploit preconditions, reachability and blast radius. Scanner severity is not exploitability.
6. Fix one coherent issue group at a time with minimal compatible changes.
7. Never disable scanners, add broad ignore rules, weaken tests, lower severity, delete reports or suppress entire rules to hide findings.
8. Never run npm audit fix --force, mass-upgrade dependencies, regenerate all lockfiles blindly, or make major upgrades without compatibility analysis.
9. Never print, copy, commit or expose secrets. If a credential is confirmed live, stop, identify its type and location without reproducing its value, and recommend immediate rotation and history remediation.
10. Do not change production data, schemas, secrets, deployment settings or external services without explicit approval.
11. Do not merge or push to the default branch. Use a dedicated branch and prepare a reviewable PR.
12. If a finding is a false positive or not exploitable, show the evidence. Use only narrow documented suppressions when justified.

## Dependency vulnerabilities

- Identify exact lockfile, package manager, installed version, dependency path and advisory aliases.
- Confirm minimum patched version from the advisory and upstream release notes.
- Prefer the smallest compatible patch/minor release.
- Update manifest and lockfile using the existing package manager.
- Run unit/integration tests, type checking, lint, build and smoke tests.
- Re-run OSV-Scanner, Trivy and package-manager audit. Confirm the advisory is absent from the resolved tree.
- If no compatible fix exists, document mitigation, exposure and blocker rather than forcing an upgrade.

## Application security

- SQL: bind parameters; allowlist dynamic identifiers; never interpolate untrusted input.
- SSRF: validate schemes/destinations, reject private/loopback/link-local/reserved IPs, re-check redirects and DNS, and set timeouts/response limits.
- Path traversal: resolve against a fixed base and verify the final path stays inside it.
- HTML/XSS: prefer safe framework rendering; use maintained allowlist sanitization only when raw HTML is essential.
- CSRF/auth: enforce server-side authorization on every state-changing endpoint.
- Secrets: use secret managers/environment references, redact logs, rotate confirmed credentials and inspect history.
- Deserialization: never load untrusted pickle or executable serialization.
- TLS: verify certificates by default; never add insecure bypasses.
- GitHub Actions: pin third-party actions to verified full commit SHAs, use least-privilege permissions, scope secrets to consuming steps and validate shell inputs.

## Required workflow

### Phase A — investigate
Produce a table with finding ID, severity, exploitability, component, evidence, root cause, reachability and proposed fix. Mark uncertainty explicitly.

### Phase B — plan
List exact files, compatibility risks, tests and rollback. Do not edit yet if the fix requires a major upgrade, data migration, secret rotation, production change or broad refactor.

### Phase C — implement
Make the smallest safe patch. Add regression tests that fail before and pass after the fix. Keep unrelated refactoring out.

### Phase D — verify
Run relevant tests, type checker, linter, build and targeted scanners. Report commands and actual exit codes. Never claim a check passed unless it ran.

### Phase E — handoff
Provide root cause and fix, changed files, test results, resolved/open/false-positive/deferred findings, residual risks, rollback instructions, commit message and PR description.

## Current task
Start with the highest-priority validated finding. Do not fix every repository in one pass. Finish one repository's critical/high issues, verify them, then move to the next. Ask before destructive, production-impacting or irreversible actions.
