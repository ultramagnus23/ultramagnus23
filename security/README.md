# Repository remediation triage

A standard-library-only importer converts scanner artifacts from multiple repositories into one deduplicated, sortable queue.

## Run locally

Extract the audit artifacts so each repository has a folder containing its scanner files: osv.json, semgrep.sarif, trivy.sarif, gitleaks.sarif, npm-audit JSON and ruff.json.

Run:

    python security/triage.py --input-dir ./audit-input --out-dir ./triage-output

Outputs: findings.json, findings.csv and findings.md.

## Priority meanings

- P0-VERIFY: Gitleaks hit; urgently confirm whether it is a live credential. Not automatically a real secret.
- P0-CRITICAL: critical dependency advisory.
- P1-HIGH: high dependency advisory.
- P1-REVIEW: security-related source-code finding requiring manual validation.
- P2-MEDIUM: medium dependency advisory.
- P3-LOW: low dependency advisory.
- P4-QUALITY: Ruff findings grouped by file and rule.

## Remediation process

Validate each finding against the current default branch, establish runtime reachability, make one coherent change per branch/PR, run tests/build/scanners, compare fingerprints, and merge only after human review. The importer intentionally does not auto-upgrade packages or rewrite source files.
