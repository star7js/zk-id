# GitHub Workflows

This directory contains the CI/CD and security workflows for the zk-id project.

## Workflows

| Workflow | Triggers | Purpose |
|----------|----------|---------|
| **ci.yml** | Push to main, PRs | Main CI pipeline - runs tests, builds packages, verifies circuit artifacts |
| **verify-circuits.yml** | Push to main (circuit changes), PRs (circuit changes), Weekly (Mon 6AM UTC), Manual | Verifies circuit reproducibility by performing clean builds from scratch |
| **security.yml** | Push to main, PRs, Weekly (Mon 9AM UTC) | Runs CodeQL and Semgrep SAST scans, uploads results to Security tab |
| **scorecard.yml** | Push to main, Weekly (Sat 1:30AM UTC), Manual | OSSF Scorecard supply-chain security analysis |
| **release.yml** | Tag push (v*) | Creates GitHub releases from version tags |

## Shared Components

### Composite Actions

- **`.github/actions/setup-circom`**: Installs and caches the Circom compiler (v2.1.8). Used by `ci.yml` and `verify-circuits.yml` to ensure consistent tooling.

## Security Scanning

All security scanning results are uploaded to the **Security** tab in GitHub:

- **CodeQL**: JavaScript/TypeScript static analysis for vulnerabilities
- **Semgrep**: Additional SAST rules for common security issues
- **OSSF Scorecard**: Supply-chain security best practices analysis

Each scanner uploads SARIF results with unique categories to prevent collisions in the Security dashboard.

## Concurrency

All workflows use concurrency groups to prevent wasted CI minutes:

- PR workflows: `cancel-in-progress: true` (newer runs cancel older ones)
- Main/release workflows: `cancel-in-progress: false` (never cancel critical workflows)

## Best Practices

- All action versions are pinned to major versions (`@v6`, `@v5`, `@v4`)
- Permissions are explicitly declared at workflow or job level (principle of least privilege)
- Timeouts are set on all jobs to prevent runaway workflows
- Circuit builds are cached to speed up CI runs
- Dependabot groups minor/patch npm updates to reduce PR noise
