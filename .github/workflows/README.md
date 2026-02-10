# GitHub Workflows

This directory contains the CI/CD and security workflows for the zk-id project.

## Design Philosophy

This workflow setup follows the **single responsibility principle** with a focus on efficiency:

- Each workflow handles one clear task (build, security scan, release)
- Overlapping tools are consolidated (CodeQL + Semgrep in one workflow)
- Only tools relevant to a ZK circuit library are included
- Concurrency controls prevent resource waste

## Workflows

| Workflow                | Triggers                                                                            | Purpose                                                                    |
| ----------------------- | ----------------------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| **ci.yml**              | Push to main, PRs                                                                   | Main CI pipeline - runs tests, builds packages, verifies circuit artifacts |
| **verify-circuits.yml** | Push to main (circuit changes), PRs (circuit changes), Weekly (Mon 6AM UTC), Manual | Verifies circuit reproducibility by performing clean builds from scratch   |
| **security.yml**        | Push to main, PRs, Weekly (Mon 9AM UTC)                                             | Runs CodeQL and Semgrep SAST scans, uploads results to Security tab        |
| **scorecard.yml**       | Push to main, Weekly (Sat 1:30AM UTC), Manual                                       | OSSF Scorecard supply-chain security analysis                              |
| **release.yml**         | Tag push (v\*)                                                                      | Creates GitHub releases from version tags                                  |

## Shared Components

### Composite Actions

- **`.github/actions/setup-circom`**: Installs and caches the Circom compiler (v2.1.8). Used by `ci.yml` and `verify-circuits.yml` to ensure consistent tooling.

## Security Scanning

All security scanning results are uploaded to the **Security** tab in GitHub:

- **CodeQL**: JavaScript/TypeScript static analysis for vulnerabilities
- **Semgrep**: Additional SAST rules for common security issues
- **OSSF Scorecard**: Supply-chain security best practices analysis
- **Dependabot**: Automated dependency updates (configured in `.github/dependabot.yml`)

Each scanner uploads SARIF results with unique categories to prevent collisions in the Security dashboard.

### Why This Stack?

We chose this focused security stack over alternatives because:

- **CodeQL**: GitHub-native, free, excellent JS/TS support
- **Semgrep**: Open-source, customizable, good for crypto patterns
- **Dependabot over Snyk**: Simpler, GitHub-native, no external account needed
- **No API scanners**: This is a circuit library, not an API service (no APIsec, EthicalCheck, etc.)
- **Consolidated approach**: Combined CodeQL + Semgrep in `security.yml` reduces workflow complexity

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
