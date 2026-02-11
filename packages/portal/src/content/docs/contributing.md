---
title: 'Contributing Guide'
description: 'Thank you for your interest in contributing to zk-id! This guide will help you understand the project structure, development workflow, and how to make'
category: 'Getting Started'
order: 2
---

# Contributing to zk-id

Thank you for your interest in contributing to zk-id! This guide will help you understand the project structure, development workflow, and how to make meaningful contributions.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Getting Started](#getting-started)
- [Monorepo Structure](#monorepo-structure)
- [Development Workflow](#development-workflow)
- [Adding New Features](#adding-new-features)
- [Testing Strategy](#testing-strategy)
- [Code Style Guidelines](#code-style-guidelines)
- [Git Workflow](#git-workflow)
- [Pull Request Process](#pull-request-process)
- [Release Process](#release-process)

## Prerequisites

### Required

- **Node.js 18+** — Check with `node --version`
- **npm 8+** — Check with `npm --version`
- **Git** — For version control

### Optional (for circuit development)

- **circom 0.5.46+** — Circuit compiler ([installation](https://docs.circom.io/getting-started/installation/))
- **Rust toolchain** — Required by circom ([rustup.rs](https://rustup.rs/))
- **snarkjs** — Installed automatically via npm

## Getting Started

### 1. Fork and Clone

```bash
# Fork the repository on GitHub, then clone your fork
git clone https://github.com/YOUR_USERNAME/zk-id.git
cd zk-id

# Add upstream remote
git remote add upstream https://github.com/star7js/zk-id.git
```

### 2. Install Dependencies

```bash
# Install all workspace dependencies
npm install
```

This installs dependencies for all packages in the monorepo using npm workspaces.

### 3. Build All Packages

```bash
# Build in dependency order
npm run build
```

Build order matters! The build script compiles packages in the correct order:

1. `@zk-id/circuits` (no TypeScript build, just circuits)
2. `@zk-id/core` (depended on by all other packages)
3. `@zk-id/sdk` (depends on core)
4. `@zk-id/issuer` (depends on core)
5. `@zk-id/redis` (depends on core)
6. `@zk-id/contracts` (depends on core, circuits)
7. `@zk-id/example-web-app` (depends on core, sdk, issuer)

### 4. Run Tests

```bash
# Run all tests
npm test

# Run tests for a specific package
npm test --workspace=@zk-id/core
npm test --workspace=@zk-id/sdk
```

### 5. Start the Demo

```bash
# From repository root
npm start --workspace=@zk-id/example-web-app

# Or from examples/web-app/
cd examples/web-app
npm start
```

## Monorepo Structure

zk-id uses **npm workspaces** for monorepo management. All packages share a single `node_modules` and `package-lock.json`.

```
zk-id/
├── packages/                   # Published packages
│   ├── circuits/              # @zk-id/circuits (Circom ZK circuits)
│   ├── core/                  # @zk-id/core (core cryptographic library)
│   ├── sdk/                   # @zk-id/sdk (client & server SDK)
│   ├── issuer/                # @zk-id/issuer (credential issuance)
│   ├── redis/                 # @zk-id/redis (Redis storage backends)
│   └── contracts/             # @zk-id/contracts (Solidity verifiers)
├── examples/                   # Example applications (not published)
│   └── web-app/               # @zk-id/example-web-app (demo)
├── docs/                       # Documentation
├── .github/                    # GitHub Actions, Dependabot config
└── package.json               # Root package.json with workspaces config
```

### Understanding npm Workspaces

Workspaces are defined in the root `package.json`:

```json
{
  "workspaces": ["packages/*", "examples/*"]
}
```

**Benefits:**

- Shared dependencies (single `node_modules`)
- Cross-package linking (no `npm link` needed)
- Unified commands (`npm test` runs tests for all packages)

**Working with workspaces:**

```bash
# Install a dependency in a specific workspace
npm install <package> --workspace=@zk-id/core

# Run a script in a specific workspace
npm run build --workspace=@zk-id/core

# Run a script in all workspaces
npm run test --workspaces
```

### Package Dependencies

```
@zk-id/circuits (standalone, no deps)
    ↓
@zk-id/core (depends on circuits for artifacts)
    ↓
    ├── @zk-id/sdk (depends on core)
    ├── @zk-id/issuer (depends on core)
    ├── @zk-id/redis (depends on core)
    └── @zk-id/contracts (depends on core, circuits)
         ↓
    @zk-id/example-web-app (depends on core, sdk, issuer)
```

## Development Workflow

### Daily Development

1. **Pull latest changes**

   ```bash
   git checkout main
   git pull upstream main
   ```

2. **Create a feature branch**

   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make changes**
   - Edit code in relevant package(s)
   - Add tests for new functionality
   - Update documentation

4. **Build affected packages**

   ```bash
   # Build specific package
   npm run build --workspace=@zk-id/core

   # Or rebuild everything
   npm run build
   ```

5. **Run tests**

   ```bash
   # Test specific package
   npm test --workspace=@zk-id/core

   # Test everything
   npm test
   ```

6. **Commit and push**
   ```bash
   git add .
   git commit -m "Add feature: description"
   git push origin feature/your-feature-name
   ```

### Rebuilding After Changes

**When to rebuild:**

- Changed TypeScript code in `packages/core` → rebuild core + dependent packages
- Changed circuits in `packages/circuits` → recompile circuits + rebuild packages using them
- Changed SDK → rebuild SDK only (unless API changed)

**Quick rebuild commands:**

```bash
# Rebuild just one package
npm run build --workspace=@zk-id/core

# Rebuild core and all dependents
npm run build --workspace=@zk-id/core && \
npm run build --workspace=@zk-id/sdk && \
npm run build --workspace=@zk-id/issuer && \
npm run build --workspace=@zk-id/redis

# Nuclear option: rebuild everything
npm run build
```

## Adding New Features

### Adding a New Circuit

1. **Create the circuit file**

   ```bash
   # In packages/circuits/src/
   touch packages/circuits/src/my-new-circuit.circom
   ```

2. **Write the circuit**

   ```circom
   pragma circom 2.1.6;

   template MyNewCircuit() {
       signal input privateInput;
       signal output publicOutput;

       // Circuit logic here
   }

   component main = MyNewCircuit();
   ```

3. **Add to compilation script**
   Edit `packages/circuits/scripts/compile.sh` to include your circuit.

4. **Compile and setup**

   ```bash
   npm run compile --workspace=@zk-id/circuits
   npm run setup --workspace=@zk-id/circuits
   ```

5. **Add tests**
   Create `packages/circuits/test/my-new-circuit.test.js`

6. **Update documentation**
   - Add circuit to `packages/circuits/README.md`
   - Update `docs/CIRCUIT-COMPLEXITY.md` with constraint counts
   - Update `docs/CIRCUIT-DIAGRAMS.md` if applicable

### Adding a New Package

1. **Create package directory**

   ```bash
   mkdir -p packages/my-new-package/src
   cd packages/my-new-package
   ```

2. **Create package.json**

   ```json
   {
     "name": "@zk-id/my-new-package",
     "version": "0.6.0",
     "main": "dist/index.js",
     "types": "dist/index.d.ts",
     "scripts": {
       "build": "tsc",
       "test": "mocha"
     },
     "dependencies": {
       "@zk-id/core": "*"
     }
   }
   ```

3. **Create tsconfig.json**
   Copy from another package and adjust paths.

4. **Add to build script**
   Update root `package.json` build script to include your package.

5. **Create README.md**
   Follow the format from existing packages.

### Adding Core Functionality

When adding features to `@zk-id/core`:

1. **Add type definitions** in `src/types.ts`
2. **Implement functionality** in appropriate module (`src/prover.ts`, `src/verifier.ts`, etc.)
3. **Export from index** in `src/index.ts`
4. **Add tests** in `test/`
5. **Update README** with new API
6. **Rebuild dependent packages**

## Testing Strategy

### Unit Tests

Each package has its own test suite:

```bash
# Core library tests
npm test --workspace=@zk-id/core

# Circuit tests
npm test --workspace=@zk-id/circuits

# SDK tests
npm test --workspace=@zk-id/sdk
```

### Test Structure

```
packages/core/
├── src/
│   ├── prover.ts
│   └── verifier.ts
└── test/
    ├── prover.test.ts
    └── verifier.test.ts
```

### Writing Tests

Use **Mocha + Chai** for TypeScript tests:

```typescript
import { expect } from 'chai';
import { generateAgeProof } from '../src/prover';

describe('generateAgeProof', () => {
  it('should generate a valid proof', async () => {
    const proof = await generateAgeProof(/* ... */);
    expect(proof).to.have.property('proof');
    expect(proof.proof).to.be.a('string');
  });
});
```

Use **Mocha + circom_tester** for circuit tests:

```javascript
const { expect } = require('chai');
const wasm_tester = require('circom_tester').wasm;

describe('MyCircuit', () => {
  it('should compute correctly', async () => {
    const circuit = await wasm_tester('src/my-circuit.circom');
    const witness = await circuit.calculateWitness({ input: 42 });
    await circuit.checkConstraints(witness);
  });
});
```

### Test Coverage

While we don't enforce strict coverage targets, aim for:

- **Core functionality**: 80%+ coverage
- **Critical paths**: 100% coverage
- **Edge cases**: Well documented tests

## Code Style Guidelines

### TypeScript

- **Use strict mode**: `"strict": true` in tsconfig.json
- **Explicit types**: Avoid `any`, prefer explicit types
- **Async/await**: Prefer over raw promises
- **Error handling**: Use try/catch, validate inputs

**Example:**

```typescript
// Good
export async function generateProof(credential: Credential, minAge: number): Promise<AgeProof> {
  validateCredential(credential);
  validateMinAge(minAge);

  try {
    const proof = await snarkjs.groth16.fullProve(/* ... */);
    return formatProof(proof);
  } catch (error) {
    throw new Error(`Proof generation failed: ${error.message}`);
  }
}

// Bad
export async function generateProof(cred: any, age: any): Promise<any> {
  return await snarkjs.groth16.fullProve(/* ... */);
}
```

### Circom

- **Use latest Circom version**: 2.1.6+
- **Include pragma**: `pragma circom 2.1.6;`
- **Comment complex logic**: Explain non-obvious constraints
- **Minimize constraints**: Optimize for proof size and speed

**Example:**

```circom
pragma circom 2.1.6;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";

// Verifies age >= minAge without revealing exact age
template AgeVerify() {
    signal input birthYear;
    signal input currentYear;
    signal input minAge;

    // Calculate age
    signal age;
    age <== currentYear - birthYear;

    // Check age >= minAge
    component ageCheck = GreaterEqThan(8);
    ageCheck.in[0] <== age;
    ageCheck.in[1] <== minAge;
    ageCheck.out === 1;
}
```

### Formatting

We use **ESLint** and **Prettier** for automated code quality and formatting:

```bash
# Lint code
npm run lint

# Auto-fix linting issues
npm run lint:fix

# Format code
npm run format

# Check formatting without modifying
npm run format:check
```

**Style rules:**

- **Indentation**: 2 spaces (no tabs)
- **Line length**: Max 100 characters (soft limit)
- **Trailing commas**: Use in multiline arrays/objects
- **Semicolons**: Required
- **Quotes**: Single quotes for strings
- **Arrow functions**: Prefer over function expressions

**Editor integration:**

- Install ESLint and Prettier extensions for your editor
- Enable "Format on Save" for automatic formatting
- ESLint will highlight issues in real-time

**Pre-commit hooks:**

- Prettier automatically formats staged files
- ESLint checks run before commit
- Hooks configured via `.husky/` directory

### Documentation

- **JSDoc comments** for public APIs
- **README** for each package
- **Inline comments** for complex logic only

**Example:**

```typescript
/**
 * Generates a zero-knowledge proof that the credential holder is at least minAge years old
 *
 * @param credential - The user's credential (private)
 * @param minAge - The minimum age requirement (public)
 * @param nonce - Nonce for replay protection (public)
 * @param requestTimestampMs - Request timestamp in milliseconds (public)
 * @param wasmPath - Path to the compiled circuit WASM file
 * @param zkeyPath - Path to the proving key
 * @returns An AgeProof that can be verified without revealing the birth year
 */
export async function generateAgeProof(/* ... */): Promise<AgeProof> {
  // Implementation
}
```

## Git Workflow

### Branch Naming

- `feature/description` — New features
- `fix/description` — Bug fixes
- `docs/description` — Documentation changes
- `refactor/description` — Code refactoring
- `test/description` — Test additions/changes

### Commit Messages

Follow the **Conventional Commits** style:

```
<type>: <description>

[optional body]

[optional footer]
```

**Types:**

- `feat:` — New feature
- `fix:` — Bug fix
- `docs:` — Documentation changes
- `refactor:` — Code refactoring
- `test:` — Adding/updating tests
- `chore:` — Maintenance tasks

**Examples:**

```
feat: Add nullifier circuit for sybil resistance

Implement nullifier computation circuit that generates unique
nullifiers per credential and scope, preventing double-spending
and enabling sybil-resistant applications.

Closes #123
```

```
fix: Correct nonce validation in verifier

The verifier was incorrectly rejecting valid nonces due to
BigInt comparison issues. Fixed by using string comparison.

Fixes #456
```

### Keeping Your Branch Updated

```bash
# Fetch upstream changes
git fetch upstream

# Rebase your branch on upstream/main
git checkout feature/your-feature
git rebase upstream/main

# Push to your fork (force push after rebase)
git push origin feature/your-feature --force-with-lease
```

## Pull Request Process

### Before Submitting

- [ ] All tests pass (`npm test`)
- [ ] All packages build (`npm run build`)
- [ ] Code passes linting (`npm run lint`)
- [ ] Code is formatted (`npm run format`)
- [ ] Documentation updated (README, inline comments)
- [ ] No console.logs or debug code (except in tests)
- [ ] Commit messages are clear and descriptive
- [ ] Type errors resolved (`npm run typecheck` if available)

### Submitting a PR

1. **Push your branch** to your fork
2. **Open a PR** on GitHub against `main`
3. **Fill out the PR template** completely
4. **Link related issues** (Closes #123)

### PR Title Format

Use the same format as commit messages:

```
feat: Add BBS selective disclosure support
fix: Resolve circuit compilation on Linux
docs: Update GETTING-STARTED guide
```

### PR Description

Include:

- **What**: What changes does this PR make?
- **Why**: Why are these changes needed?
- **How**: How do the changes work?
- **Testing**: How did you test this?
- **Screenshots**: For UI changes

### Review Process

1. **Automated checks** run (tests, builds)
2. **Maintainers review** your code
3. **Address feedback** by pushing new commits
4. **Squash and merge** when approved

### After Merge

1. **Delete your branch** (GitHub does this automatically)
2. **Pull latest main**
   ```bash
   git checkout main
   git pull upstream main
   ```
3. **Delete local branch**
   ```bash
   git branch -d feature/your-feature
   ```

## Release Process

_(For maintainers)_

### Version Numbering

We follow [Semantic Versioning](https://semver.org/):

- **Major (1.0.0)**: Breaking changes
- **Minor (0.1.0)**: New features, backwards compatible
- **Patch (0.0.1)**: Bug fixes, backwards compatible

### Pre-1.0 Status

Currently at version **0.6.0** (pre-release):

- APIs may change
- Not recommended for production use
- Development Powers of Tau (not production-ready)
- No npm publishing until 1.0.0

### Release Checklist (Future)

- [ ] All tests pass
- [ ] Documentation updated
- [ ] CHANGELOG.md updated
- [ ] Version bumped in all package.json files
- [ ] Git tag created
- [ ] GitHub release created
- [ ] npm packages published (when ready)

## Getting Help

### Resources

- **Documentation**: [docs/](./docs/)
- **README files**: Each package has detailed README
- **GETTING-STARTED**: [GETTING-STARTED.md](./GETTING-STARTED.md)
- **Architecture**: [docs/ARCHITECTURE.md](./docs/ARCHITECTURE.md)
- **Protocol**: [docs/PROTOCOL.md](./docs/PROTOCOL.md)

### Communication

- **GitHub Issues**: Bug reports, feature requests
- **GitHub Discussions**: Questions, ideas, community
- **Pull Requests**: Code contributions

### Common Questions

**Q: Why won't my circuits compile?**
A: Ensure you have circom and Rust installed. Check `npm run compile:circuits` output for errors.

**Q: Tests fail after updating dependencies?**
A: Rebuild all packages: `npm run build`

**Q: How do I test changes across multiple packages?**
A: Use `npm link` isn't needed with workspaces — changes are automatically reflected after rebuild.

**Q: Should I update package-lock.json?**
A: Yes, if you add/update dependencies. Commit the updated lockfile.

## Code of Conduct

Be respectful, inclusive, and constructive. We're all here to build great software together.

- Be patient with newcomers
- Provide constructive feedback
- Focus on the code, not the person
- Assume good intentions

## License

By contributing to zk-id, you agree that your contributions will be licensed under the Apache-2.0 License.

---

Thank you for contributing to zk-id! Your efforts help make privacy-preserving identity verification accessible to everyone.
