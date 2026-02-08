# Contributing to zk-id

Thank you for your interest in contributing to zk-id! This document provides guidelines and information to help you get started.

## Prerequisites

- **Node.js**: Version 20 or higher
- **npm**: Comes with Node.js
- **Rust & Circom toolchain**: Required for circuit compilation
  - Install Circom: https://docs.circom.io/getting-started/installation/
  - Rust toolchain: https://rustup.rs/

## Development Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/star7js/zk-id.git
   cd zk-id
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Build all packages:
   ```bash
   npm run build
   ```

4. Run tests:
   ```bash
   npm test
   ```

## Project Structure

The project is organized as a monorepo:

- `packages/circuits/` - Zero-knowledge circuits (Circom)
- `packages/sdk/` - TypeScript SDK for credential operations
- `packages/issuer/` - Reference credential issuer implementation
- `examples/web/` - Web-based demo application

## Development Workflow

1. **Fork** the repository to your GitHub account
2. **Create a branch** for your changes:
   ```bash
   git checkout -b feature/my-feature
   ```
3. **Make your changes** following the code style guidelines
4. **Test your changes** thoroughly
5. **Submit a pull request** with a clear description

## Code Style

- **Language**: TypeScript for SDK and application code
- **Follow existing patterns**: Review similar code in the project for consistency
- **Run tests**: Ensure all tests pass before submitting your PR
- **Type safety**: Maintain strict TypeScript types

## Commit Messages

- Use **imperative mood** in the subject line (e.g., "Add feature" not "Added feature")
- Keep the subject line **under 72 characters**
- Use the body to explain **what** and **why** (not how)
- Reference issues and PRs where appropriate

Example:
```
Add credential revocation support

Implements revocation lists using Bloom filters to maintain privacy
while allowing verifiers to check credential validity.

Closes #123
```

## Circuit Changes

If you modify zero-knowledge circuits:

1. **Recompile circuits**:
   ```bash
   npm run compile:circuits
   ```

2. **Trusted setup**: Circuit changes require a new trusted setup ceremony for production use

3. **Test thoroughly**: Circuit bugs can compromise security

4. **Document changes**: Update circuit documentation and specs

## Reporting Bugs

Found a bug? Please report it via [GitHub Issues](https://github.com/star7js/zk-id/issues):

- **Search first**: Check if the issue already exists
- **Provide details**: Include reproduction steps, expected vs actual behavior, and environment info
- **Security issues**: For security vulnerabilities, see [SECURITY.md](SECURITY.md)

## Questions?

Feel free to open a GitHub Discussion or Issue if you have questions about contributing!
