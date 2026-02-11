---
title: 'Project Tickets'
description: 'These are concrete tickets derived from the near-term roadmap. Use them as GitHub issues or a backlog seed.'
category: 'Reference'
order: 53
---

# Roadmap Tickets (Draft)

These are concrete tickets derived from the near-term roadmap. Use them as GitHub issues or a backlog seed.

## Revocation Root Distribution (MVP)

### T-001: Define Revocation Root Metadata Schema + Endpoint Contract ✅

**Goal:** Standardize the root info shape and how it is served/cached.

**Scope**

- Define `RevocationRootInfo` fields (root, version, updatedAt, expiresAt, ttlSeconds, source).
- Document cache headers and freshness guidance.
- Update `docs/PROTOCOL.md` and `docs/openapi.yaml`.

**Acceptance Criteria**

- Protocol doc includes a revocation root section with versioning + TTL rules.
- OpenAPI describes `GET /api/revocation/root` response schema.
- SDK types align with the schema.

**Out of scope**

- Root signing / provenance (covered elsewhere).

### T-002: Client/Server Freshness Policy for Revocation Roots ✅

**Goal:** Provide a consistent policy for how old a root can be.

**Scope**

- Add config option for max root age (server & client).
- Provide recommended defaults and warnings.
- Update docs + README snippet.

**Acceptance Criteria**

- Config option exists and is documented.
- Tests cover rejection when root is stale (if enabled).

**Out of scope**

- Distributed root sync across multiple servers.

## Security Readiness

### T-003: Circuit Artifact Hash Manifest ✅

**Goal:** Provide integrity checks for circuit artifacts.

**Scope**

- Generate SHA-256 hashes for WASM + ZKEY outputs.
- Store in `docs/circuit-hashes.json` (or similar).
- Add CI check that validates hashes against artifacts.

**Acceptance Criteria**

- Hash manifest exists and is kept up to date in CI.
- CI fails if hashes drift without update.

### T-004: Reproducible Circuit Build + Verification-Key Provenance ✅

**Goal:** Make circuit builds reproducible and verifiable.

**Scope**

- Document deterministic build steps and environment.
- Add CI job to rebuild artifacts and compare hashes.
- Add a `VERIFICATION_KEYS.md` note on provenance + update process.

**Acceptance Criteria**

- CI confirms reproducible build for circuits.
- Docs describe how keys are produced and validated.

## Issuer Trust & Key Lifecycle

### T-005: Issuer Registry Spec + Metadata ✅

**Goal:** Formalize issuer registry fields and behavior.

**Scope**

- Add metadata fields: `jurisdiction`, `policyUrl`, `auditUrl`, `validFrom`, `validTo`.
- Update SDK types and issuer registry validation.
- Document in protocol and README.

**Acceptance Criteria**

- Type definitions updated + validated.
- Docs show example registry entry with metadata.

### T-006: Key Rotation + Suspension Workflow ✅

**Goal:** Define and implement issuer key rotation and suspension rules.

**Scope**

- Add rotation logic / overlap windows.
- Add suspension behavior and tests.
- Document recommended operational flow.

**Acceptance Criteria**

- Tests cover rotation + suspension paths.
- Docs include an operational checklist.

## API & Protocol Clarity

### T-007: JSON Schemas for SDK Inputs ✅

**Goal:** Provide machine-readable validation for API payloads.

**Scope**

- Define JSON schema for `ProofRequest`, `ProofResponse`, `SignedProofRequest`.
- Validate requests in SDK server (optional strict mode).
- Publish schema in `docs/schemas/`.

**Acceptance Criteria**

- Schemas exist and are referenced in docs.
- Optional strict validation path in SDK server is documented.

### T-008: OpenAPI Completion for Verification Flows ✅

**Goal:** Ensure public API docs are complete and accurate.

**Scope**

- Add endpoints for signed and revocable verification flows.
- Include revocation root info endpoint schema.
- Include error response schemas.

**Acceptance Criteria**

- `docs/openapi.yaml` covers all demo verification endpoints with request/response schemas.

## Q2 2026

### T-009: Mobile SDK (React Native)

**Goal:** Provide a React Native wrapper for zk-id proof generation on mobile platforms.

**Scope**

- React Native wrapper around core TypeScript libraries
- Proof generation on iOS and Android
- Secure credential storage (Keychain/Keystore integration)
- Example mobile app demonstrating age verification flow

**Acceptance Criteria**

- Proof generation works on iOS and Android
- Credentials stored securely in platform keychain
- Example app demonstrates age verification with signed credentials
- Documentation covers mobile-specific considerations

**Out of scope**

- Native (non-RN) SDKs for iOS/Android
- Production app store deployment and distribution

### T-010: Credential Exchange Protocol

**Goal:** Enable standardized credential exchange with the VC/VP ecosystem.

**Scope**

- DIF Presentation Exchange v2.0 support
- OpenID4VP (OpenID for Verifiable Presentations) integration
- Standardized wallet request/response flow
- Interoperability with existing VC/VP ecosystems

**Acceptance Criteria**

- Presentation Exchange v2.0 request/response flow works end-to-end
- OpenID4VP flow documented and tested
- At least one external wallet tested for interoperability
- Integration examples provided in documentation

**Out of scope**

- Full OIDC4VCI (credential issuance protocol)
- SIOPv2 (self-issued OpenID Provider) implementation

### T-011: Developer Portal & Playground

**Goal:** Provide interactive documentation and a live sandbox for developers.

**Scope**

- Interactive tutorials and step-by-step guides
- "Verify your first proof in 5 minutes" quick start experience
- Live sandbox environment for testing proof generation/verification
- API reference with multi-language code examples

**Acceptance Criteria**

- Quick start guide completes end-to-end in under 5 minutes
- Sandbox runs in browser without local installation
- API reference covers all public endpoints with examples
- At least 3 programming languages covered in examples (TypeScript, Python, Go)

**Out of scope**

- Hosted production infrastructure for customer deployments
- Billing system or account management features
