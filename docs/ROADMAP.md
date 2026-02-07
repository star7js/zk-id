# ZK-ID Roadmap

This document tracks the development progress and future plans for the zk-id project.

## Completed Features

### Phase 1: Core Infrastructure (Completed)
- ✅ Core cryptographic primitives (Poseidon hash)
- ✅ Circom circuits for age verification
- ✅ Circom circuits for credential hashing
- ✅ TypeScript SDK with snarkjs integration
- ✅ Circuit compilation and artifact generation
- ✅ Comprehensive test suite (70+ tests)

### Phase 2: Basic Functionality (Completed)
- ✅ Credential creation and management
- ✅ Zero-knowledge proof generation
- ✅ Proof verification (age claims)
- ✅ Working end-to-end CLI demo
- ✅ Issuer implementation with HMAC signing
- ✅ Age verification circuit with constraint validation

### Phase 3: Security Hardening (Completed)
- ✅ **Critical Security Fix**: Credential hash verification in circuit
  - Ensures proofs are bound to specific credentials
  - Prevents malicious actors from generating proofs with arbitrary birth years
  - Verifies credentialHash = Poseidon(birthYear, salt)

### Phase 4: Multi-Attribute Credentials (Completed - Feb 2026)
- ✅ Extended credential schema with nationality attribute
- ✅ Nationality verification circuit
- ✅ Selective disclosure support (prove one attribute without revealing others)
- ✅ Enhanced credential commitment scheme

### Phase 5: Production Features (Completed - Feb 2026)
- ✅ **Ed25519 Signatures**: Replaced HMAC with production-grade asymmetric signatures
- ✅ **Credential Revocation**:
  - RevocationStore interface in core package
  - InMemoryRevocationStore implementation
  - Issuer revocation methods (revokeCredential, isCredentialRevoked)
  - SDK server revocation checking before proof verification
- ✅ **Batch Verification**:
  - verifyBatch() function for efficient multi-proof verification
  - Promise.allSettled-based parallel verification
  - Per-proof result tracking with error handling
- ✅ **Telemetry & Monitoring**:
  - EventEmitter-based verification event system
  - VerificationEvent with timestamp, duration, and status
  - onVerification() callback registration
  - No external dependencies
- ✅ **Integration Example**:
  - Express server with RESTful API endpoints
  - Static HTML demo page with credential issuance
  - Real telemetry logging
  - Revocation demonstration

## In Progress

Nothing currently in progress - all planned features for Phase 5 completed!

## Planned Features

### Phase 6: Client Applications (Q2 2026)
- [ ] **Browser Wallet Extension**
  - Chrome/Firefox extension for credential storage
  - Secure local key management
  - One-click proof generation
  - Multi-credential support

- [ ] **Mobile Wallets**
  - iOS app (Swift/SwiftUI)
  - Android app (Kotlin)
  - Biometric authentication
  - QR code scanning for credential issuance

### Phase 7: Advanced Cryptography (Q3 2026)
- [ ] **Credential Accumulators**
  - On-chain revocation using cryptographic accumulators
  - Merkle tree-based revocation proofs
  - Gas-efficient blockchain integration

- [ ] **Recursive Proof Composition**
  - Prove multiple claims in a single proof
  - Reduced verification cost
  - Better privacy through proof aggregation

- [ ] **Alternative Proof Systems**
  - PLONK circuit support (universal setup)
  - STARKs for post-quantum security
  - Bulletproofs for range proofs

### Phase 8: Enterprise Features (Q4 2026)
- [ ] **Issuer Dashboard**
  - Web interface for credential management
  - Bulk issuance tools
  - Revocation management
  - Analytics and reporting

- [ ] **Multi-Issuer Trust Framework**
  - Issuer registry and discovery
  - Trust scoring and reputation
  - Issuer key rotation

- [ ] **Advanced Attribute Types**
  - Location verification (country, region)
  - Time-bound credentials (expiration)
  - Credential chains (derived credentials)
  - Range proofs (income bracket, credit score range)

### Phase 9: Scalability & Performance (2027)
- [ ] **Proof Caching**
  - Server-side proof result caching
  - Replay attack prevention with proof freshness

- [ ] **Hardware Acceleration**
  - GPU-accelerated proof generation
  - WASM optimization for browser

- [ ] **Distributed Verification**
  - Load balancing across verification nodes
  - Horizontal scaling support

### Phase 10: Standards & Compliance (2027)
- [ ] **DID Integration**
  - did:web method support
  - did:key method support
  - DID resolution

- [ ] **Compliance Frameworks**
  - GDPR compliance tools
  - CCPA compliance support
  - Age verification standards (COPPA, GDPR Article 8)

- [ ] **Audit & Certification**
  - Third-party security audit
  - Formal verification of circuits
  - Certification for production use

## Future Research

### Open Questions
- How to handle credential expiration in ZK proofs?
- Best practices for threshold issuance (multiple issuers for one credential)?
- Privacy-preserving credential metadata (issuer hiding)?
- Cross-chain interoperability?

### Experimental Features
- Anonymous credentials (BBS+ signatures)
- Predicate proofs (arbitrary boolean expressions)
- Conditional disclosure (reveal data only if proof verifies)
- Zero-knowledge machine learning (prove model predictions)

## Contributing

Want to help? Check out the [Contributing Guide](../CONTRIBUTING.md) and pick an item from the "Planned Features" section.

Priority areas:
1. Browser wallet (high impact, good first project)
2. Mobile wallets (iOS/Android)
3. Performance optimization (proof generation speed)
4. Documentation and examples

## Version History

- **v0.1.0** (Jan 2026): Initial release with basic age verification
- **v0.2.0** (Feb 2026): Multi-attribute credentials, Ed25519, revocation, telemetry
- **v0.3.0** (Planned Q2 2026): Browser wallet and mobile apps
- **v1.0.0** (Planned Q4 2026): Production-ready with enterprise features

---

Last updated: February 2026
