# Compliance Regulation Mapping

How zk-id maps to regulatory requirements for age verification and digital identity.

---

## 1. UK Online Safety Act 2023

The [Online Safety Act 2023](https://www.legislation.gov.uk/ukpga/2023/50) requires platforms to prevent children from accessing harmful content. Ofcom's codes of practice mandate "highly effective" age assurance.

### Requirement Mapping

| Requirement | OSA Reference | zk-id Capability | Status |
|---|---|---|---|
| Age estimation or verification | Part 5, s.11 | ZK age proofs prove `age >= threshold` without revealing birth date | Supported |
| Proportionality | Ofcom CoP 2024 | Only reveals over/under threshold — no personal data transmitted | Supported |
| Privacy by design | s.11(5), ICO guidance | Zero-knowledge proofs are privacy-preserving by construction | Supported |
| Interoperability | Ofcom CoP | Standard JSON proof format; OpenAPI schema available | Supported |
| Auditability | Ofcom CoP | `AuditLogger` interface logs verification events without PII | Supported |
| Credential issuer trust | Ofcom CoP | Signed credentials with issuer registry and key rotation | Supported |
| Replay prevention | Ofcom CoP | Server-issued nonce + timestamp challenges with TTL | Supported |
| Revocation | Ofcom CoP | Merkle-tree revocation with in-circuit validity proofs | Supported |

### Integration Notes

- Deploy with `requiredMinAge: 18` (or 13, depending on service category)
- Use signed credentials (`requireSignedCredentials: true`) for Ofcom "highly effective" tier
- Credential issuers must be DIATF-certified (UK Digital Identity and Attributes Trust Framework); zk-id does not handle certification but integrates with certified issuers via the `IssuerRegistry`
- Log verification outcomes via `AuditLogger` for Ofcom reporting obligations

---

## 2. EU Digital Services Act (DSA) / Age Verification Regulation

The [Digital Services Act (Regulation (EU) 2022/2065)](https://eur-lex.europa.eu/eli/reg/2022/2065) requires very large online platforms (VLOPs) to assess and mitigate risks to minors. The proposed EU Age Verification Regulation would extend these obligations.

### Requirement Mapping

| Requirement | DSA Reference | zk-id Capability | Status |
|---|---|---|---|
| Risk mitigation for minors | Art. 34, 35 | Age verification proofs with configurable thresholds | Supported |
| Data minimisation (GDPR Art. 5(1)(c)) | Art. 14(2) DSA + GDPR | ZK proofs reveal only the threshold comparison result | Supported |
| Purpose limitation | GDPR Art. 5(1)(b) | Proof contains no reusable personal data | Supported |
| No profiling from age checks | Art. 26a (proposed) | Nullifiers are scope-bound; no cross-service linkability | Supported |
| Storage limitation | GDPR Art. 5(1)(e) | Server stores only verification result, not identity data | Supported |
| Transparency | Art. 14 DSA | Proof format is open-source and auditable | Supported |
| Cross-border recognition | eIDAS 2.0 alignment | ISO 3166-1 nationality codes; standards-mapped credentials | Partial |

### Integration Notes

- GDPR DPIA recommended before production deployment
- Configure `maxRequestAgeMs` to limit proof replay window
- For VLOP compliance, combine age verification with content classification
- Consider national variations (e.g., Germany's JuSchG requires age 18 for certain content)

---

## 3. eIDAS 2.0 (EU Digital Identity Regulation)

[Regulation (EU) 2024/1183](https://eur-lex.europa.eu/eli/reg/2024/1183) establishes the European Digital Identity Wallet (EUDIW) framework. While zk-id is not an EUDIW implementation, it aligns with the architecture.

### Alignment Matrix

| eIDAS 2.0 Concept | zk-id Equivalent | Gap Analysis |
|---|---|---|
| Person Identification Data (PID) | `birthYear`, `nationality` in credential | zk-id has minimal PID; full eIDAS PID requires name, DoB, etc. |
| Qualified Electronic Attestation of Attributes (QEAA) | `SignedCredential` with issuer signature | zk-id credentials are not QEAA; would need qualified trust service provider (QTSP) as issuer |
| Selective disclosure | ZK proofs (Groth16) | Supported — proofs reveal only the verified claim |
| Unlinkability | Scope-bound nullifiers | Supported — different nullifiers per relying party |
| Wallet attestation | `BrowserWallet` / `CredentialStore` | Partial — no device binding or Level of Assurance attestation |
| Relying party registration | `IssuerRegistry` / `requiredPolicy` | Partial — registry exists but no RP registration protocol |
| Trust framework | Issuer registry with key rotation | Partial — no connection to EU Trust Lists |

### Path to eIDAS 2.0 Compatibility

1. Extend credential schema to include full PID attributes (requires new circuits)
2. Integrate with QTSP for credential issuance
3. Implement ARF (Architecture Reference Framework) wallet attestation
4. Connect issuer registry to EU Trusted Lists

---

## 4. US State-Level Age Verification Laws

Several US states have enacted age verification requirements (e.g., Louisiana Act 440, Utah SB 152, Texas HB 1181).

### Common Requirements

| Requirement | Typical Statute | zk-id Capability | Status |
|---|---|---|---|
| Verify user is 18+ | All state laws | `requiredMinAge: 18` | Supported |
| No retention of personal data | LA Act 440, UT SB 152 | ZK proofs contain no PII; server stores only pass/fail | Supported |
| Reasonable age verification method | TX HB 1181 | Cryptographic proof from credential issuer | Supported |
| Third-party verification | Most statutes | Issuer-verifier separation via signed credentials | Supported |

---

## 5. Deployment Checklist

Use this checklist when deploying zk-id for regulatory compliance.

### All Jurisdictions

- [ ] Set `verboseErrors: false` (default) — prevents information leakage
- [ ] Use persistent stores (Redis/PostgreSQL) — in-memory stores warn in production
- [ ] Enable signed credentials (`requireSignedCredentials: true`)
- [ ] Configure server-issued challenges (`challengeStore` + `challengeTtlMs`)
- [ ] Set `maxRequestAgeMs` to limit proof replay window (recommended: 300000 ms)
- [ ] Deploy `AuditLogger` with persistent backend (SIEM, database)
- [ ] Use rate limiting on verification endpoints
- [ ] Configure issuer registry with trusted, vetted issuers

### UK Online Safety Act

- [ ] Credential issuer is DIATF-certified
- [ ] `requiredMinAge` set per Ofcom service category (13 or 18)
- [ ] Audit logs retained per Ofcom reporting period
- [ ] Age assurance DPIA completed

### EU DSA / GDPR

- [ ] DPIA completed and filed with DPA
- [ ] Data processing agreement with credential issuer
- [ ] Privacy notice updated to describe ZK verification process
- [ ] Nullifier scoping configured to prevent cross-service linkability
- [ ] Record of processing activities updated (Art. 30 GDPR)

### US State Laws

- [ ] Verify applicable state law requirements (varies by state)
- [ ] Confirm no PII retention (ZK proofs satisfy this by default)
- [ ] Document third-party issuer relationship

---

## 6. Limitations and Disclaimers

- **zk-id is not a certified age verification solution.** Regulatory compliance depends on the overall deployment architecture, the credential issuer's certification, and the legal framework of each jurisdiction.
- **Credential issuers are outside zk-id's scope.** The cryptographic guarantees of ZK proofs depend on the trustworthiness of the issuer who creates credentials. Deployers must vet issuers independently.
- **This document is informational, not legal advice.** Consult qualified legal counsel for compliance obligations in your jurisdiction.
- **Regulations evolve.** This mapping reflects the state of legislation as of February 2026. Monitor Ofcom, EU Commission, and state legislative updates for changes.
