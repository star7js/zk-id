# Threat Model

**Date:** 2026-02-09
**Version:** 1.0.0
**Status:** Production

---

## 1. System Overview

zk-id is a zero-knowledge proof system for selective disclosure of identity credentials. The system operates across three roles:

```
┌─────────┐           ┌─────────┐           ┌──────────┐
│ Issuer  │──(sign)──>│ Holder  │──(prove)─>│ Verifier │
└─────────┘           └─────────┘           └──────────┘
```

**Issuer** → Issues signed credentials containing birth year, nationality, and a random salt bound by Poseidon hash commitment.

**Holder** → Stores credentials locally, generates zero-knowledge proofs using Groth16 SNARKs to prove properties (e.g., age ≥ 18) without revealing the underlying data.

**Verifier** → Validates proofs cryptographically, enforces server-side policies, and maintains replay/revocation protection.

---

## 2. Trust Assumptions

The security of zk-id depends on the following trust assumptions:

### 2.1 Cryptographic Assumptions
- **Circuit correctness**: The circom circuits (age-verify, nationality-verify, etc.) correctly encode the intended constraints. Malformed circuits could allow proof forgery.
- **Trusted setup integrity**: The Groth16 Powers of Tau ceremony (Hermez, 177 participants) generated proving/verification keys without toxic waste retention. Compromised setup keys enable arbitrary proof generation.
- **Poseidon collision resistance**: The Poseidon hash (BN128, t=3/4) is collision-resistant. Collisions would allow credential forgery.
- **EdDSA signature security**: BabyJubJub EdDSA (in-circuit) and Ed25519 (off-chain) are unforgeable under chosen-message attacks.
- **BN128 discrete log hardness**: The elliptic curve discrete logarithm problem on BN128 is computationally infeasible (~128-bit security).

### 2.2 System Assumptions
- **Issuer key security**: Issuer private keys are stored securely (HSM recommended). Compromised keys allow arbitrary credential issuance.
- **Verification key distribution**: Verification keys (`.zkey`) are distributed through trusted channels. Tampered keys could validate invalid proofs.
- **CSPRNG quality**: `crypto.randomBytes()` (Node.js) provides cryptographically secure randomness for salts, nonces, and keys on all platforms (Linux: `/dev/urandom`, macOS: `arc4random_buf`, Windows: `BCryptGenRandom`).
- **Circuit artifact integrity**: SHA-256 hashes in `docs/circuit-hashes.json` match deployed artifacts. Hash mismatches indicate tampering or build drift.

### 2.3 Operational Assumptions
- **Holder environment**: Proofs are generated in a trusted client environment. Malware on the prover's device could exfiltrate credentials.
- **Server time synchronization**: Verifiers maintain accurate clocks. Large clock skew enables time-shifted proof attacks (mitigated by `maxFutureSkewMs`).
- **Audit log integrity**: Audit logs are tamper-evident or write-only (e.g., append-only S3, Elasticsearch with WORM). Log deletion could hide attacks.

---

## 3. Threat Actors

| Actor | Motivation | Capabilities |
|-------|------------|--------------|
| **Malicious Prover** | Bypass age/nationality restrictions, impersonate others, reuse proofs | Local circuit execution, network MitM, credential replay |
| **Malicious Verifier** | Harvest user data, correlate sessions, de-anonymize users | Log analysis, timing attacks, traffic analysis |
| **Compromised Issuer** | Mass credential forgery, backdoor issuance | Generate valid signatures for arbitrary credentials |
| **Network Attacker** | Intercept/replay proofs, DoS verification servers | Packet sniffing, replay attacks, rate limiting bypass |
| **Colluding Parties** | Cross-issuer correlation, de-anonymize users | Share commitment hashes, nullifiers, or metadata |

---

## 4. Attack Surface

### 4.1 Malicious Prover Attacks

| Attack Vector | Impact | Mitigation | Residual Risk |
|---------------|--------|------------|---------------|
| **Proof forgery** | Prover claims age ≥ 18 when age < 18 | Groth16 soundness + circuit constraints enforce age comparison | Circuit bugs (under-constrained signals) could allow bypass |
| **Credential self-issuance** | Prover generates credential without trusted issuer | Verifier checks issuer signature (`validateSignedCredentialBinding`) | Requires compromised issuer key (out of scope) |
| **Replay attack** | Reuse proof from one verifier at another | Nonce binding (`proof.publicSignals.nonce`) + `NonceStore` marks nonces as used | Nonce store must be persistent (Redis/DB); in-memory stores leak on restart |
| **Time-shifted proofs** | Generate proof with future timestamp to bypass expiry | Server validates `requestTimestamp` against `maxFutureSkewMs` (default 60s) | Clock skew <60s is tolerated; tighter bounds require NTP sync |
| **Revocation bypass** | Use revoked credential | Merkle inclusion proof (revocable circuits) or commitment-based revocation check | Revocation root staleness (`maxRevocationRootAgeMs`) must be configured |

### 4.2 Malicious Verifier Attacks

| Attack Vector | Impact | Mitigation | Residual Risk |
|---------------|--------|------------|---------------|
| **Metadata leakage** | Infer user attributes from timing, frequency, issuer | None (intentional tradeoff for usability) | Verifier learns: issuer identity, claim type, timestamp, proof frequency |
| **Session correlation** | Link multiple proofs from same user | Nullifiers (`computeNullifier(commitment, scope)`) create pseudonymous IDs per scope | Verifier can correlate within scope; cross-scope correlation requires colluding verifiers |
| **Traffic analysis** | Infer user location/behavior from network metadata | Client-side Tor/VPN (out of scope) | IP addresses, request timing visible to verifier |

### 4.3 Compromised Issuer Attacks

| Attack Vector | Impact | Mitigation | Residual Risk |
|---------------|--------|------------|---------------|
| **Mass forgery** | Issue credentials for non-existent identities | `IssuerRegistry` status checks (`active`, `revoked`, `suspended`) | Requires real-time issuer status monitoring; `InMemoryIssuerRegistry` has no external sync |
| **Backdated credentials** | Issue credentials with past `issuedAt` dates | Verifier can check `signedCredential.issuedAt` against issuer's `validFrom` | Not currently enforced; requires policy configuration |

### 4.4 Network Attacker Attacks

| Attack Vector | Impact | Mitigation | Residual Risk |
|---------------|--------|------------|---------------|
| **Replay via proxy** | Reuse intercepted proof at different verifier | Nonce uniqueness + `NonceStore` | Nonce store must be shared across verifiers (Redis) |
| **DoS via flood** | Overwhelm verifier with proof requests | Rate limiting (`SimpleRateLimiter` or external gateway) | `SimpleRateLimiter` is IP-based (trivially bypassable); use authenticated rate limits in production |
| **Proof tampering** | Modify proof in transit | TLS encryption (deployment requirement) | Assumes TLS termination at reverse proxy |

### 4.5 Colluding Parties

| Attack Vector | Impact | Mitigation | Residual Risk |
|---------------|--------|------------|---------------|
| **Commitment linkage** | Share credential commitments across issuers | Use separate commitments per issuer (requires holder privacy practices) | Commitments are deterministic; same credential yields same hash |
| **Nullifier linkage** | Share nullifiers across verifiers | Nullifier scopes (`scopeHash`) isolate per-verifier pseudonyms | Scope separation depends on verifier cooperation |

---

## 5. Cryptographic Assumptions

| Primitive | Assumption | Security Level | Failure Impact |
|-----------|------------|----------------|----------------|
| **Groth16** | Knowledge soundness (BN128 discrete log) | ~128-bit | Forged proofs without valid witness |
| **Poseidon** | Collision resistance (t=3: RF=8/RP=57, t=4: RF=8/RP=56) | ~128-bit | Credential forgery via hash collision |
| **EdDSA (BabyJub)** | Signature unforgeability (Baby Jubjub curve) | ~128-bit | In-circuit signature forgery |
| **Ed25519** | Signature unforgeability (Curve25519) | ~128-bit | Off-chain credential forgery |
| **SHA-256** | Preimage resistance (circuit artifact hashing) | 256-bit | Build artifact tampering undetected |

---

## 6. Metadata Leakage

### 6.1 What a Verifier Learns

Even with zero-knowledge proofs, verifiers inevitably learn:

| Metadata | Leakage | Privacy Impact |
|----------|---------|----------------|
| **Issuer identity** | `signedCredential.issuer` field is plaintext | Verifier knows which government/org issued the credential |
| **Claim type** | `claimType: 'age' / 'nationality' / 'age-revocable'` | Verifier knows what property was proven |
| **Timestamp** | `requestTimestamp` (ISO 8601) | Verifier knows when proof was generated |
| **Frequency** | Number of proofs per session | Verifier can infer usage patterns |
| **Network metadata** | IP address, TLS fingerprint, User-Agent | Standard web privacy concerns (use Tor/VPN if needed) |

### 6.2 Pseudonymity via Nullifiers

- **Nullifiers** (`Poseidon(commitment, scopeHash)`) create per-scope pseudonyms.
- Example: Alice proves age ≥18 at `example.com` twice → same nullifier both times.
- Cross-site tracking requires colluding verifiers sharing nullifiers (not prevented).

---

## 7. Known Limitations

| Limitation | Impact | Workaround / Future Work |
|------------|--------|--------------------------|
| **3-field commitment binding** | Credential schema locked to `(birthYear, nationality, salt)` | Requires new circuits for schema changes; documented in `Credential` interface JSDoc |
| **Merkle tree depth cap (1024)** | Valid credential set limited to 2^10 = 1024 entries | Use sparse Merkle trees (16-32 depth) for larger sets; scale horizontally with sharding |
| **IP-based rate limiting** | `SimpleRateLimiter` bypassable via proxies | Use token bucket with authenticated sessions or API gateway rate limiting |
| **In-memory stores leak on restart** | `InMemoryNonceStore`, `InMemoryChallengeStore` lose state | Use Redis or DB-backed stores in production |
| **No cross-issuer revocation** | Revocation list is issuer-specific | Federated revocation lists (future roadmap) |
| **Timestamp freshness depends on clock sync** | Large clock skew enables time-shifted proofs | Configure `maxFutureSkewMs` tightly; use NTP sync on servers |

---

## 8. Mitigations Summary

| Threat | Control | Implemented | Configuration Required |
|--------|---------|-------------|------------------------|
| Proof forgery | Circuit soundness + Groth16 | ✅ Yes | Review circuit constraints before trusted setup |
| Credential forgery | Issuer signature validation | ✅ Yes | Distribute issuer public keys securely |
| Replay attacks | Nonce uniqueness + `NonceStore` | ✅ Yes | Use persistent nonce store (Redis) |
| Time-shifted proofs | Timestamp validation (`maxFutureSkewMs`) | ✅ Yes | Set `maxFutureSkewMs` ≤ 60000ms |
| Revocation bypass | Merkle inclusion proof / commitment check | ✅ Yes | Configure `maxRevocationRootAgeMs` |
| Rate limit bypass | `RateLimiter` interface | ⚠️ Demo only | Use authenticated rate limiter in production |
| Information leakage | Error sanitization (`sanitizeError`) | ✅ Yes (v1.0) | Set `verboseErrors: false` (default) |
| Metadata correlation | Nullifier scopes | ✅ Yes | Verifiers must use unique `scopeHash` values |
| Circuit tampering | SHA-256 hash verification | ✅ Yes | Run `npm run verify-circuits` in CI |
| Key rotation gaps | Grace period (`rotationGracePeriodMs`) | ✅ Yes (v1.0) | Set `rotationGracePeriodMs` on `IssuerRecord` |

---

## 9. Recommendations for Deployment

### 9.1 Mandatory Security Controls
1. **Use TLS 1.3+** for all API endpoints (reverse proxy termination recommended).
2. **Persistent nonce store** (Redis with TTL) to prevent replay across restarts.
3. **Authenticated rate limiting** (token bucket per session ID, not IP).
4. **Set `verboseErrors: false`** to prevent information leakage to attackers.
5. **Configure `maxRequestAgeMs`** (e.g., 5 minutes) to reject stale proofs.
6. **Enable audit logging** with tamper-evident storage (write-only S3, Elasticsearch WORM).

### 9.2 Recommended Security Controls
1. **HSM/KMS for issuer keys** (AWS KMS, Azure Key Vault, HashiCorp Vault).
2. **Strict protocol version enforcement** (`protocolVersionPolicy: 'strict'`).
3. **Revocation root staleness checks** (`maxRevocationRootAgeMs: 300000` = 5 minutes).
4. **NTP clock synchronization** for accurate timestamp validation.
5. **Circuit artifact verification** (`npm run verify-circuits`) in CI/CD pipeline.

---

## 10. Out of Scope

The following are explicitly **not** addressed by this system and require external controls:

- **Secure key management** (HSM/KMS integration)
- **Full anonymity network protections** (Tor, VPN, traffic obfuscation)
- **Side-channel resistance** in client environments (timing attacks, memory scraping)
- **Data retention and GDPR compliance** (log lifecycle policies)
- **Physical security** of issuer infrastructure
- **Social engineering** (phishing for credentials)

---

## 11. Audit Recommendations

For third-party security audits, prioritize:

1. **Circuit constraint completeness** — verify all signals used in output are properly constrained (no under-constrained paths).
2. **Poseidon parameter verification** — confirm canonical parameters for BN128.
3. **Nonce/timestamp binding** — ensure proof public signals match request nonce/timestamp.
4. **Replay protection robustness** — test nonce store persistence, TTL expiry, and cross-instance synchronization.
5. **Error sanitization** — verify `verboseErrors: false` does not leak internal state.
6. **Rate limiting bypass** — test IP rotation, proxy evasion, and session forgery.

---

## 12. References

- **Protocol documentation**: `docs/PROTOCOL.md`
- **Circuit complexity metrics**: `docs/CIRCUIT-COMPLEXITY.md`
- **Cryptographic parameters**: `docs/CRYPTOGRAPHIC-PARAMETERS.md`
- **Trusted setup ceremony**: `docs/TRUSTED-SETUP.md`
- **Security policy**: `SECURITY.md`
- **Audit checklist**: `docs/AUDIT.md`

---

**Last updated:** 2026-02-09
**Reviewed by:** Claude Sonnet 4.5 (zk-id v1.0.0 release preparation)
