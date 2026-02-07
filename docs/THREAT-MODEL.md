# Threat Model

Date: 2026-02-07

## Scope
This repo focuses on correctness and security of the core zk-id protocol.
It is not a production system and does not provide full operational security.

## Trust Model
- **Issuer-signed credentials** are required for verification.
- Verifiers trust a configured set of issuer public keys.
- Proofs must bind to the credential commitment and a request nonce.

## Assets
- Credential secrecy (birth year, nationality, salt)
- Proof integrity (no forged proofs)
- Issuer authenticity (no self-issued credentials)
- Replay resistance (proofs bound to nonce)

## Adversaries
- Malicious client attempting to bypass policy or revocation
- Network attacker replaying or tampering with proofs
- Rogue issuer or untrusted key presented as trusted

## Security Goals
- Prevent proofs without valid issuer signatures
- Enforce server policy (min age / nationality)
- Prevent replay of proofs with different nonce
- Detect revoked credentials

## Out of Scope
- Secure key management (HSM/KMS)
- Full anonymity network protections
- Side-channel resistance in client environments
- Data retention and logging policy enforcement

## Assumptions
- Circuits, proving keys, and verification keys are correctly generated
- Issuer public keys are distributed securely
- Clients generate proofs locally and do not leak secrets

## Known Risks
- If issuer keys are compromised, forged credentials are possible
- If proof responses are logged, privacy could be degraded
- Revocation list model can leak correlation if misused
