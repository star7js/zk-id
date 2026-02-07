# zk-id Review Notes (Security + Correctness)

Date: 2026-02-07

## Top Findings (Must Fix)

1) Revocation bypass (credentialId not bound to proof)
- Fixed: revocation checks now use credential commitment from the proof (no credentialId trust).

2) Replay protection ineffective (nonce not bound to proof)
- Fixed: `nonce` is now a public input to both circuits and verified by server.

3) Policy bypass (minAge/targetNationality not enforced by server)
- Server verifies whatever `minAge`/`targetNationality` is embedded in the proof.
- Client can request a weaker policy (e.g., `minAge=13`) and still receive `verified=true`.
- Fix: enforce required policy in `ZkIdServer` config or per-request parameter and compare to proof public signals.

4) Issuer trust not enforced
- Proofs don’t verify issuer signatures or trust roots, enabling self‑issued credentials.
- Fix: require signed credentials and verify issuer signature with a configured issuer registry.

## Design Direction Recommendation

- **Trust model**: issuer‑signed credentials with a configured issuer registry.
- **Policy model**: server‑side required policy (e.g., `requiredMinAge`) enforced for all proofs.
- **Demos**: keep format interop demos isolated (e.g., `examples/credential-format-demo`) so core stays focused on security.
- **Open source**: good idea for external review; publish a clear threat model and “known limitations” section.

## Implementation Proposal (Short)

- Add `SignedCredential` type to core and require it in `ProofResponse`.
- Verify issuer signature and commitment match before any verification.
- Enforce `requiredMinAge` / `requiredNationality` in `ZkIdServer`.
- Add tests in `packages/sdk/test` for signature/policy enforcement.
- (Follow-up) Bind `nonce` into circuits and regenerate build artifacts.
