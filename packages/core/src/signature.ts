import { Credential } from './types';

/**
 * Canonical payload used for issuer signatures.
 * Keep this stable across issuer and verifier implementations.
 *
 * SECURITY: The issuer identity and issuance time MUST be included in the
 * signed payload to prevent issuer substitution attacks (where an attacker
 * replaces the `issuer` field on a SignedCredential with a different
 * trusted issuer's name, and the signature remains valid because it
 * wasn't bound to the issuer).
 *
 * @param credential - The credential to sign
 * @param issuer     - The issuer identity (name or DID) to bind into the signature
 * @param issuedAt   - The issuance timestamp (ISO 8601) to bind into the signature
 */
export function credentialSignaturePayload(
  credential: Credential,
  issuer?: string,
  issuedAt?: string,
): string {
  const payload: Record<string, unknown> = {
    id: credential.id,
    commitment: credential.commitment,
    createdAt: credential.createdAt,
  };

  // Include issuer binding when provided (v0.6.0+)
  if (issuer !== undefined) {
    payload.issuer = issuer;
  }
  if (issuedAt !== undefined) {
    payload.issuedAt = issuedAt;
  }

  return JSON.stringify(payload);
}
