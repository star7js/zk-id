import { Credential } from './types';

/**
 * Canonical payload used for issuer signatures.
 * Keep this stable across issuer and verifier implementations.
 */
export function credentialSignaturePayload(credential: Credential): string {
  return JSON.stringify({
    id: credential.id,
    commitment: credential.commitment,
    createdAt: credential.createdAt,
  });
}
