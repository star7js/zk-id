import { createCredential, Credential } from '@zk-id/core';
import { createHash, randomBytes } from 'crypto';

/**
 * IssuerConfig defines the configuration for a credential issuer
 */
export interface IssuerConfig {
  /** Name of the issuing authority */
  name: string;
  /** Private signing key (for testing - production should use HSM/KMS) */
  signingKey: string;
  /** Public verification key */
  publicKey: string;
}

/**
 * SignedCredential wraps a credential with an issuer signature
 */
export interface SignedCredential {
  credential: Credential;
  issuer: string;
  signature: string;
  issuedAt: string;
}

/**
 * CredentialIssuer handles the issuance of signed credentials
 *
 * In a production system, this would:
 * - Verify the user's identity through KYC/government ID
 * - Use secure key management (HSM, AWS KMS, etc.)
 * - Log all issuance events for audit
 * - Rate limit requests
 * - Implement revocation mechanisms
 */
export class CredentialIssuer {
  private config: IssuerConfig;

  constructor(config: IssuerConfig) {
    this.config = config;
  }

  /**
   * Issues a new credential for a user after identity verification
   *
   * @param birthYear - The verified birth year from the user's government ID
   * @param userId - Optional user identifier for audit logging
   * @returns A signed credential
   */
  async issueCredential(birthYear: number, userId?: string): Promise<SignedCredential> {
    // In production, this would first verify the user's identity
    // through government ID, biometrics, or trusted identity provider

    // Create the base credential
    const credential = await createCredential(birthYear);

    // Sign the credential
    const signature = this.signCredential(credential);

    const signedCredential: SignedCredential = {
      credential,
      issuer: this.config.name,
      signature,
      issuedAt: new Date().toISOString(),
    };

    // In production: log this issuance event for audit trail
    this.logIssuance(signedCredential, userId);

    return signedCredential;
  }

  /**
   * Signs a credential using the issuer's private key
   * (Simplified - production should use proper digital signatures)
   */
  private signCredential(credential: Credential): string {
    const message = JSON.stringify({
      id: credential.id,
      commitment: credential.commitment,
      createdAt: credential.createdAt,
    });

    // HMAC signature using the issuer's signing key
    const hmac = createHash('sha256')
      .update(this.config.signingKey)
      .update(message)
      .digest('hex');

    return hmac;
  }

  /**
   * Verifies a signed credential's signature
   */
  static verifySignature(signedCredential: SignedCredential, publicKey: string): boolean {
    const message = JSON.stringify({
      id: signedCredential.credential.id,
      commitment: signedCredential.credential.commitment,
      createdAt: signedCredential.credential.createdAt,
    });

    const expectedSignature = createHash('sha256')
      .update(publicKey)
      .update(message)
      .digest('hex');

    return expectedSignature === signedCredential.signature;
  }

  /**
   * Audit logging for credential issuance
   */
  private logIssuance(signedCredential: SignedCredential, userId?: string): void {
    // In production, this would write to a secure audit log
    const logEntry = {
      timestamp: new Date().toISOString(),
      issuer: this.config.name,
      credentialId: signedCredential.credential.id,
      userId: userId || 'anonymous',
      action: 'issue',
    };

    // For now, just log to console (production would use proper logging service)
    console.log('[ISSUER AUDIT]', JSON.stringify(logEntry));
  }

  /**
   * Creates a new issuer with generated keys (for testing)
   */
  static createTestIssuer(name: string): CredentialIssuer {
    const signingKey = randomBytes(32).toString('hex');
    const publicKey = createHash('sha256').update(signingKey).digest('hex');

    return new CredentialIssuer({
      name,
      signingKey,
      publicKey,
    });
  }
}
