import { createCredential, Credential, RevocationStore, SignedCredential, credentialSignaturePayload, AuditLogger, ConsoleAuditLogger } from '@zk-id/core';
import { generateKeyPairSync, sign, verify, KeyObject } from 'crypto';

/**
 * IssuerConfig defines the configuration for a credential issuer
 */
export interface IssuerConfig {
  /** Name of the issuing authority */
  name: string;
  /** Ed25519 private signing key (for testing - production should use HSM/KMS) */
  signingKey: KeyObject;
  /** Ed25519 public verification key */
  publicKey: KeyObject;
  /** Optional audit logger (defaults to ConsoleAuditLogger) */
  auditLogger?: AuditLogger;
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
  private revocationStore?: RevocationStore;
  private auditLogger: AuditLogger;

  constructor(config: IssuerConfig) {
    this.config = config;
    this.auditLogger = config.auditLogger ?? new ConsoleAuditLogger();
  }

  /**
   * Issues a new credential for a user after identity verification
   *
   * @param birthYear - The verified birth year from the user's government ID
   * @param nationality - The verified nationality (ISO 3166-1 numeric code)
   * @param userId - Optional user identifier for audit logging
   * @returns A signed credential
   */
  async issueCredential(
    birthYear: number,
    nationality: number,
    userId?: string
  ): Promise<SignedCredential> {
    // In production, this would first verify the user's identity
    // through government ID, biometrics, or trusted identity provider

    // Create the base credential
    const credential = await createCredential(birthYear, nationality);

    // Sign the credential (issuer identity bound into signature)
    const issuedAt = new Date().toISOString();
    const signature = this.signCredential(credential, issuedAt);

    const signedCredential: SignedCredential = {
      credential,
      issuer: this.config.name,
      signature,
      issuedAt,
    };

    // In production: log this issuance event for audit trail
    this.logIssuance(signedCredential, userId);

    return signedCredential;
  }

  /**
   * Signs a credential using the issuer's Ed25519 private key.
   *
   * The signature binds the credential to this issuer's identity,
   * preventing issuer substitution attacks.
   */
  private signCredential(credential: Credential, issuedAt: string): string {
    const message = credentialSignaturePayload(
      credential,
      this.config.name,
      issuedAt
    );

    // Ed25519 signature using the issuer's private key
    const signature = sign(null, Buffer.from(message), this.config.signingKey);

    return signature.toString('base64');
  }

  /**
   * Verifies a signed credential's Ed25519 signature.
   *
   * Includes issuer and issuance time in the verification payload
   * to prevent issuer substitution attacks.
   */
  static verifySignature(signedCredential: SignedCredential, publicKey: KeyObject): boolean {
    const message = credentialSignaturePayload(
      signedCredential.credential,
      signedCredential.issuer,
      signedCredential.issuedAt
    );

    try {
      const signature = Buffer.from(signedCredential.signature, 'base64');
      return verify(null, Buffer.from(message), publicKey, signature);
    } catch {
      return false;
    }
  }

  /**
   * Audit logging for credential issuance
   */
  private logIssuance(signedCredential: SignedCredential, userId?: string): void {
    this.auditLogger.log({
      timestamp: new Date().toISOString(),
      action: 'issue',
      actor: this.config.name,
      target: signedCredential.credential.id,
      success: true,
      metadata: { userId: userId || 'anonymous' },
    });
  }

  /**
   * Set the revocation store for this issuer
   */
  setRevocationStore(store: RevocationStore): void {
    this.revocationStore = store;
  }

  /**
   * Revoke a credential commitment
   */
  async revokeCredential(commitment: string): Promise<void> {
    if (!this.revocationStore) {
      throw new Error('Revocation store not configured');
    }

    await this.revocationStore.revoke(commitment);

    this.auditLogger.log({
      timestamp: new Date().toISOString(),
      action: 'revoke',
      actor: this.config.name,
      target: commitment,
      success: true,
    });
  }

  /**
   * Check if a credential has been revoked
   */
  async isCredentialRevoked(commitment: string): Promise<boolean> {
    if (!this.revocationStore) {
      return false;
    }

    return this.revocationStore.isRevoked(commitment);
  }

  /**
   * Creates a new issuer with generated Ed25519 keys (for testing)
   */
  static createTestIssuer(name: string): CredentialIssuer {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');

    return new CredentialIssuer({
      name,
      signingKey: privateKey,
      publicKey: publicKey,
    });
  }

  /**
   * Get issuer public key for verification
   */
  getPublicKey(): KeyObject {
    return this.config.publicKey;
  }

  /**
   * Get issuer name
   */
  getIssuerName(): string {
    return this.config.name;
  }
}
