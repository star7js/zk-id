import {
  createCredential,
  Credential,
  RevocationStore,
  SignedCredential,
  credentialSignaturePayload,
  AuditLogger,
  ConsoleAuditLogger,
} from '@zk-id/core';
import { IssuerKeyManager } from './key-management';

/**
 * Credential issuer that delegates signing to a key manager (KMS/HSM).
 *
 * This is the production-ready issuer implementation that supports KMS/HSM
 * backends for secure key management. It uses standard Ed25519 signatures
 * (not circuit-compatible) and integrates with optional revocation stores
 * and audit logging.
 */
export class ManagedCredentialIssuer {
  private keyManager: IssuerKeyManager;
  private revocationStore?: RevocationStore;
  private auditLogger: AuditLogger;

  /**
   * Create a new managed credential issuer.
   *
   * @param keyManager - Key management backend (KMS, HSM, or file-based)
   * @param auditLogger - Optional audit logger (defaults to ConsoleAuditLogger)
   */
  constructor(keyManager: IssuerKeyManager, auditLogger?: AuditLogger) {
    this.keyManager = keyManager;
    this.auditLogger = auditLogger ?? new ConsoleAuditLogger();
  }

  /**
   * Issue a new credential with an Ed25519 signature.
   *
   * Creates a credential commitment from the birth year and nationality, then
   * signs it using the key manager's private key. The signature is Base64-encoded
   * and can be verified by the ZkIdServer using the issuer's public key.
   *
   * @param birthYear - The credential holder's birth year (e.g., 1990)
   * @param nationality - ISO 3166-1 numeric nationality code (e.g., 840 for USA)
   * @param userId - Optional user identifier for audit logging
   * @returns A signed credential with Ed25519 signature
   */
  async issueCredential(
    birthYear: number,
    nationality: number,
    userId?: string
  ): Promise<SignedCredential> {
    const credential = await createCredential(birthYear, nationality);
    const issuedAt = new Date().toISOString();
    const signature = await this.signCredential(credential, issuedAt);

    const signedCredential: SignedCredential = {
      credential,
      issuer: this.keyManager.getIssuerName(),
      signature,
      issuedAt,
    };

    this.logIssuance(signedCredential, userId);
    return signedCredential;
  }

  private async signCredential(credential: Credential, issuedAt: string): Promise<string> {
    const message = credentialSignaturePayload(
      credential,
      this.keyManager.getIssuerName(),
      issuedAt
    );
    const signature = await this.keyManager.sign(Buffer.from(message));
    return signature.toString('base64');
  }

  /**
   * Configure a revocation store for this issuer.
   *
   * After calling this method, the issuer can revoke credentials using
   * revokeCredential() and check revocation status with isCredentialRevoked().
   *
   * @param store - Revocation store backend (in-memory, database, or Merkle tree)
   */
  setRevocationStore(store: RevocationStore): void {
    this.revocationStore = store;
  }

  /**
   * Revoke a credential by its commitment hash.
   *
   * Marks the credential as revoked in the revocation store and emits an audit
   * log entry. Throws an error if no revocation store is configured.
   *
   * @param commitment - The credential commitment hash to revoke
   * @throws Error if revocation store is not configured
   */
  async revokeCredential(commitment: string): Promise<void> {
    if (!this.revocationStore) {
      throw new Error('Revocation store not configured');
    }

    await this.revocationStore.revoke(commitment);
    this.auditLogger.log({
      timestamp: new Date().toISOString(),
      action: 'revoke',
      actor: this.keyManager.getIssuerName(),
      target: commitment,
      success: true,
    });
  }

  /**
   * Check if a credential has been revoked.
   *
   * @param commitment - The credential commitment hash to check
   * @returns true if the credential is revoked, false otherwise (or if no revocation store is configured)
   */
  async isCredentialRevoked(commitment: string): Promise<boolean> {
    if (!this.revocationStore) {
      return false;
    }

    return this.revocationStore.isRevoked(commitment);
  }

  /**
   * Get the issuer's Ed25519 public verification key.
   *
   * @returns The public key as a Node.js KeyObject
   */
  getPublicKey() {
    return this.keyManager.getPublicKey();
  }

  /**
   * Get the issuer's identifier.
   *
   * @returns The issuer name (e.g., "gov-id-issuer" or "did:example:123")
   */
  getIssuerName(): string {
    return this.keyManager.getIssuerName();
  }

  private logIssuance(signedCredential: SignedCredential, userId?: string): void {
    this.auditLogger.log({
      timestamp: new Date().toISOString(),
      action: 'issue',
      actor: this.keyManager.getIssuerName(),
      target: signedCredential.credential.id,
      success: true,
      metadata: { userId: userId || 'anonymous' },
    });
  }
}
