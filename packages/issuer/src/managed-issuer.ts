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
 */
export class ManagedCredentialIssuer {
  private keyManager: IssuerKeyManager;
  private revocationStore?: RevocationStore;
  private auditLogger: AuditLogger;

  constructor(keyManager: IssuerKeyManager, auditLogger?: AuditLogger) {
    this.keyManager = keyManager;
    this.auditLogger = auditLogger ?? new ConsoleAuditLogger();
  }

  async issueCredential(
    birthYear: number,
    nationality: number,
    userId?: string
  ): Promise<SignedCredential> {
    const credential = await createCredential(birthYear, nationality);
    const signature = await this.signCredential(credential);

    const signedCredential: SignedCredential = {
      credential,
      issuer: this.keyManager.getIssuerName(),
      signature,
      issuedAt: new Date().toISOString(),
    };

    this.logIssuance(signedCredential, userId);
    return signedCredential;
  }

  private async signCredential(credential: Credential): Promise<string> {
    const message = credentialSignaturePayload(credential);
    const signature = await this.keyManager.sign(Buffer.from(message));
    return signature.toString('base64');
  }

  setRevocationStore(store: RevocationStore): void {
    this.revocationStore = store;
  }

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

  async isCredentialRevoked(commitment: string): Promise<boolean> {
    if (!this.revocationStore) {
      return false;
    }

    return this.revocationStore.isRevoked(commitment);
  }

  getPublicKey() {
    return this.keyManager.getPublicKey();
  }

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
