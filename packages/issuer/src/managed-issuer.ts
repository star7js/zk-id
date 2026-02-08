import {
  createCredential,
  Credential,
  RevocationStore,
  SignedCredential,
  credentialSignaturePayload,
} from '@zk-id/core';
import { IssuerKeyManager } from './key-management';

/**
 * Credential issuer that delegates signing to a key manager (KMS/HSM).
 */
export class ManagedCredentialIssuer {
  private keyManager: IssuerKeyManager;
  private revocationStore?: RevocationStore;

  constructor(keyManager: IssuerKeyManager) {
    this.keyManager = keyManager;
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
    const logEntry = {
      timestamp: new Date().toISOString(),
      issuer: this.keyManager.getIssuerName(),
      commitment,
      action: 'revoke',
    };
    console.log('[ISSUER AUDIT]', JSON.stringify(logEntry));
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
    const logEntry = {
      timestamp: new Date().toISOString(),
      issuer: this.keyManager.getIssuerName(),
      credentialId: signedCredential.credential.id,
      userId: userId || 'anonymous',
      action: 'issue',
    };

    console.log('[ISSUER AUDIT]', JSON.stringify(logEntry));
  }
}
