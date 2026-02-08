import { KeyObject, sign } from 'crypto';

/**
 * Interface for issuer key management (KMS/HSM friendly).
 */
export interface IssuerKeyManager {
  getIssuerName(): string;
  getPublicKey(): KeyObject;
  sign(payload: Buffer): Promise<Buffer>;
}

/**
 * In-memory key manager for testing and local development.
 */
export class InMemoryIssuerKeyManager implements IssuerKeyManager {
  private issuerName: string;
  private privateKey: KeyObject;
  private publicKey: KeyObject;

  constructor(issuerName: string, privateKey: KeyObject, publicKey: KeyObject) {
    this.issuerName = issuerName;
    this.privateKey = privateKey;
    this.publicKey = publicKey;
  }

  getIssuerName(): string {
    return this.issuerName;
  }

  getPublicKey(): KeyObject {
    return this.publicKey;
  }

  async sign(payload: Buffer): Promise<Buffer> {
    return sign(null, payload, this.privateKey);
  }
}
