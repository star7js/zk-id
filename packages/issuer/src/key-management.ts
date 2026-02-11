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
    if (process.env.NODE_ENV === 'production') {
      console.warn(
        '[zk-id] InMemoryIssuerKeyManager is not suitable for production. ' +
          'Private keys are held in process memory. Use a KMS/HSM-backed key manager.',
      );
    }
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
