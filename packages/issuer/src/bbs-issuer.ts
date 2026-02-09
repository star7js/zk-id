/**
 * BBS Credential Issuer
 *
 * Issues credentials signed with BBS (BLS12-381) instead of Ed25519.
 * BBS-signed credentials enable selective disclosure: the holder can
 * reveal individual fields to a verifier without exposing the rest,
 * and without needing a ZK-SNARK circuit.
 *
 * Use this when:
 *   - You need field-level selective disclosure (show nationality, hide age)
 *   - You don't need predicate proofs (age >= 18 without revealing birth year)
 *
 * Use the traditional Ed25519 issuer + ZK-SNARK circuits when:
 *   - You need predicate proofs (range checks, equality checks)
 *   - You need nullifiers for sybil resistance
 *   - You need on-chain verification
 */

import { createCredential, AuditLogger, ConsoleAuditLogger } from '@zk-id/core';
import {
  generateBBSKeyPair,
  signBBSMessages,
  credentialFieldsToBBSMessages,
  BBSKeyPair,
  BBSCredential,
  BBS_CREDENTIAL_FIELDS,
} from '@zk-id/core';

export interface BBSIssuerConfig {
  /** Issuer name or DID */
  name: string;
  /** Pre-generated BBS key pair (if omitted, one is generated on create()) */
  keyPair?: BBSKeyPair;
  /** Optional audit logger */
  auditLogger?: AuditLogger;
}

/**
 * Credential issuer that signs with BBS signatures.
 *
 * ```ts
 * const issuer = await BBSCredentialIssuer.create({ name: 'Gov Authority' });
 * const cred = await issuer.issueCredential(1990, 840);
 *
 * // Holder derives selective disclosure proof
 * import { deriveBBSDisclosureProof } from '@zk-id/core';
 * const proof = await deriveBBSDisclosureProof(cred, {
 *   disclose: ['nationality'],
 * });
 * ```
 */
export class BBSCredentialIssuer {
  private keyPair: BBSKeyPair;
  private issuerName: string;
  private auditLogger: AuditLogger;

  private constructor(config: BBSIssuerConfig & { keyPair: BBSKeyPair }) {
    this.keyPair = config.keyPair;
    this.issuerName = config.name;
    this.auditLogger = config.auditLogger ?? new ConsoleAuditLogger();
  }

  /**
   * Create a new BBS credential issuer.
   * Generates a fresh BBS key pair unless one is provided.
   */
  static async create(config: BBSIssuerConfig): Promise<BBSCredentialIssuer> {
    const keyPair = config.keyPair ?? await generateBBSKeyPair();
    return new BBSCredentialIssuer({ ...config, keyPair });
  }

  /**
   * Issue a BBS-signed credential.
   *
   * Each credential field (id, birthYear, nationality, salt, issuedAt,
   * issuer) is signed as a separate BBS message, enabling selective
   * disclosure of individual fields.
   */
  async issueCredential(
    birthYear: number,
    nationality: number,
    userId?: string,
  ): Promise<BBSCredential> {
    const credential = await createCredential(birthYear, nationality);
    const issuedAt = new Date().toISOString();

    const fieldValues: Record<string, string | number> = {
      id: credential.id,
      birthYear: credential.birthYear,
      nationality: credential.nationality,
      salt: credential.salt,
      issuedAt,
      issuer: this.issuerName,
    };

    const { messages, labels } = credentialFieldsToBBSMessages(fieldValues);
    const header = new Uint8Array();

    const signature = await signBBSMessages(
      this.keyPair.secretKey,
      this.keyPair.publicKey,
      messages,
      header,
    );

    const bbsCredential: BBSCredential = {
      id: credential.id,
      messages,
      labels,
      signature,
      header,
      issuerPublicKey: this.keyPair.publicKey,
      fieldValues,
    };

    this.auditLogger.log({
      timestamp: issuedAt,
      action: 'issue',
      actor: this.issuerName,
      target: credential.id,
      success: true,
      metadata: {
        userId: userId || 'anonymous',
        signatureScheme: 'BBS-BLS12-381-SHA-256',
        fieldCount: BBS_CREDENTIAL_FIELDS.length,
      },
    });

    return bbsCredential;
  }

  /** Get the issuer's BBS public key. */
  getPublicKey(): Uint8Array {
    return this.keyPair.publicKey;
  }

  /** Get the issuer name. */
  getIssuerName(): string {
    return this.issuerName;
  }
}
