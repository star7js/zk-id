/**
 * KMS/HSM integration examples for zk-id issuer key management.
 *
 * These classes demonstrate how to implement the IssuerKeyManager interface
 * for external key management services. Production deployments should use
 * a KMS or HSM to protect signing keys.
 *
 * Included examples:
 * - EnvelopeKeyManager: Wraps a local Ed25519 key with a master key (envelope encryption)
 * - FileKeyManager: Loads Ed25519 keys from PEM files on disk
 *
 * For cloud KMS integration (AWS KMS, GCP Cloud KMS, Azure Key Vault),
 * implement the IssuerKeyManager interface and delegate sign() to the
 * cloud provider's asymmetric signing API.
 */

import {
  KeyObject,
  createCipheriv,
  createDecipheriv,
  randomBytes,
  sign,
  createPublicKey,
  createPrivateKey,
} from 'crypto';
import { IssuerKeyManager } from './key-management';
import { ZkIdCryptoError } from '@zk-id/core';

// ---------------------------------------------------------------------------
// Envelope Key Manager
// ---------------------------------------------------------------------------

/**
 * Sealed key bundle produced by EnvelopeKeyManager.seal().
 * Can be stored on disk or in a database. The private key is
 * encrypted with a master key using AES-256-GCM.
 */
export interface SealedKeyBundle {
  /** Encrypted private key (hex) */
  encryptedPrivateKey: string;
  /** AES-GCM initialization vector (hex) */
  iv: string;
  /** AES-GCM auth tag (hex) */
  authTag: string;
  /** Public key in PEM format */
  publicKeyPem: string;
  /** Issuer name */
  issuerName: string;
}

/**
 * Key manager that protects the signing key with envelope encryption.
 *
 * The Ed25519 private key is encrypted at rest using a master key
 * (AES-256-GCM). The master key can be derived from a passphrase,
 * loaded from an environment variable, or fetched from a KMS.
 *
 * Usage:
 * ```typescript
 * // Seal (one-time setup)
 * const masterKey = randomBytes(32);
 * const bundle = await EnvelopeKeyManager.seal('My Issuer', masterKey);
 * // Store bundle to disk/database, keep masterKey in KMS
 *
 * // Unseal (at startup)
 * const manager = await EnvelopeKeyManager.unseal(bundle, masterKey);
 * const issuer = new ManagedCredentialIssuer(manager);
 * ```
 */
export class EnvelopeKeyManager implements IssuerKeyManager {
  private issuerName: string;
  private privateKey: KeyObject;
  private publicKey: KeyObject;

  private constructor(issuerName: string, privateKey: KeyObject, publicKey: KeyObject) {
    this.issuerName = issuerName;
    this.privateKey = privateKey;
    this.publicKey = publicKey;
  }

  /**
   * Get the issuer's identifier.
   *
   * @returns The issuer name
   */
  getIssuerName(): string {
    return this.issuerName;
  }

  /**
   * Get the issuer's Ed25519 public verification key.
   *
   * @returns The public key as a Node.js KeyObject
   */
  getPublicKey(): KeyObject {
    return this.publicKey;
  }

  /**
   * Sign a payload using the decrypted private key.
   *
   * The private key is decrypted on-demand for each signature operation.
   * Uses Node.js crypto.sign with Ed25519.
   *
   * @param payload - The data to sign
   * @returns Ed25519 signature
   */
  async sign(payload: Buffer): Promise<Buffer> {
    return sign(null, payload, this.privateKey);
  }

  /**
   * Generate a new Ed25519 key pair and seal it with the master key.
   *
   * @param issuerName - Name of the issuer
   * @param masterKey - 32-byte AES-256 master key
   * @returns Sealed key bundle for persistent storage
   */
  static async seal(issuerName: string, masterKey: Buffer): Promise<SealedKeyBundle> {
    if (masterKey.length !== 32) {
      throw new ZkIdCryptoError('Master key must be 32 bytes (AES-256)');
    }

    const { privateKey, publicKey } = await import('crypto').then((c) =>
      c.generateKeyPairSync('ed25519'),
    );

    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', masterKey, iv);
    const pkDer = privateKey.export({ type: 'pkcs8', format: 'der' });

    const encrypted = Buffer.concat([cipher.update(pkDer), cipher.final()]);
    const authTag = cipher.getAuthTag();

    return {
      encryptedPrivateKey: encrypted.toString('hex'),
      iv: iv.toString('hex'),
      authTag: authTag.toString('hex'),
      publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
      issuerName,
    };
  }

  /**
   * Unseal a key bundle to produce a usable key manager.
   *
   * @param bundle - Previously sealed key bundle
   * @param masterKey - Same 32-byte master key used to seal
   * @returns EnvelopeKeyManager ready for signing
   */
  static async unseal(bundle: SealedKeyBundle, masterKey: Buffer): Promise<EnvelopeKeyManager> {
    if (masterKey.length !== 32) {
      throw new ZkIdCryptoError('Master key must be 32 bytes (AES-256)');
    }

    const iv = Buffer.from(bundle.iv, 'hex');
    const authTag = Buffer.from(bundle.authTag, 'hex');
    const encrypted = Buffer.from(bundle.encryptedPrivateKey, 'hex');

    const decipher = createDecipheriv('aes-256-gcm', masterKey, iv, {
      authTagLength: 16, // 16 bytes = 128 bits (standard for GCM)
    });
    decipher.setAuthTag(authTag);

    const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);

    const privateKey = createPrivateKey({
      key: decrypted,
      format: 'der',
      type: 'pkcs8',
    });
    const publicKey = createPublicKey(bundle.publicKeyPem);

    return new EnvelopeKeyManager(bundle.issuerName, privateKey, publicKey);
  }
}

// ---------------------------------------------------------------------------
// File Key Manager
// ---------------------------------------------------------------------------

/**
 * Key manager that loads Ed25519 keys from PEM files.
 *
 * Suitable for development and simple deployments where keys are
 * stored as files with restricted filesystem permissions.
 *
 * Usage:
 * ```typescript
 * const manager = FileKeyManager.fromPemFiles(
 *   'My Issuer',
 *   '/etc/zk-id/issuer.key',
 *   '/etc/zk-id/issuer.pub'
 * );
 * const issuer = new ManagedCredentialIssuer(manager);
 * ```
 */
export class FileKeyManager implements IssuerKeyManager {
  private issuerName: string;
  private privateKey: KeyObject;
  private publicKey: KeyObject;

  constructor(issuerName: string, privateKey: KeyObject, publicKey: KeyObject) {
    this.issuerName = issuerName;
    this.privateKey = privateKey;
    this.publicKey = publicKey;
  }

  /**
   * Get the issuer's identifier.
   *
   * @returns The issuer name
   */
  getIssuerName(): string {
    return this.issuerName;
  }

  /**
   * Get the issuer's Ed25519 public verification key.
   *
   * @returns The public key as a Node.js KeyObject
   */
  getPublicKey(): KeyObject {
    return this.publicKey;
  }

  /**
   * Sign a payload using the Ed25519 private key.
   *
   * Uses Node.js crypto.sign with Ed25519 algorithm.
   *
   * @param payload - The data to sign
   * @returns Ed25519 signature
   */
  async sign(payload: Buffer): Promise<Buffer> {
    return sign(null, payload, this.privateKey);
  }

  /**
   * Load keys from PEM-encoded files.
   *
   * @param issuerName - Name of the issuer
   * @param privateKeyPath - Path to Ed25519 private key PEM
   * @param publicKeyPath - Path to Ed25519 public key PEM
   * @returns FileKeyManager ready for signing
   */
  static fromPemFiles(
    issuerName: string,
    privateKeyPath: string,
    publicKeyPath: string,
  ): FileKeyManager {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const fs = require('fs');
    const privateKeyPem = fs.readFileSync(privateKeyPath, 'utf8');
    const publicKeyPem = fs.readFileSync(publicKeyPath, 'utf8');

    const privateKey = createPrivateKey(privateKeyPem);
    const publicKey = createPublicKey(publicKeyPem);

    return new FileKeyManager(issuerName, privateKey, publicKey);
  }

  /**
   * Create a FileKeyManager from PEM strings (no filesystem access needed).
   *
   * Useful when keys are loaded from environment variables, configuration
   * stores, or secret management systems instead of files.
   *
   * @param issuerName - Name of the issuer
   * @param privateKeyPem - Ed25519 private key in PEM format
   * @param publicKeyPem - Ed25519 public key in PEM format
   * @returns FileKeyManager ready for signing
   */
  static fromPemStrings(
    issuerName: string,
    privateKeyPem: string,
    publicKeyPem: string,
  ): FileKeyManager {
    const privateKey = createPrivateKey(privateKeyPem);
    const publicKey = createPublicKey(publicKeyPem);

    return new FileKeyManager(issuerName, privateKey, publicKey);
  }
}
