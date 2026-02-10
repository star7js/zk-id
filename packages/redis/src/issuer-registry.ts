import { createPublicKey } from 'crypto';
import type { IssuerRegistry, IssuerRecord } from '@zk-id/sdk';
import type { RedisClient } from './types';
import { ZkIdConfigError } from '@zk-id/core';

export interface RedisIssuerRegistryOptions {
  /** Key prefix for issuer keys (default: "zkid:issuer:") */
  keyPrefix?: string;
}

interface StoredIssuerRecord {
  issuer: string;
  publicKeyPem: string;
  status?: 'active' | 'revoked' | 'suspended';
  validFrom?: string;
  validTo?: string;
  jurisdiction?: string;
  policyUrl?: string;
  auditUrl?: string;
}

/**
 * Redis-backed issuer registry.
 * Stores IssuerRecord as JSON with publicKey serialized to PEM format.
 */
export class RedisIssuerRegistry implements IssuerRegistry {
  private readonly client: RedisClient;
  private readonly keyPrefix: string;

  constructor(client: RedisClient, options: RedisIssuerRegistryOptions = {}) {
    this.client = client;
    this.keyPrefix = options.keyPrefix ?? 'zkid:issuer:';
  }

  async getIssuer(issuer: string): Promise<IssuerRecord | null> {
    const key = this.keyPrefix + issuer;
    const value = await this.client.get(key);

    if (value === null) {
      return null;
    }

    let stored: StoredIssuerRecord;
    try {
      stored = JSON.parse(value) as StoredIssuerRecord;
    } catch (error) {
      throw new ZkIdConfigError(
        `Failed to parse issuer record from Redis: ${error instanceof Error ? error.message : String(error)}`,
      );
    }

    const publicKey = createPublicKey({
      key: stored.publicKeyPem,
      format: 'pem',
      type: 'spki',
    });

    return {
      issuer: stored.issuer,
      publicKey,
      status: stored.status,
      validFrom: stored.validFrom,
      validTo: stored.validTo,
      jurisdiction: stored.jurisdiction,
      policyUrl: stored.policyUrl,
      auditUrl: stored.auditUrl,
    };
  }

  /**
   * Helper method to store an issuer record (not part of IssuerRegistry interface).
   */
  async setIssuer(record: IssuerRecord): Promise<void> {
    const key = this.keyPrefix + record.issuer;
    const publicKeyPem = record.publicKey.export({ type: 'spki', format: 'pem' }) as string;

    const stored: StoredIssuerRecord = {
      issuer: record.issuer,
      publicKeyPem,
      status: record.status,
      validFrom: record.validFrom,
      validTo: record.validTo,
      jurisdiction: record.jurisdiction,
      policyUrl: record.policyUrl,
      auditUrl: record.auditUrl,
    };

    await this.client.set(key, JSON.stringify(stored));
  }

  /**
   * Helper method to remove an issuer record (not part of IssuerRegistry interface).
   */
  async removeIssuer(issuer: string): Promise<void> {
    const key = this.keyPrefix + issuer;
    await this.client.del(key);
  }
}
