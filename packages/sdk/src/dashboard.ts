/**
 * Issuer dashboard data layer.
 *
 * Aggregates statistics from the issuer registry, audit log, and
 * revocation store to provide a summary view for operational monitoring.
 * This is a data-layer prototype; a full dashboard UI is out of scope.
 */

import { InMemoryAuditLogger, RevocationStore } from '@zk-id/core';
import { IssuerRegistry, IssuerRecord } from './server';

// ---------------------------------------------------------------------------
// Dashboard Types
// ---------------------------------------------------------------------------

/**
 * Summary statistics for a single issuer.
 */
export interface IssuerSummary {
  /** Issuer name/identifier */
  issuer: string;
  /** Current status */
  status: 'active' | 'revoked' | 'suspended' | 'unknown';
  /** Number of registered key records */
  keyCount: number;
  /** Number of active keys (within validity window) */
  activeKeyCount: number;
  /** Number of credentials issued (from audit log) */
  credentialsIssued: number;
  /** Number of credentials revoked (from audit log) */
  credentialsRevoked: number;
  /** Most recent issuance timestamp (ISO 8601, or null) */
  lastIssuedAt: string | null;
  /** Jurisdiction (from registry metadata) */
  jurisdiction: string | null;
}

/**
 * Aggregate dashboard statistics.
 */
export interface DashboardStats {
  /** Total number of registered issuers */
  totalIssuers: number;
  /** Number of active issuers */
  activeIssuers: number;
  /** Number of suspended issuers */
  suspendedIssuers: number;
  /** Number of revoked issuers */
  revokedIssuers: number;
  /** Total credentials issued across all issuers */
  totalCredentialsIssued: number;
  /** Total credentials revoked across all issuers */
  totalCredentialsRevoked: number;
  /** Total number of revoked credentials in the revocation store (if available) */
  revokedCredentialCount: number | null;
  /** Per-issuer summaries */
  issuers: IssuerSummary[];
  /** Timestamp when stats were computed */
  computedAt: string;
}

// ---------------------------------------------------------------------------
// Dashboard Implementation
// ---------------------------------------------------------------------------

/**
 * Extended registry interface that supports listing all issuers.
 * The base IssuerRegistry only has getIssuer(); the dashboard needs
 * to enumerate. InMemoryIssuerRegistry supports listRecords().
 */
export interface DashboardIssuerRegistry extends IssuerRegistry {
  /** List all records for a given issuer (for key counting) */
  listRecords(issuer: string): Promise<IssuerRecord[]>;
}

/**
 * Issuer dashboard aggregating stats from registry, audit log,
 * and revocation store.
 *
 * Usage:
 * ```typescript
 * const auditLogger = new InMemoryAuditLogger();
 * const registry = new InMemoryIssuerRegistry(records, auditLogger);
 * const dashboard = new IssuerDashboard(registry, auditLogger);
 *
 * // Register issuer names for tracking
 * dashboard.trackIssuer('Government-ID');
 * dashboard.trackIssuer('Bank-ID');
 *
 * const stats = await dashboard.getStats();
 * console.log(`Active issuers: ${stats.activeIssuers}`);
 * ```
 */
export class IssuerDashboard {
  private registry: DashboardIssuerRegistry;
  private auditLogger: InMemoryAuditLogger;
  private revocationStore?: RevocationStore;
  private trackedIssuers: Set<string> = new Set();

  constructor(
    registry: DashboardIssuerRegistry,
    auditLogger: InMemoryAuditLogger,
    revocationStore?: RevocationStore,
  ) {
    this.registry = registry;
    this.auditLogger = auditLogger;
    this.revocationStore = revocationStore;
  }

  /**
   * Register an issuer name for dashboard tracking.
   */
  trackIssuer(issuer: string): void {
    this.trackedIssuers.add(issuer);
  }

  /**
   * Unregister an issuer from dashboard tracking.
   */
  untrackIssuer(issuer: string): void {
    this.trackedIssuers.delete(issuer);
  }

  /**
   * Compute dashboard statistics from all data sources.
   */
  async getStats(): Promise<DashboardStats> {
    const issuers: IssuerSummary[] = [];

    for (const issuerName of this.trackedIssuers) {
      const summary = await this.getIssuerSummary(issuerName);
      issuers.push(summary);
    }

    const activeIssuers = issuers.filter((i) => i.status === 'active').length;
    const suspendedIssuers = issuers.filter((i) => i.status === 'suspended').length;
    const revokedIssuers = issuers.filter((i) => i.status === 'revoked').length;

    const totalCredentialsIssued = issuers.reduce((sum, i) => sum + i.credentialsIssued, 0);
    const totalCredentialsRevoked = issuers.reduce((sum, i) => sum + i.credentialsRevoked, 0);

    let revokedCredentialCount: number | null = null;
    if (this.revocationStore) {
      revokedCredentialCount = await this.revocationStore.getRevokedCount();
    }

    return {
      totalIssuers: issuers.length,
      activeIssuers,
      suspendedIssuers,
      revokedIssuers,
      totalCredentialsIssued,
      totalCredentialsRevoked,
      revokedCredentialCount,
      issuers,
      computedAt: new Date().toISOString(),
    };
  }

  /**
   * Get summary statistics for a single issuer.
   */
  async getIssuerSummary(issuerName: string): Promise<IssuerSummary> {
    // Get registry records
    const records = await this.registry.listRecords(issuerName);
    const currentRecord = await this.registry.getIssuer(issuerName);

    // Count active keys
    const now = Date.now();
    const activeKeyCount = records.filter((r) => {
      if (r.status && r.status !== 'active') return false;
      if (r.validFrom && Date.parse(r.validFrom) > now) return false;
      if (r.validTo && Date.parse(r.validTo) < now) return false;
      return true;
    }).length;

    // Count audit events
    const issueEntries = this.auditLogger.entries.filter(
      (e) => e.action === 'issue' && e.actor === issuerName,
    );
    const revokeEntries = this.auditLogger.entries.filter(
      (e) => e.action === 'revoke' && e.actor === issuerName,
    );

    // Find most recent issuance
    let lastIssuedAt: string | null = null;
    if (issueEntries.length > 0) {
      lastIssuedAt = issueEntries[issueEntries.length - 1].timestamp;
    }

    return {
      issuer: issuerName,
      status: currentRecord?.status ?? 'unknown',
      keyCount: records.length,
      activeKeyCount,
      credentialsIssued: issueEntries.length,
      credentialsRevoked: revokeEntries.length,
      lastIssuedAt,
      jurisdiction: currentRecord?.jurisdiction ?? null,
    };
  }
}
