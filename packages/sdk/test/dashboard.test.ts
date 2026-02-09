import { expect } from 'chai';
import { generateKeyPairSync, KeyObject } from 'crypto';
import {
  InMemoryAuditLogger,
  InMemoryRevocationStore,
} from '@zk-id/core';
import { InMemoryIssuerRegistry, IssuerRecord } from '../src/server';
import { IssuerDashboard } from '../src/dashboard';

describe('IssuerDashboard', () => {
  let auditLogger: InMemoryAuditLogger;
  let registry: InMemoryIssuerRegistry;
  let dashboard: IssuerDashboard;
  let issuerKey1: KeyObject;
  let issuerKey2: KeyObject;

  beforeEach(() => {
    auditLogger = new InMemoryAuditLogger();
    issuerKey1 = generateKeyPairSync('ed25519').publicKey;
    issuerKey2 = generateKeyPairSync('ed25519').publicKey;

    const records: IssuerRecord[] = [
      {
        issuer: 'Gov-ID',
        publicKey: issuerKey1,
        status: 'active',
        jurisdiction: 'US',
      },
      {
        issuer: 'Bank-ID',
        publicKey: issuerKey2,
        status: 'active',
        jurisdiction: 'DE',
      },
    ];

    registry = new InMemoryIssuerRegistry(records, auditLogger);
    dashboard = new IssuerDashboard(registry, auditLogger);
    dashboard.trackIssuer('Gov-ID');
    dashboard.trackIssuer('Bank-ID');
  });

  describe('getStats()', () => {
    it('should return stats for all tracked issuers', async () => {
      const stats = await dashboard.getStats();

      expect(stats.totalIssuers).to.equal(2);
      expect(stats.activeIssuers).to.equal(2);
      expect(stats.suspendedIssuers).to.equal(0);
      expect(stats.revokedIssuers).to.equal(0);
      expect(stats.issuers).to.have.lengthOf(2);
      expect(stats.computedAt).to.be.a('string');
    });

    it('should count credentials issued from audit log', async () => {
      // Simulate issuance events
      auditLogger.log({
        timestamp: new Date().toISOString(),
        action: 'issue',
        actor: 'Gov-ID',
        target: 'cred-1',
        success: true,
      });
      auditLogger.log({
        timestamp: new Date().toISOString(),
        action: 'issue',
        actor: 'Gov-ID',
        target: 'cred-2',
        success: true,
      });
      auditLogger.log({
        timestamp: new Date().toISOString(),
        action: 'issue',
        actor: 'Bank-ID',
        target: 'cred-3',
        success: true,
      });

      const stats = await dashboard.getStats();

      expect(stats.totalCredentialsIssued).to.equal(3);
      const govSummary = stats.issuers.find((i) => i.issuer === 'Gov-ID');
      expect(govSummary!.credentialsIssued).to.equal(2);
      const bankSummary = stats.issuers.find((i) => i.issuer === 'Bank-ID');
      expect(bankSummary!.credentialsIssued).to.equal(1);
    });

    it('should count revocations from audit log', async () => {
      auditLogger.log({
        timestamp: new Date().toISOString(),
        action: 'revoke',
        actor: 'Gov-ID',
        target: 'commitment-1',
        success: true,
      });

      const stats = await dashboard.getStats();

      expect(stats.totalCredentialsRevoked).to.equal(1);
      const govSummary = stats.issuers.find((i) => i.issuer === 'Gov-ID');
      expect(govSummary!.credentialsRevoked).to.equal(1);
    });

    it('should track suspended issuers', async () => {
      registry.suspend('Bank-ID');

      const stats = await dashboard.getStats();

      expect(stats.activeIssuers).to.equal(1);
      expect(stats.suspendedIssuers).to.equal(1);
      const bankSummary = stats.issuers.find((i) => i.issuer === 'Bank-ID');
      expect(bankSummary!.status).to.equal('suspended');
    });

    it('should track revoked issuers', async () => {
      registry.deactivate('Gov-ID');

      const stats = await dashboard.getStats();

      expect(stats.revokedIssuers).to.equal(1);
      const govSummary = stats.issuers.find((i) => i.issuer === 'Gov-ID');
      expect(govSummary!.status).to.equal('revoked');
    });

    it('should include revocation store count when available', async () => {
      const revStore = new InMemoryRevocationStore();
      await revStore.revoke('commitment-a');
      await revStore.revoke('commitment-b');

      const dashWithRev = new IssuerDashboard(
        registry,
        auditLogger,
        revStore
      );
      dashWithRev.trackIssuer('Gov-ID');

      const stats = await dashWithRev.getStats();

      expect(stats.revokedCredentialCount).to.equal(2);
    });

    it('should report null revocation count when no store configured', async () => {
      const stats = await dashboard.getStats();
      expect(stats.revokedCredentialCount).to.be.null;
    });
  });

  describe('getIssuerSummary()', () => {
    it('should return summary for a single issuer', async () => {
      const summary = await dashboard.getIssuerSummary('Gov-ID');

      expect(summary.issuer).to.equal('Gov-ID');
      expect(summary.status).to.equal('active');
      expect(summary.keyCount).to.equal(1);
      expect(summary.activeKeyCount).to.equal(1);
      expect(summary.jurisdiction).to.equal('US');
      expect(summary.credentialsIssued).to.equal(0);
      expect(summary.credentialsRevoked).to.equal(0);
      expect(summary.lastIssuedAt).to.be.null;
    });

    it('should track last issuance timestamp', async () => {
      const ts = new Date().toISOString();
      auditLogger.log({
        timestamp: ts,
        action: 'issue',
        actor: 'Gov-ID',
        target: 'cred-1',
        success: true,
      });

      const summary = await dashboard.getIssuerSummary('Gov-ID');
      expect(summary.lastIssuedAt).to.equal(ts);
    });

    it('should count multiple key records', async () => {
      // Add a second key for rotation
      registry.upsert({
        issuer: 'Gov-ID',
        publicKey: generateKeyPairSync('ed25519').publicKey,
        status: 'active',
        validFrom: new Date().toISOString(),
      });

      const summary = await dashboard.getIssuerSummary('Gov-ID');
      expect(summary.keyCount).to.equal(2);
    });

    it('should return unknown status for unregistered issuer', async () => {
      const summary = await dashboard.getIssuerSummary('Unknown-Issuer');

      expect(summary.status).to.equal('unknown');
      expect(summary.keyCount).to.equal(0);
    });
  });

  describe('trackIssuer / untrackIssuer', () => {
    it('should only include tracked issuers in stats', async () => {
      dashboard.untrackIssuer('Bank-ID');

      const stats = await dashboard.getStats();
      expect(stats.totalIssuers).to.equal(1);
      expect(stats.issuers[0].issuer).to.equal('Gov-ID');
    });

    it('should allow re-tracking after untrack', async () => {
      dashboard.untrackIssuer('Bank-ID');
      dashboard.trackIssuer('Bank-ID');

      const stats = await dashboard.getStats();
      expect(stats.totalIssuers).to.equal(2);
    });
  });
});
