import { expect } from 'chai';
import { generateKeyPairSync } from 'crypto';
import {
  checkKeyRotation,
  validateIssuerPolicy,
  generateRotationPlan,
  DEFAULT_ISSUER_POLICY,
  STRICT_ISSUER_POLICY,
  IssuerPolicy,
  IssuerRecordForPolicy,
} from '../src/policy';

describe('Issuer Policy', () => {
  const { publicKey } = generateKeyPairSync('ed25519');

  const makeRecord = (
    overrides: Partial<IssuerRecordForPolicy> = {}
  ): IssuerRecordForPolicy => ({
    issuer: 'Test-Issuer',
    publicKey,
    status: 'active',
    ...overrides,
  });

  describe('DEFAULT_ISSUER_POLICY', () => {
    it('should have reasonable defaults', () => {
      expect(DEFAULT_ISSUER_POLICY.maxKeyAgeDays).to.equal(365);
      expect(DEFAULT_ISSUER_POLICY.rotationWarningDays).to.equal(30);
      expect(DEFAULT_ISSUER_POLICY.minRotationOverlapDays).to.equal(14);
      expect(DEFAULT_ISSUER_POLICY.requiredAlgorithm).to.equal('ed25519');
      expect(DEFAULT_ISSUER_POLICY.maxCredentialsPerKey).to.equal(0);
      expect(DEFAULT_ISSUER_POLICY.requirePolicyUrl).to.be.false;
      expect(DEFAULT_ISSUER_POLICY.requireJurisdiction).to.be.false;
    });
  });

  describe('STRICT_ISSUER_POLICY', () => {
    it('should be stricter than defaults', () => {
      expect(STRICT_ISSUER_POLICY.maxKeyAgeDays).to.be.lessThan(
        DEFAULT_ISSUER_POLICY.maxKeyAgeDays
      );
      expect(STRICT_ISSUER_POLICY.maxCredentialsPerKey).to.be.greaterThan(0);
      expect(STRICT_ISSUER_POLICY.requirePolicyUrl).to.be.true;
      expect(STRICT_ISSUER_POLICY.requireJurisdiction).to.be.true;
    });
  });

  describe('checkKeyRotation', () => {
    const policy: IssuerPolicy = {
      ...DEFAULT_ISSUER_POLICY,
      maxKeyAgeDays: 90,
      rotationWarningDays: 14,
    };

    it('should report healthy key within validity', () => {
      const tenDaysAgo = new Date(
        Date.now() - 10 * 24 * 60 * 60 * 1000
      ).toISOString();
      const status = checkKeyRotation(tenDaysAgo, policy);

      expect(status.rotationRequired).to.be.false;
      expect(status.rotationWarning).to.be.false;
      expect(status.daysUntilExpiry).to.equal(80);
      expect(status.keyAgeDays).to.equal(10);
    });

    it('should warn when key is nearing expiry', () => {
      const eightyDaysAgo = new Date(
        Date.now() - 80 * 24 * 60 * 60 * 1000
      ).toISOString();
      const status = checkKeyRotation(eightyDaysAgo, policy);

      expect(status.rotationRequired).to.be.false;
      expect(status.rotationWarning).to.be.true;
      expect(status.daysUntilExpiry).to.equal(10);
      expect(status.message).to.include('rotation recommended');
    });

    it('should require rotation when key is expired', () => {
      const hundredDaysAgo = new Date(
        Date.now() - 100 * 24 * 60 * 60 * 1000
      ).toISOString();
      const status = checkKeyRotation(hundredDaysAgo, policy);

      expect(status.rotationRequired).to.be.true;
      expect(status.rotationWarning).to.be.true;
      expect(status.daysUntilExpiry).to.be.lessThan(0);
      expect(status.message).to.include('rotation required');
    });

    it('should handle invalid date', () => {
      const status = checkKeyRotation('not-a-date', policy);

      expect(status.rotationRequired).to.be.true;
      expect(status.message).to.include('Invalid');
    });

    it('should use default policy when none provided', () => {
      const recentDate = new Date().toISOString();
      const status = checkKeyRotation(recentDate);

      expect(status.rotationRequired).to.be.false;
      expect(status.daysUntilExpiry).to.be.approximately(365, 1);
    });
  });

  describe('validateIssuerPolicy', () => {
    it('should pass for a valid active issuer', () => {
      const record = makeRecord();
      const result = validateIssuerPolicy(record);

      expect(result.valid).to.be.true;
      expect(result.violations).to.have.lengthOf(0);
    });

    it('should fail for suspended issuer', () => {
      const record = makeRecord({ status: 'suspended' });
      const result = validateIssuerPolicy(record);

      expect(result.valid).to.be.false;
      expect(result.violations[0]).to.include('suspended');
    });

    it('should fail for revoked issuer', () => {
      const record = makeRecord({ status: 'revoked' });
      const result = validateIssuerPolicy(record);

      expect(result.valid).to.be.false;
      expect(result.violations[0]).to.include('revoked');
    });

    it('should fail when key has expired based on validFrom', () => {
      const twoYearsAgo = new Date(
        Date.now() - 730 * 24 * 60 * 60 * 1000
      ).toISOString();
      const record = makeRecord({ validFrom: twoYearsAgo });
      const result = validateIssuerPolicy(record);

      expect(result.valid).to.be.false;
      expect(result.violations[0]).to.include('rotation required');
    });

    it('should warn when key is nearing expiry', () => {
      const elevenMonthsAgo = new Date(
        Date.now() - 340 * 24 * 60 * 60 * 1000
      ).toISOString();
      const record = makeRecord({ validFrom: elevenMonthsAgo });
      const result = validateIssuerPolicy(record);

      expect(result.valid).to.be.true;
      expect(result.warnings.length).to.be.greaterThan(0);
      expect(result.warnings[0]).to.include('rotation recommended');
    });

    it('should fail when validTo has passed', () => {
      const yesterday = new Date(
        Date.now() - 24 * 60 * 60 * 1000
      ).toISOString();
      const record = makeRecord({ validTo: yesterday });
      const result = validateIssuerPolicy(record);

      expect(result.valid).to.be.false;
      expect(result.violations).to.satisfy((v: string[]) =>
        v.some((msg) => msg.includes('expired'))
      );
    });

    it('should fail when credential limit is reached', () => {
      const policy: IssuerPolicy = {
        ...DEFAULT_ISSUER_POLICY,
        maxCredentialsPerKey: 1000,
      };
      const record = makeRecord();
      const result = validateIssuerPolicy(record, policy, 1000);

      expect(result.valid).to.be.false;
      expect(result.violations[0]).to.include('limit reached');
    });

    it('should warn when approaching credential limit', () => {
      const policy: IssuerPolicy = {
        ...DEFAULT_ISSUER_POLICY,
        maxCredentialsPerKey: 1000,
      };
      const record = makeRecord();
      const result = validateIssuerPolicy(record, policy, 950);

      expect(result.valid).to.be.true;
      expect(result.warnings[0]).to.include('Approaching');
    });

    it('should enforce strict policy metadata requirements', () => {
      const record = makeRecord(); // no policyUrl or jurisdiction
      const result = validateIssuerPolicy(record, STRICT_ISSUER_POLICY);

      expect(result.valid).to.be.false;
      expect(result.violations).to.satisfy((v: string[]) =>
        v.some((msg) => msg.includes('policyUrl'))
      );
      expect(result.violations).to.satisfy((v: string[]) =>
        v.some((msg) => msg.includes('jurisdiction'))
      );
    });

    it('should pass strict policy when metadata is present', () => {
      const record = makeRecord({
        policyUrl: 'https://example.com/policy',
        jurisdiction: 'US',
      });
      const result = validateIssuerPolicy(record, STRICT_ISSUER_POLICY, 0);

      expect(result.valid).to.be.true;
    });
  });

  describe('generateRotationPlan', () => {
    it('should produce a 4-step rotation plan', () => {
      const sixMonthsAgo = new Date(
        Date.now() - 180 * 24 * 60 * 60 * 1000
      ).toISOString();
      const plan = generateRotationPlan(sixMonthsAgo);

      expect(plan).to.have.lengthOf(4);
      expect(plan[0].action).to.include('Generate');
      expect(plan[1].action).to.include('Activate');
      expect(plan[2].action).to.include('issuing');
      expect(plan[3].action).to.include('Deactivate');
    });

    it('should schedule steps with valid ISO dates', () => {
      const oneMonthAgo = new Date(
        Date.now() - 30 * 24 * 60 * 60 * 1000
      ).toISOString();
      const plan = generateRotationPlan(oneMonthAgo);

      for (const step of plan) {
        const parsed = Date.parse(step.scheduledAt);
        expect(isNaN(parsed)).to.be.false;
      }
    });

    it('should handle invalid date gracefully', () => {
      const plan = generateRotationPlan('bad-date');

      expect(plan).to.have.lengthOf(1);
      expect(plan[0].action).to.include('Fix');
    });

    it('should use custom policy for scheduling', () => {
      const shortPolicy: IssuerPolicy = {
        ...DEFAULT_ISSUER_POLICY,
        maxKeyAgeDays: 30,
        minRotationOverlapDays: 7,
      };
      const twoWeeksAgo = new Date(
        Date.now() - 14 * 24 * 60 * 60 * 1000
      ).toISOString();
      const plan = generateRotationPlan(twoWeeksAgo, shortPolicy);

      expect(plan).to.have.lengthOf(4);
    });
  });
});
