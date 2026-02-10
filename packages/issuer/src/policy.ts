/**
 * Issuer policy tooling for key rotation and compliance enforcement.
 *
 * Provides configurable policies for key lifecycle management,
 * rotation scheduling, and credential issuance constraints.
 */

import { KeyObject } from 'crypto';

// ---------------------------------------------------------------------------
// Policy Types
// ---------------------------------------------------------------------------

/**
 * Policy configuration for an issuer's key lifecycle and operational limits.
 */
export interface IssuerPolicy {
  /** Maximum age of a signing key in days before rotation is required */
  maxKeyAgeDays: number;
  /** Number of days before key expiry to start warning */
  rotationWarningDays: number;
  /** Minimum overlap in days between old and new keys during rotation */
  minRotationOverlapDays: number;
  /** Required key algorithm (default: 'ed25519') */
  requiredAlgorithm: string;
  /** Maximum number of credentials that may be issued per key (0 = unlimited) */
  maxCredentialsPerKey: number;
  /** Whether issuer must have a policyUrl defined */
  requirePolicyUrl: boolean;
  /** Whether issuer must have a jurisdiction defined */
  requireJurisdiction: boolean;
}

/**
 * Default issuer policy suitable for most deployments.
 */
export const DEFAULT_ISSUER_POLICY: IssuerPolicy = {
  maxKeyAgeDays: 365,
  rotationWarningDays: 30,
  minRotationOverlapDays: 14,
  requiredAlgorithm: 'ed25519',
  maxCredentialsPerKey: 0,
  requirePolicyUrl: false,
  requireJurisdiction: false,
};

/**
 * Strict issuer policy for high-assurance deployments.
 */
export const STRICT_ISSUER_POLICY: IssuerPolicy = {
  maxKeyAgeDays: 180,
  rotationWarningDays: 30,
  minRotationOverlapDays: 14,
  requiredAlgorithm: 'ed25519',
  maxCredentialsPerKey: 100000,
  requirePolicyUrl: true,
  requireJurisdiction: true,
};

// ---------------------------------------------------------------------------
// Key Rotation Status
// ---------------------------------------------------------------------------

/**
 * Result of checking an issuer key's rotation status.
 */
export interface KeyRotationStatus {
  /** Whether the key needs immediate rotation */
  rotationRequired: boolean;
  /** Whether rotation is recommended soon */
  rotationWarning: boolean;
  /** Number of days until the key expires (negative if expired) */
  daysUntilExpiry: number;
  /** Number of days the key has been active */
  keyAgeDays: number;
  /** Human-readable status message */
  message: string;
}

/**
 * Check whether a signing key needs rotation based on policy.
 *
 * @param keyCreatedAt - ISO 8601 timestamp when the key was created or activated
 * @param policy - Issuer policy to check against
 * @param now - Current time (default: Date.now())
 * @returns Key rotation status
 */
export function checkKeyRotation(
  keyCreatedAt: string,
  policy: IssuerPolicy = DEFAULT_ISSUER_POLICY,
  now: number = Date.now(),
): KeyRotationStatus {
  const createdMs = Date.parse(keyCreatedAt);
  if (isNaN(createdMs)) {
    return {
      rotationRequired: true,
      rotationWarning: true,
      daysUntilExpiry: 0,
      keyAgeDays: 0,
      message: 'Invalid key creation date',
    };
  }

  const keyAgeDays = (now - createdMs) / (1000 * 60 * 60 * 24);
  const daysUntilExpiry = policy.maxKeyAgeDays - keyAgeDays;

  if (daysUntilExpiry <= 0) {
    return {
      rotationRequired: true,
      rotationWarning: true,
      daysUntilExpiry: Math.floor(daysUntilExpiry),
      keyAgeDays: Math.floor(keyAgeDays),
      message: `Key expired ${Math.abs(Math.floor(daysUntilExpiry))} days ago — rotation required`,
    };
  }

  if (daysUntilExpiry <= policy.rotationWarningDays) {
    return {
      rotationRequired: false,
      rotationWarning: true,
      daysUntilExpiry: Math.floor(daysUntilExpiry),
      keyAgeDays: Math.floor(keyAgeDays),
      message: `Key expires in ${Math.floor(daysUntilExpiry)} days — rotation recommended`,
    };
  }

  return {
    rotationRequired: false,
    rotationWarning: false,
    daysUntilExpiry: Math.floor(daysUntilExpiry),
    keyAgeDays: Math.floor(keyAgeDays),
    message: `Key is valid for ${Math.floor(daysUntilExpiry)} more days`,
  };
}

// ---------------------------------------------------------------------------
// Policy Validation
// ---------------------------------------------------------------------------

/**
 * Result of validating an issuer against a policy.
 */
export interface PolicyValidationResult {
  /** Whether the issuer passes all policy checks */
  valid: boolean;
  /** List of policy violations */
  violations: string[];
  /** List of warnings (non-blocking) */
  warnings: string[];
}

/**
 * Issuer record fields needed for policy validation.
 * Compatible with IssuerRecord from @zk-id/sdk.
 */
export interface IssuerRecordForPolicy {
  issuer: string;
  publicKey: KeyObject;
  status?: 'active' | 'revoked' | 'suspended';
  validFrom?: string;
  validTo?: string;
  jurisdiction?: string;
  policyUrl?: string;
}

/**
 * Validate an issuer record against a policy.
 *
 * @param record - Issuer record to validate
 * @param policy - Policy to check against
 * @param credentialsIssued - Number of credentials issued with the current key (for limit checks)
 * @returns Validation result with violations and warnings
 */
export function validateIssuerPolicy(
  record: IssuerRecordForPolicy,
  policy: IssuerPolicy = DEFAULT_ISSUER_POLICY,
  credentialsIssued: number = 0,
): PolicyValidationResult {
  const violations: string[] = [];
  const warnings: string[] = [];

  // Check issuer status
  if (record.status && record.status !== 'active') {
    violations.push(`Issuer status is '${record.status}' (must be 'active')`);
  }

  // Check key algorithm
  const keyType = record.publicKey.asymmetricKeyType;
  if (keyType && keyType !== policy.requiredAlgorithm) {
    violations.push(
      `Key algorithm '${keyType}' does not match required '${policy.requiredAlgorithm}'`,
    );
  }

  // Check key validity window
  if (record.validFrom) {
    const rotationStatus = checkKeyRotation(record.validFrom, policy);
    if (rotationStatus.rotationRequired) {
      violations.push(rotationStatus.message);
    } else if (rotationStatus.rotationWarning) {
      warnings.push(rotationStatus.message);
    }
  }

  // Check key expiry
  if (record.validTo) {
    const expiryMs = Date.parse(record.validTo);
    if (!isNaN(expiryMs) && expiryMs < Date.now()) {
      violations.push('Key validity window has expired');
    }
  }

  // Check credential issuance limit
  if (policy.maxCredentialsPerKey > 0 && credentialsIssued >= policy.maxCredentialsPerKey) {
    violations.push(
      `Credential limit reached (${credentialsIssued}/${policy.maxCredentialsPerKey})`,
    );
  } else if (
    policy.maxCredentialsPerKey > 0 &&
    credentialsIssued >= policy.maxCredentialsPerKey * 0.9
  ) {
    warnings.push(
      `Approaching credential limit (${credentialsIssued}/${policy.maxCredentialsPerKey})`,
    );
  }

  // Check required metadata fields
  if (policy.requirePolicyUrl && !record.policyUrl) {
    violations.push('Missing required policyUrl');
  }
  if (policy.requireJurisdiction && !record.jurisdiction) {
    violations.push('Missing required jurisdiction');
  }

  return {
    valid: violations.length === 0,
    violations,
    warnings,
  };
}

// ---------------------------------------------------------------------------
// Rotation Plan Generator
// ---------------------------------------------------------------------------

/**
 * A planned key rotation step.
 */
export interface RotationPlanStep {
  /** Step description */
  action: string;
  /** ISO 8601 date when this step should be executed */
  scheduledAt: string;
}

/**
 * Generate a key rotation plan based on the current key's age and policy.
 *
 * @param keyCreatedAt - ISO 8601 timestamp when the current key was activated
 * @param policy - Issuer policy
 * @returns Ordered list of rotation steps
 */
export function generateRotationPlan(
  keyCreatedAt: string,
  policy: IssuerPolicy = DEFAULT_ISSUER_POLICY,
): RotationPlanStep[] {
  const createdMs = Date.parse(keyCreatedAt);
  if (isNaN(createdMs)) {
    return [{ action: 'Fix invalid key creation date', scheduledAt: new Date().toISOString() }];
  }

  const expiryMs = createdMs + policy.maxKeyAgeDays * 24 * 60 * 60 * 1000;
  const newKeyActivationMs = expiryMs - policy.minRotationOverlapDays * 24 * 60 * 60 * 1000;
  const _warningMs = expiryMs - policy.rotationWarningDays * 24 * 60 * 60 * 1000;

  const steps: RotationPlanStep[] = [];

  steps.push({
    action: 'Generate new Ed25519 key pair and register in issuer registry',
    scheduledAt: new Date(Math.max(newKeyActivationMs, Date.now())).toISOString(),
  });

  steps.push({
    action: 'Activate new key in registry with overlapping validFrom/validTo window',
    scheduledAt: new Date(Math.max(newKeyActivationMs, Date.now())).toISOString(),
  });

  steps.push({
    action: 'Begin issuing credentials with new key',
    scheduledAt: new Date(Math.max(newKeyActivationMs, Date.now())).toISOString(),
  });

  steps.push({
    action: 'Deactivate old key (set validTo to overlap end date)',
    scheduledAt: new Date(expiryMs).toISOString(),
  });

  return steps;
}
