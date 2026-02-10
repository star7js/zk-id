/**
 * Verification scenarios layer.
 *
 * Composes existing proof types into named real-world use cases, allowing
 * applications to verify age, nationality, or combined requirements without
 * knowing the underlying proof structure. Builds on the multi-claim system.
 */

import {
  ClaimSpec,
  MultiClaimRequest,
  MultiClaimVerificationResult,
  createMultiClaimRequest,
} from './multi-claim';
import { ZkIdValidationError } from './errors';

// ---------------------------------------------------------------------------
// Scenario Types
// ---------------------------------------------------------------------------

/**
 * A named verification scenario that composes multiple claims.
 */
export interface VerificationScenario {
  /** Unique identifier for the scenario */
  id: string;
  /** Human-readable name */
  name: string;
  /** Description of what the scenario verifies */
  description: string;
  /** Claims that must be proven for this scenario */
  claims: ClaimSpec[];
}

/**
 * Result of verifying a scenario.
 */
export interface ScenarioVerificationResult {
  /** Whether all scenario claims were satisfied */
  satisfied: boolean;
  /** Labels of claims that failed verification (empty if all passed) */
  failedClaims: string[];
  /** Full multi-claim verification result */
  details: MultiClaimVerificationResult;
}

// ---------------------------------------------------------------------------
// Built-in Scenarios
// ---------------------------------------------------------------------------

/**
 * Registry of built-in verification scenarios.
 */
export const SCENARIOS: Record<string, VerificationScenario> = {
  VOTING_ELIGIBILITY_US: {
    id: 'voting-eligibility-us',
    name: 'US Voting Eligibility',
    description: 'Verify user is 18+ and a US citizen',
    claims: [
      {
        label: 'age-requirement',
        claimType: 'age',
        minAge: 18,
      },
      {
        label: 'citizenship',
        claimType: 'nationality',
        targetNationality: 840, // USA
      },
    ],
  },

  ALCOHOL_PURCHASE_US: {
    id: 'alcohol-purchase-us',
    name: 'US Alcohol Purchase',
    description: 'Verify user is 21+ for alcohol purchase',
    claims: [
      {
        label: 'legal-drinking-age',
        claimType: 'age',
        minAge: 21,
      },
    ],
  },

  SENIOR_DISCOUNT: {
    id: 'senior-discount',
    name: 'Senior Discount',
    description: 'Verify user is 65+ for senior discounts',
    claims: [
      {
        label: 'senior-age',
        claimType: 'age',
        minAge: 65,
      },
    ],
  },

  TOBACCO_PURCHASE_US: {
    id: 'tobacco-purchase-us',
    name: 'US Tobacco Purchase',
    description: 'Verify user is 21+ for tobacco purchase',
    claims: [
      {
        label: 'legal-tobacco-age',
        claimType: 'age',
        minAge: 21,
      },
    ],
  },

  GAMBLING_US: {
    id: 'gambling-us',
    name: 'US Gambling',
    description: 'Verify user is 21+ for gambling',
    claims: [
      {
        label: 'legal-gambling-age',
        claimType: 'age',
        minAge: 21,
      },
    ],
  },

  EU_GDPR_AGE_CONSENT: {
    id: 'eu-gdpr-age-consent',
    name: 'EU GDPR Age of Consent',
    description: 'Verify user is 16+ for GDPR data processing consent',
    claims: [
      {
        label: 'gdpr-age-consent',
        claimType: 'age',
        minAge: 16,
      },
    ],
  },

  RENTAL_CAR_US: {
    id: 'rental-car-us',
    name: 'US Rental Car',
    description: 'Verify user is 25+ for rental car (standard rate)',
    claims: [
      {
        label: 'rental-car-age',
        claimType: 'age',
        minAge: 25,
      },
    ],
  },
};

// ---------------------------------------------------------------------------
// Scenario Functions
// ---------------------------------------------------------------------------

/**
 * Create a multi-claim request from a scenario.
 *
 * @param scenario - The verification scenario to request
 * @param nonce - Nonce for replay protection
 * @returns Multi-claim request for the scenario
 */
export function createScenarioRequest(
  scenario: VerificationScenario,
  nonce: string,
): MultiClaimRequest {
  if (!scenario.claims || scenario.claims.length === 0) {
    throw new ZkIdValidationError(
      `Scenario '${scenario.id}' has no claims defined`,
      'scenario.claims',
    );
  }

  return createMultiClaimRequest(scenario.claims, nonce);
}

/**
 * Verify that a multi-claim verification result satisfies a scenario.
 *
 * @param scenario - The scenario to check against
 * @param result - Multi-claim verification result
 * @returns Scenario verification result
 */
export function verifyScenario(
  scenario: VerificationScenario,
  result: MultiClaimVerificationResult,
): ScenarioVerificationResult {
  const failedClaims = result.results.filter((r) => !r.verified).map((r) => r.label);

  return {
    satisfied: result.allVerified,
    failedClaims,
    details: result,
  };
}

/**
 * Get a scenario by its ID.
 *
 * @param id - Scenario ID
 * @returns The scenario, or undefined if not found
 */
export function getScenarioById(id: string): VerificationScenario | undefined {
  return Object.values(SCENARIOS).find((s) => s.id === id);
}

/**
 * List all available scenarios.
 *
 * @returns Array of all built-in scenarios
 */
export function listScenarios(): VerificationScenario[] {
  return Object.values(SCENARIOS);
}
