import { expect } from 'chai';
import {
  SCENARIOS,
  VerificationScenario,
  createScenarioRequest,
  verifyScenario,
  getScenarioById,
  listScenarios,
} from '../src/scenarios';
import { expandMultiClaimRequest, ClaimVerificationResult } from '../src/multi-claim';

describe('Verification Scenarios', () => {
  describe('Scenario Definitions', () => {
    it('should have valid claims for all scenarios', () => {
      const scenarios = Object.values(SCENARIOS);
      expect(scenarios.length).to.be.greaterThan(0);

      for (const scenario of scenarios) {
        expect(scenario.claims).to.be.an('array');
        expect(scenario.claims.length).to.be.greaterThan(0);

        for (const claim of scenario.claims) {
          expect(claim.label).to.be.a('string').with.length.greaterThan(0);
          expect(claim.claimType).to.be.oneOf(['age', 'nationality', 'age-revocable']);

          if (claim.claimType === 'age' || claim.claimType === 'age-revocable') {
            expect(claim.minAge).to.be.a('number').and.to.be.at.least(0);
          }
          if (claim.claimType === 'nationality') {
            expect(claim.targetNationality)
              .to.be.a('number')
              .and.to.be.at.least(1)
              .and.to.be.at.most(999);
          }
        }
      }
    });

    it('should have unique IDs for all scenarios', () => {
      const scenarios = Object.values(SCENARIOS);
      const ids = scenarios.map((s) => s.id);
      const uniqueIds = new Set(ids);
      expect(uniqueIds.size).to.equal(ids.length);
    });

    it('should have non-empty names and descriptions', () => {
      const scenarios = Object.values(SCENARIOS);

      for (const scenario of scenarios) {
        expect(scenario.name).to.be.a('string').with.length.greaterThan(0);
        expect(scenario.description).to.be.a('string').with.length.greaterThan(0);
      }
    });
  });

  describe('createScenarioRequest', () => {
    it('should create a valid multi-claim request', () => {
      const scenario = SCENARIOS.ALCOHOL_PURCHASE_US;
      const nonce = 'test-nonce-1234567890abcdef';

      const request = createScenarioRequest(scenario, nonce);

      expect(request.nonce).to.equal(nonce);
      expect(request.claims).to.have.lengthOf(scenario.claims.length);
      expect(request.timestamp).to.be.a('string');
    });

    it('should use scenario claims', () => {
      const scenario = SCENARIOS.VOTING_ELIGIBILITY_US;
      const nonce = 'test-nonce-1234567890abcdef';

      const request = createScenarioRequest(scenario, nonce);

      expect(request.claims).to.deep.equal(scenario.claims);
    });

    it('should pass nonce to multi-claim request', () => {
      const scenario = SCENARIOS.SENIOR_DISCOUNT;
      const nonce = 'unique-nonce-xyz123456789';

      const request = createScenarioRequest(scenario, nonce);

      expect(request.nonce).to.equal(nonce);
    });

    it('should throw for scenario with no claims', () => {
      const emptyScenario: VerificationScenario = {
        id: 'empty',
        name: 'Empty',
        description: 'No claims',
        claims: [],
      };

      expect(() => createScenarioRequest(emptyScenario, 'test-nonce-1234567890')).to.throw(
        /has no claims/,
      );
    });
  });

  describe('verifyScenario', () => {
    it('should return satisfied when all claims pass', () => {
      const scenario = SCENARIOS.ALCOHOL_PURCHASE_US;
      const mockResult = {
        results: [{ label: 'legal-drinking-age', verified: true }],
        allVerified: true,
        verifiedCount: 1,
        totalCount: 1,
      };

      const result = verifyScenario(scenario, mockResult);

      expect(result.satisfied).to.be.true;
      expect(result.failedClaims).to.be.empty;
      expect(result.details).to.equal(mockResult);
    });

    it('should return not satisfied when any claim fails', () => {
      const scenario = SCENARIOS.VOTING_ELIGIBILITY_US;
      const mockResult = {
        results: [
          { label: 'age-requirement', verified: true },
          { label: 'citizenship', verified: false, error: 'Nationality mismatch' },
        ],
        allVerified: false,
        verifiedCount: 1,
        totalCount: 2,
      };

      const result = verifyScenario(scenario, mockResult);

      expect(result.satisfied).to.be.false;
      expect(result.failedClaims).to.deep.equal(['citizenship']);
      expect(result.details).to.equal(mockResult);
    });

    it('should identify all failed claims', () => {
      const scenario = SCENARIOS.VOTING_ELIGIBILITY_US;
      const mockResult = {
        results: [
          { label: 'age-requirement', verified: false, error: 'Too young' },
          { label: 'citizenship', verified: false, error: 'Wrong country' },
        ],
        allVerified: false,
        verifiedCount: 0,
        totalCount: 2,
      };

      const result = verifyScenario(scenario, mockResult);

      expect(result.satisfied).to.be.false;
      expect(result.failedClaims).to.deep.equal(['age-requirement', 'citizenship']);
    });
  });

  describe('getScenarioById', () => {
    it('should return scenario by ID', () => {
      const scenario = getScenarioById('voting-eligibility-us');

      expect(scenario).to.exist;
      expect(scenario?.id).to.equal('voting-eligibility-us');
      expect(scenario?.name).to.equal('US Voting Eligibility');
    });

    it('should return undefined for unknown ID', () => {
      const scenario = getScenarioById('unknown-scenario-id');
      expect(scenario).to.be.undefined;
    });
  });

  describe('listScenarios', () => {
    it('should list all scenarios', () => {
      const scenarios = listScenarios();

      expect(scenarios).to.be.an('array');
      expect(scenarios.length).to.equal(Object.keys(SCENARIOS).length);
    });

    it('should include all built-in scenarios', () => {
      const scenarios = listScenarios();
      const ids = scenarios.map((s) => s.id);

      expect(ids).to.include('voting-eligibility-us');
      expect(ids).to.include('alcohol-purchase-us');
      expect(ids).to.include('senior-discount');
      expect(ids).to.include('tobacco-purchase-us');
      expect(ids).to.include('gambling-us');
      expect(ids).to.include('eu-gdpr-age-consent');
      expect(ids).to.include('rental-car-us');
    });
  });

  describe('Integration - VOTING_ELIGIBILITY_US', () => {
    it('should expand to 2 proof requests (age + nationality)', () => {
      const scenario = SCENARIOS.VOTING_ELIGIBILITY_US;
      const nonce = 'integration-test-nonce-123456';

      const request = createScenarioRequest(scenario, nonce);
      const expanded = expandMultiClaimRequest(request);

      expect(expanded).to.have.lengthOf(2);
      expect(expanded[0].label).to.equal('age-requirement');
      expect(expanded[0].proofRequest.claimType).to.equal('age');
      expect(expanded[0].proofRequest.minAge).to.equal(18);
      expect(expanded[1].label).to.equal('citizenship');
      expect(expanded[1].proofRequest.claimType).to.equal('nationality');
      expect(expanded[1].proofRequest.targetNationality).to.equal(840);
    });
  });

  describe('Integration - SENIOR_DISCOUNT', () => {
    it('should expand to 1 proof request (age >= 65)', () => {
      const scenario = SCENARIOS.SENIOR_DISCOUNT;
      const nonce = 'senior-test-nonce-789012';

      const request = createScenarioRequest(scenario, nonce);
      const expanded = expandMultiClaimRequest(request);

      expect(expanded).to.have.lengthOf(1);
      expect(expanded[0].label).to.equal('senior-age');
      expect(expanded[0].proofRequest.claimType).to.equal('age');
      expect(expanded[0].proofRequest.minAge).to.equal(65);
    });
  });
});
