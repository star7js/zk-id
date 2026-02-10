import { expect } from 'chai';
import { ethers } from 'hardhat';
import { ZkIdVerifier } from '../typechain-types';
import { SignerWithAddress } from '@nomicfoundation/hardhat-ethers/signers';

/**
 * Integration tests for ZkIdVerifier contract
 *
 * Note: These tests use mock proof data. In production, proofs would be generated
 * using the zk-id prover with real credentials.
 */
describe('ZkIdVerifier', function () {
  let zkIdVerifier: ZkIdVerifier;
  let _owner: SignerWithAddress;
  let _user: SignerWithAddress;

  before(async function () {
    [_owner, _user] = await ethers.getSigners();

    // Deploy all verifier contracts
    const AgeVerifierFactory = await ethers.getContractFactory('AgeVerifier');
    const ageVerifier = await AgeVerifierFactory.deploy();
    await ageVerifier.waitForDeployment();

    const NationalityVerifierFactory = await ethers.getContractFactory('NationalityVerifier');
    const nationalityVerifier = await NationalityVerifierFactory.deploy();
    await nationalityVerifier.waitForDeployment();

    const AgeVerifierSignedFactory = await ethers.getContractFactory('AgeVerifierSigned');
    const ageVerifierSigned = await AgeVerifierSignedFactory.deploy();
    await ageVerifierSigned.waitForDeployment();

    const NationalityVerifierSignedFactory = await ethers.getContractFactory(
      'NationalityVerifierSigned',
    );
    const nationalityVerifierSigned = await NationalityVerifierSignedFactory.deploy();
    await nationalityVerifierSigned.waitForDeployment();

    const AgeVerifierRevocableFactory = await ethers.getContractFactory('AgeVerifierRevocable');
    const ageVerifierRevocable = await AgeVerifierRevocableFactory.deploy();
    await ageVerifierRevocable.waitForDeployment();

    // Deploy the wrapper contract
    const ZkIdVerifierFactory = await ethers.getContractFactory('ZkIdVerifier');
    zkIdVerifier = await ZkIdVerifierFactory.deploy(
      await ageVerifier.getAddress(),
      await nationalityVerifier.getAddress(),
      await ageVerifierSigned.getAddress(),
      await nationalityVerifierSigned.getAddress(),
      await ageVerifierRevocable.getAddress(),
    );
    await zkIdVerifier.waitForDeployment();
  });

  describe('Deployment', function () {
    it('Should deploy successfully', async function () {
      expect(await zkIdVerifier.getAddress()).to.be.properAddress;
    });
  });

  describe('verifyAgeProof', function () {
    it('Should reject invalid proof with zero values', async function () {
      // Mock proof components (all zeros - invalid)
      const pA: [bigint, bigint] = [0n, 0n];
      const pB: [[bigint, bigint], [bigint, bigint]] = [
        [0n, 0n],
        [0n, 0n],
      ];
      const pC: [bigint, bigint] = [0n, 0n];

      // Public signals
      const currentYear = 2026;
      const minAge = 18;
      const credentialHash = 123456789n;
      const nonce = 1n;
      const requestTimestamp = Math.floor(Date.now() / 1000);

      // Should revert or return false for invalid proof
      const result = await zkIdVerifier.verifyAgeProof(
        pA,
        pB,
        pC,
        currentYear,
        minAge,
        credentialHash,
        nonce,
        requestTimestamp,
      );

      expect(result).to.be.false;
    });

    it('Should emit event on successful verification', async function () {
      // Note: This test would need a valid proof from the prover
      // For now, we're just testing the interface
      this.skip(); // Skip until we have a valid proof generator in the test suite
    });
  });

  describe('verifyNationalityProof', function () {
    it('Should reject invalid proof with zero values', async function () {
      // Mock proof components (all zeros - invalid)
      const pA: [bigint, bigint] = [0n, 0n];
      const pB: [[bigint, bigint], [bigint, bigint]] = [
        [0n, 0n],
        [0n, 0n],
      ];
      const pC: [bigint, bigint] = [0n, 0n];

      // Public signals
      const nationalityCode = 840; // USA
      const credentialHash = 123456789n;
      const nonce = 1n;
      const requestTimestamp = Math.floor(Date.now() / 1000);

      const result = await zkIdVerifier.verifyNationalityProof(
        pA,
        pB,
        pC,
        nationalityCode,
        credentialHash,
        nonce,
        requestTimestamp,
      );

      expect(result).to.be.false;
    });
  });

  describe('Gas estimation', function () {
    it('Should provide gas estimates for verification', async function () {
      const pA: [bigint, bigint] = [0n, 0n];
      const pB: [[bigint, bigint], [bigint, bigint]] = [
        [0n, 0n],
        [0n, 0n],
      ];
      const pC: [bigint, bigint] = [0n, 0n];

      const currentYear = 2026;
      const minAge = 18;
      const credentialHash = 123456789n;
      const nonce = 1n;
      const requestTimestamp = Math.floor(Date.now() / 1000);

      // Estimate gas for age proof verification
      const gasEstimate = await zkIdVerifier.verifyAgeProof.estimateGas(
        pA,
        pB,
        pC,
        currentYear,
        minAge,
        credentialHash,
        nonce,
        requestTimestamp,
      );

      console.log(`      Gas estimate for verifyAgeProof: ${gasEstimate.toString()}`);
      expect(gasEstimate).to.be.gt(0);
    });
  });
});
