import { ethers } from 'hardhat';

/**
 * Deploy script for zk-id on-chain verifiers
 *
 * Deploys all Groth16 verifier contracts and the high-level ZkIdVerifier wrapper
 */
async function main() {
  console.log('Deploying zk-id verifier contracts...');

  // Deploy individual verifier contracts
  console.log('\n1. Deploying AgeVerifier...');
  const AgeVerifierFactory = await ethers.getContractFactory('AgeVerifier');
  const ageVerifier = await AgeVerifierFactory.deploy();
  await ageVerifier.waitForDeployment();
  const ageVerifierAddress = await ageVerifier.getAddress();
  console.log(`   ✓ AgeVerifier deployed to: ${ageVerifierAddress}`);

  console.log('\n2. Deploying NationalityVerifier...');
  const NationalityVerifierFactory = await ethers.getContractFactory('NationalityVerifier');
  const nationalityVerifier = await NationalityVerifierFactory.deploy();
  await nationalityVerifier.waitForDeployment();
  const nationalityVerifierAddress = await nationalityVerifier.getAddress();
  console.log(`   ✓ NationalityVerifier deployed to: ${nationalityVerifierAddress}`);

  console.log('\n3. Deploying AgeVerifierSigned...');
  const AgeVerifierSignedFactory = await ethers.getContractFactory('AgeVerifierSigned');
  const ageVerifierSigned = await AgeVerifierSignedFactory.deploy();
  await ageVerifierSigned.waitForDeployment();
  const ageVerifierSignedAddress = await ageVerifierSigned.getAddress();
  console.log(`   ✓ AgeVerifierSigned deployed to: ${ageVerifierSignedAddress}`);

  console.log('\n4. Deploying NationalityVerifierSigned...');
  const NationalityVerifierSignedFactory = await ethers.getContractFactory(
    'NationalityVerifierSigned',
  );
  const nationalityVerifierSigned = await NationalityVerifierSignedFactory.deploy();
  await nationalityVerifierSigned.waitForDeployment();
  const nationalityVerifierSignedAddress = await nationalityVerifierSigned.getAddress();
  console.log(`   ✓ NationalityVerifierSigned deployed to: ${nationalityVerifierSignedAddress}`);

  console.log('\n5. Deploying AgeVerifierRevocable...');
  const AgeVerifierRevocableFactory = await ethers.getContractFactory('AgeVerifierRevocable');
  const ageVerifierRevocable = await AgeVerifierRevocableFactory.deploy();
  await ageVerifierRevocable.waitForDeployment();
  const ageVerifierRevocableAddress = await ageVerifierRevocable.getAddress();
  console.log(`   ✓ AgeVerifierRevocable deployed to: ${ageVerifierRevocableAddress}`);

  console.log('\n6. Deploying ZkIdVerifier (wrapper contract)...');
  const ZkIdVerifier = await ethers.getContractFactory('ZkIdVerifier');
  const zkIdVerifier = await ZkIdVerifier.deploy(
    ageVerifierAddress,
    nationalityVerifierAddress,
    ageVerifierSignedAddress,
    nationalityVerifierSignedAddress,
    ageVerifierRevocableAddress,
  );
  await zkIdVerifier.waitForDeployment();
  const zkIdVerifierAddress = await zkIdVerifier.getAddress();
  console.log(`   ✓ ZkIdVerifier deployed to: ${zkIdVerifierAddress}`);

  console.log('\n=== Deployment Summary ===');
  console.log(`AgeVerifier:                ${ageVerifierAddress}`);
  console.log(`NationalityVerifier:        ${nationalityVerifierAddress}`);
  console.log(`AgeVerifierSigned:          ${ageVerifierSignedAddress}`);
  console.log(`NationalityVerifierSigned:  ${nationalityVerifierSignedAddress}`);
  console.log(`AgeVerifierRevocable:       ${ageVerifierRevocableAddress}`);
  console.log(`ZkIdVerifier (wrapper):     ${zkIdVerifierAddress}`);
  console.log('\n=== Verification ===');
  console.log('To verify contracts on Etherscan:');
  console.log(`npx hardhat verify --network <network> ${ageVerifierAddress}`);
  console.log(`npx hardhat verify --network <network> ${nationalityVerifierAddress}`);
  console.log(`npx hardhat verify --network <network> ${ageVerifierSignedAddress}`);
  console.log(`npx hardhat verify --network <network> ${nationalityVerifierSignedAddress}`);
  console.log(`npx hardhat verify --network <network> ${ageVerifierRevocableAddress}`);
  console.log(
    `npx hardhat verify --network <network> ${zkIdVerifierAddress} ${ageVerifierAddress} ${nationalityVerifierAddress} ${ageVerifierSignedAddress} ${nationalityVerifierSignedAddress} ${ageVerifierRevocableAddress}`,
  );
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
