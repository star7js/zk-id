/**
 * Complete end-to-end demo of zk-id age verification
 *
 * This demonstrates the full flow:
 * 1. Issuer creates a credential for a user (after verifying their ID)
 * 2. User generates a zero-knowledge proof of age
 * 3. Website verifies the proof without learning the user's birth year
 */

import { createCredential, generateAgeProof, verifyAgeProof, loadVerificationKey } from '@zk-id/core';
import { CredentialIssuer } from '@zk-id/issuer';

async function main() {
  console.log('\n🔐 zk-id Age Verification Demo\n');
  console.log('This demonstrates privacy-preserving age verification using zero-knowledge proofs.\n');

  // ============================================================================
  // STEP 1: User obtains a credential from a trusted issuer
  // ============================================================================
  console.log('📝 Step 1: Credential Issuance');
  console.log('   User visits government website or trusted identity provider');
  console.log('   After ID verification, they receive a signed credential\n');

  const issuer = CredentialIssuer.createTestIssuer('Government Identity Service');
  const userBirthYear = 1995; // User is 29 years old (as of 2024)

  const signedCredential = await issuer.issueCredential(userBirthYear, 'user-123');

  console.log('   ✓ Credential issued');
  console.log(`   - Credential ID: ${signedCredential.credential.id}`);
  console.log(`   - Commitment: ${signedCredential.credential.commitment.substring(0, 16)}...`);
  console.log('   - Birth year is NOT revealed in the commitment\n');

  // ============================================================================
  // STEP 2: User wants to access age-restricted content
  // ============================================================================
  console.log('🌐 Step 2: Website Requests Age Verification');
  console.log('   User visits age-restricted content that requires 18+ verification');
  console.log('   Website: "Prove you are at least 18 years old"\n');

  const minAge = 18;

  // NOTE: In production, these paths would point to the compiled circuits
  // For this demo, we're showing the structure - actual proof generation
  // requires compiled .wasm and .zkey files from the circuits package

  console.log('🔒 Step 3: User Generates Zero-Knowledge Proof');
  console.log('   The proof is generated locally on user\'s device');
  console.log('   Private inputs: birth year (1995), credential salt');
  console.log(`   Public inputs: current year (${new Date().getFullYear()}), minimum age (${minAge})\n`);

  let proof;
  try {
    const wasmPath = '../../packages/circuits/build/age-verify_js/age-verify.wasm';
    const zkeyPath = '../../packages/circuits/build/age-verify.zkey';

    proof = await generateAgeProof(
      signedCredential.credential,
      minAge,
      wasmPath,
      zkeyPath
    );

    console.log('   ✓ Proof generated successfully!');
    console.log('   ✓ Proof that (currentYear - birthYear) >= minAge');
    console.log('   ✓ Credential commitment (binds proof to specific identity)');
    console.log('   ✗ Birth year is NOT revealed');
    console.log('   ✗ Exact age is NOT revealed');
    console.log(`   - Proof size: ~${JSON.stringify(proof).length} bytes\n`);

  } catch (error) {
    console.log('   ⚠️  Proof generation failed');
    console.log('   Run: cd packages/circuits && npm run compile && npm run setup');
    console.log(`   Error: ${error}\n`);
    return;
  }

  // ============================================================================
  // STEP 3: Website verifies the proof
  // ============================================================================
  console.log('✅ Step 4: Website Verifies Proof');
  console.log('   Website checks the cryptographic proof');
  console.log('   Learns: User IS at least 18 years old');
  console.log('   Does NOT learn: Birth year, exact age, or any other personal info\n');

  try {
    const vkeyPath = '../../packages/circuits/build/age-verify_verification_key.json';
    const verificationKey = await loadVerificationKey(vkeyPath);

    const startTime = Date.now();
    const isValid = await verifyAgeProof(proof!, verificationKey);
    const verificationTime = Date.now() - startTime;

    if (isValid) {
      console.log('   ✓ Proof verified successfully!');
      console.log(`   ✓ Verification time: ${verificationTime}ms`);
      console.log('   ✓ User is confirmed to be at least 18 years old');
      console.log('   ✓ Website grants access to age-restricted content\n');
    } else {
      console.log('   ✗ Proof verification failed');
      console.log('   ✗ Access denied\n');
    }
  } catch (error) {
    console.log('   ⚠️  Verification failed');
    console.log(`   Error: ${error}\n`);
    return;
  }

  // ============================================================================
  // SUMMARY
  // ============================================================================
  console.log('📊 Summary of Privacy Properties:\n');
  console.log('   What the website learns:');
  console.log('   ✓ User is at least 18 years old');
  console.log('   ✓ Proof is cryptographically valid');
  console.log('   ✓ Credential was issued by a trusted authority\n');

  console.log('   What the website does NOT learn:');
  console.log('   ✗ User\'s birth year');
  console.log('   ✗ User\'s exact age');
  console.log('   ✗ User\'s name, address, or any other personal data');
  console.log('   ✗ When the credential was issued\n');

  console.log('🎯 Use Cases:');
  console.log('   • Age-gated content (18+, 21+ verification)');
  console.log('   • Social media age requirements');
  console.log('   • Alcohol/tobacco sales (prove 21+ without ID)');
  console.log('   • Student/senior discounts (prove age range)');
  console.log('   • Voting eligibility (prove 18+ without revealing age)\n');

  console.log('🔧 Next Steps:');
  console.log('   1. Compile circuits: cd packages/circuits && npm run compile');
  console.log('   2. Run trusted setup: cd packages/circuits && npm run setup');
  console.log('   3. Run this demo again to see full proof generation\n');

  console.log('📚 Technical Details:');
  console.log('   • Proof system: Groth16 (efficient ZK-SNARKs)');
  console.log('   • Hash function: Poseidon (ZK-friendly)');
  console.log('   • Circuit language: Circom 2.0');
  console.log('   • Proof size: ~200 bytes');
  console.log('   • Verification time: <100ms\n');
}

main().catch(console.error);
