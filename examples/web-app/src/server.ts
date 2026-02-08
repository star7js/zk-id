import express from 'express';
import { join } from 'path';
import { CredentialIssuer, CircuitCredentialIssuer } from '@zk-id/issuer';
import {
  ZkIdServer,
  InMemoryNonceStore,
  InMemoryIssuerRegistry,
  InMemoryChallengeStore,
  SignedProofRequest,
} from '@zk-id/sdk';
import {
  ProofResponse,
  InMemoryRevocationStore,
  InMemoryValidCredentialTree,
  generateAgeProof,
  generateNationalityProof,
  generateAgeProofSigned,
  generateNationalityProofSigned,
  generateAgeProofRevocable,
  PROTOCOL_VERSION,
} from '@zk-id/core';

async function main() {
  const app = express();
  const PORT = Number(process.env.PORT) || 3000;

// Circuit paths for proof generation
const CIRCUITS_BASE = join(__dirname, '../../../packages/circuits/build');
const AGE_WASM_PATH = join(CIRCUITS_BASE, 'age-verify_js/age-verify.wasm');
const AGE_ZKEY_PATH = join(CIRCUITS_BASE, 'age-verify.zkey');
const NATIONALITY_WASM_PATH = join(CIRCUITS_BASE, 'nationality-verify_js/nationality-verify.wasm');
const NATIONALITY_ZKEY_PATH = join(CIRCUITS_BASE, 'nationality-verify.zkey');
const AGE_SIGNED_WASM_PATH = join(CIRCUITS_BASE, 'age-verify-signed_js/age-verify-signed.wasm');
const AGE_SIGNED_ZKEY_PATH = join(CIRCUITS_BASE, 'age-verify-signed.zkey');
const NATIONALITY_SIGNED_WASM_PATH = join(
  CIRCUITS_BASE,
  'nationality-verify-signed_js/nationality-verify-signed.wasm'
);
const NATIONALITY_SIGNED_ZKEY_PATH = join(CIRCUITS_BASE, 'nationality-verify-signed.zkey');
const AGE_REVOCABLE_WASM_PATH = join(CIRCUITS_BASE, 'age-verify-revocable_js/age-verify-revocable.wasm');
const AGE_REVOCABLE_ZKEY_PATH = join(CIRCUITS_BASE, 'age-verify-revocable.zkey');

// Middleware
app.use(express.json({ limit: '100kb' }));
app.use(express.static(join(__dirname, 'public')));

// Protocol version header middleware
app.use((req, res, next) => {
  res.setHeader('X-ZkId-Protocol-Version', PROTOCOL_VERSION);
  next();
});

// Create a test issuer (in production, this would use secure key management)
const issuerName = 'Demo Government ID Authority';
const issuer = CredentialIssuer.createTestIssuer(issuerName);
const circuitIssuer = await CircuitCredentialIssuer.createTestIssuer(issuerName);
const revocationStore = new InMemoryRevocationStore();
issuer.setRevocationStore(revocationStore);
const validCredentialTree = new InMemoryValidCredentialTree(10);

// Setup issuer registry (demo; production should be backed by DB/KMS/HSM)
const issuerRegistry = new InMemoryIssuerRegistry([
  {
    issuer: issuerName,
    publicKey: issuer.getPublicKey(),
    status: 'active',
  },
]);

// Setup ZK-ID server for verification
const zkIdServer = new ZkIdServer({
  verificationKeyPath: join(__dirname, '../../../packages/circuits/build/age-verify_verification_key.json'),
  nationalityVerificationKeyPath: join(__dirname, '../../../packages/circuits/build/nationality-verify_verification_key.json'),
  signedVerificationKeyPath: join(
    __dirname,
    '../../../packages/circuits/build/age-verify-signed_verification_key.json'
  ),
  signedNationalityVerificationKeyPath: join(
    __dirname,
    '../../../packages/circuits/build/nationality-verify-signed_verification_key.json'
  ),
  revocableVerificationKeyPath: join(
    __dirname,
    '../../../packages/circuits/build/age-verify-revocable_verification_key.json'
  ),
  nonceStore: new InMemoryNonceStore(),
  challengeStore: new InMemoryChallengeStore(),
  challengeTtlMs: 5 * 60 * 1000,
  revocationStore,
  validCredentialTree,
  issuerRegistry,
  issuerPublicKeyBits: {
    [issuerName]: circuitIssuer.getIssuerPublicKeyBits(),
  },
});

// Setup telemetry
zkIdServer.onVerification((event) => {
  console.log('[TELEMETRY]', {
    timestamp: event.timestamp,
    claimType: event.claimType,
    verified: event.verified,
    timeMs: event.verificationTimeMs,
    client: event.clientIdentifier || 'unknown',
    error: event.error,
  });
});

// Store issued credentials (in-memory for demo - production would use database)
const issuedCredentials = new Map<string, any>();
const issuedCircuitCredentials = new Map<string, any>();

/**
 * Demo endpoint: Issue a credential
 * In production, this would:
 * - Require authentication
 * - Verify user's identity through KYC
 * - Rate limit requests
 */
app.post('/api/issue-credential', async (req, res) => {
  try {
    const { birthYear, nationality, userId } = req.body;

    if (!birthYear || !nationality) {
      return res.status(400).json({
        error: 'Missing required fields: birthYear, nationality',
      });
    }

    // Validate inputs
    const currentYear = new Date().getFullYear();
    if (birthYear < 1900 || birthYear > currentYear) {
      return res.status(400).json({
        error: 'Invalid birth year',
      });
    }

    if (nationality < 1 || nationality > 999) {
      return res.status(400).json({
        error: 'Invalid nationality code (ISO 3166-1 numeric)',
      });
    }

    // Issue credential
    const signedCredential = await issuer.issueCredential(birthYear, nationality, userId);

    // Store for demo purposes
    issuedCredentials.set(signedCredential.credential.id, signedCredential);

    // Add to valid credential tree for revocable proofs
    await validCredentialTree.add(signedCredential.credential.commitment);

    res.json({
      success: true,
      credential: signedCredential,
      message: 'Credential issued successfully',
    });
  } catch (error) {
    console.error('Error issuing credential:', error);
    res.status(500).json({
      error: 'Failed to issue credential',
      details: error instanceof Error ? error.message : 'Unknown error',
    });
  }
});

/**
 * Demo endpoint: Get a server-issued nonce + timestamp challenge
 */
app.get('/api/challenge', async (_req, res) => {
  const challenge = await zkIdServer.createChallenge();
  res.json(challenge);
});

/**
 * Demo endpoint: Issue a credential for signed circuits
 */
app.post('/api/issue-credential-signed', async (req, res) => {
  try {
    const { birthYear, nationality } = req.body;

    if (!birthYear || !nationality) {
      return res.status(400).json({
        error: 'Missing required fields: birthYear, nationality',
      });
    }

    // Validate inputs
    const currentYear = new Date().getFullYear();
    if (birthYear < 1900 || birthYear > currentYear) {
      return res.status(400).json({
        error: 'Invalid birth year',
      });
    }

    if (nationality < 1 || nationality > 999) {
      return res.status(400).json({
        error: 'Invalid nationality code (ISO 3166-1 numeric)',
      });
    }

    const circuitCredential = await circuitIssuer.issueCredential(birthYear, nationality);
    issuedCircuitCredentials.set(circuitCredential.credential.id, circuitCredential);

    res.json({
      success: true,
      credential: circuitCredential,
      message: 'Signed-circuit credential issued successfully',
    });
  } catch (error) {
    console.error('Error issuing signed-circuit credential:', error);
    res.status(500).json({
      error: 'Failed to issue signed-circuit credential',
      details: error instanceof Error ? error.message : 'Unknown error',
    });
  }
});

/**
 * Demo endpoint: Verify age proof
 */
app.post('/api/verify-age', async (req, res) => {
  try {
    const proofResponse: ProofResponse = req.body;
    const clientIp = req.ip || req.socket.remoteAddress || 'unknown';
    if (!proofResponse.nonce || !proofResponse.requestTimestamp) {
      return res.status(400).json({
        verified: false,
        error: 'Missing nonce or requestTimestamp. Fetch /api/challenge before generating a proof.',
      });
    }

    // Verify the proof
    const result = await zkIdServer.verifyProof(proofResponse, clientIp);

    if (result.verified) {
      res.json({
        verified: true,
        message: `Age verification successful! User is at least ${result.minAge} years old.`,
        claimType: result.claimType,
        minAge: result.minAge,
      });
    } else {
      res.json({
        verified: false,
        message: 'Age verification failed',
        error: result.error,
      });
    }
  } catch (error) {
    console.error('Error verifying proof:', error);
    res.status(500).json({
      verified: false,
      error: 'Failed to verify proof',
      details: error instanceof Error ? error.message : 'Unknown error',
    });
  }
});

/**
 * Demo endpoint: Verify nationality proof
 */
app.post('/api/verify-nationality', async (req, res) => {
  try {
    const proofResponse: ProofResponse = req.body;
    const clientIp = req.ip || req.socket.remoteAddress || 'unknown';
    if (!proofResponse.nonce || !proofResponse.requestTimestamp) {
      return res.status(400).json({
        verified: false,
        error: 'Missing nonce or requestTimestamp. Fetch /api/challenge before generating a proof.',
      });
    }

    // Verify the proof
    const result = await zkIdServer.verifyProof(proofResponse, clientIp);

    if (result.verified) {
      res.json({
        verified: true,
        message: `Nationality verification successful!`,
        claimType: result.claimType,
        nationality: result.targetNationality,
      });
    } else {
      res.json({
        verified: false,
        message: 'Nationality verification failed',
        error: result.error,
      });
    }
  } catch (error) {
    console.error('Error verifying proof:', error);
    res.status(500).json({
      verified: false,
      error: 'Failed to verify proof',
      details: error instanceof Error ? error.message : 'Unknown error',
    });
  }
});

/**
 * Demo endpoint: Generate and verify age proof
 * This endpoint combines proof generation + verification for the web demo.
 * It generates a real ZK proof server-side and then verifies it.
 */
app.post('/api/demo/verify-age', async (req, res) => {
  try {
    const { credentialId, minAge, nonce: providedNonce, requestTimestamp: providedTimestamp } = req.body;

    if (!credentialId || minAge === undefined) {
      return res.status(400).json({
        error: 'Missing required fields: credentialId, minAge',
      });
    }

    // Validate minAge
    if (!Number.isInteger(minAge) || minAge < 0 || minAge > 150) {
      return res.status(400).json({
        error: 'Invalid minAge: must be a number between 0 and 150',
      });
    }

    // Look up stored credential
    const signedCredential = issuedCredentials.get(credentialId);
    if (!signedCredential) {
      return res.status(404).json({
        error: 'Credential not found',
      });
    }

    // Generate proof (this is the expensive operation)
    const proofGenStart = Date.now();
    const { nonce, requestTimestamp } =
      providedNonce && providedTimestamp
        ? { nonce: providedNonce, requestTimestamp: providedTimestamp }
        : await zkIdServer.createChallenge();
    const requestTimestampMs = Date.parse(requestTimestamp);
    const proof = await generateAgeProof(
      signedCredential.credential,
      minAge,
      nonce,
      requestTimestampMs,
      AGE_WASM_PATH,
      AGE_ZKEY_PATH
    );
    const proofGenTime = Date.now() - proofGenStart;

    // Wrap in ProofResponse with a fresh nonce
    const proofResponse: ProofResponse = {
      proof,
      nonce,
      claimType: 'age',
      credentialId,
      signedCredential,
      requestTimestamp,
    };

    // Verify the proof
    const verifyStart = Date.now();
    const clientIp = req.ip || req.socket.remoteAddress || 'unknown';
    const result = await zkIdServer.verifyProof(proofResponse, clientIp);
    const verifyTime = Date.now() - verifyStart;
    const totalTime = Date.now() - proofGenStart;

    if (result.verified) {
      res.json({
        verified: true,
        message: `Age verification successful! User is at least ${result.minAge} years old.`,
        timing: {
          proofGenerationMs: proofGenTime,
          verificationMs: verifyTime,
          totalMs: totalTime,
        },
        privacy: {
          revealed: [`Age ≥ ${result.minAge}`],
          hidden: ['Exact birth year', 'Nationality', 'Other attributes'],
        },
        proofDetails: {
          system: 'Groth16',
          curve: 'BN128',
          proofSize: `${JSON.stringify(proof.proof).length} bytes`,
        },
      });
    } else {
      res.json({
        verified: false,
        message: result.error || 'Age verification failed',
        timing: {
          proofGenerationMs: proofGenTime,
          verificationMs: verifyTime,
          totalMs: totalTime,
        },
      });
    }
  } catch (error) {
    console.error('Error in demo age verification:', error);
    // Check if this is a circuit assertion failure (user doesn't meet the requirement)
    const errorMsg = error instanceof Error ? error.message : 'Unknown error';
    const isAssertionFailure = errorMsg.includes('Assert Failed');

    res.status(400).json({
      verified: false,
      message: isAssertionFailure
        ? `Age verification failed: User does not meet the minimum age requirement`
        : `Failed to generate or verify proof: ${errorMsg}`,
    });
  }
});

/**
 * Demo endpoint: Generate and verify signed age proof
 */
app.post('/api/demo/verify-age-signed', async (req, res) => {
  try {
    const { credentialId, minAge, nonce: providedNonce, requestTimestamp: providedTimestamp } = req.body;

    if (!credentialId || minAge === undefined) {
      return res.status(400).json({
        error: 'Missing required fields: credentialId, minAge',
      });
    }

    if (!Number.isInteger(minAge) || minAge < 0 || minAge > 150) {
      return res.status(400).json({
        error: 'Invalid minAge: must be a number between 0 and 150',
      });
    }

    const signedCredential = issuedCircuitCredentials.get(credentialId);
    if (!signedCredential) {
      return res.status(404).json({
        error: 'Signed-circuit credential not found',
      });
    }

    const proofGenStart = Date.now();
    const { nonce, requestTimestamp } =
      providedNonce && providedTimestamp
        ? { nonce: providedNonce, requestTimestamp: providedTimestamp }
        : await zkIdServer.createChallenge();
    const requestTimestampMs = Date.parse(requestTimestamp);
    const signatureInputs = circuitIssuer.getSignatureInputs(signedCredential);

    const proof = await generateAgeProofSigned(
      signedCredential.credential,
      minAge,
      nonce,
      requestTimestampMs,
      signatureInputs,
      AGE_SIGNED_WASM_PATH,
      AGE_SIGNED_ZKEY_PATH
    );
    const proofGenTime = Date.now() - proofGenStart;

    const signedRequest: SignedProofRequest = {
      claimType: 'age',
      issuer: signedCredential.issuer,
      nonce,
      requestTimestamp,
      proof,
    };

    const verifyStart = Date.now();
    const clientIp = req.ip || req.socket.remoteAddress || 'unknown';
    const result = await zkIdServer.verifySignedProof(signedRequest, clientIp);
    const verifyTime = Date.now() - verifyStart;
    const totalTime = Date.now() - proofGenStart;

    if (result.verified) {
      res.json({
        verified: true,
        message: `Signed age verification successful! User is at least ${result.minAge} years old.`,
        timing: {
          proofGenerationMs: proofGenTime,
          verificationMs: verifyTime,
          totalMs: totalTime,
        },
        privacy: {
          revealed: [`Age ≥ ${result.minAge}`],
          hidden: ['Exact birth year', 'Nationality', 'Other attributes'],
        },
        proofDetails: {
          system: 'Groth16',
          curve: 'BN128',
          proofSize: `${JSON.stringify(proof.proof).length} bytes`,
          issuerVerification: 'In-circuit (BabyJub EdDSA)',
        },
      });
    } else {
      res.json({
        verified: false,
        message: result.error || 'Signed age verification failed',
        timing: {
          proofGenerationMs: proofGenTime,
          verificationMs: verifyTime,
          totalMs: totalTime,
        },
      });
    }
  } catch (error) {
    console.error('Error in demo signed age verification:', error);
    const errorMsg = error instanceof Error ? error.message : 'Unknown error';
    const isAssertionFailure = errorMsg.includes('Assert Failed');

    res.status(400).json({
      verified: false,
      message: isAssertionFailure
        ? `Signed age verification failed: User does not meet the minimum age requirement`
        : `Failed to generate or verify signed proof: ${errorMsg}`,
    });
  }
});

/**
 * Demo endpoint: Generate and verify nationality proof
 * This endpoint combines proof generation + verification for the web demo.
 * It generates a real ZK proof server-side and then verifies it.
 */
app.post('/api/demo/verify-nationality', async (req, res) => {
  try {
    const { credentialId, targetNationality, nonce: providedNonce, requestTimestamp: providedTimestamp } = req.body;

    if (!credentialId || targetNationality === undefined) {
      return res.status(400).json({
        error: 'Missing required fields: credentialId, targetNationality',
      });
    }

    // Validate targetNationality
    if (!Number.isInteger(targetNationality) || targetNationality < 1 || targetNationality > 999) {
      return res.status(400).json({
        error: 'Invalid targetNationality: must be a number between 1 and 999',
      });
    }

    // Look up stored credential
    const signedCredential = issuedCredentials.get(credentialId);
    if (!signedCredential) {
      return res.status(404).json({
        error: 'Credential not found',
      });
    }

    // Generate proof (this is the expensive operation)
    const proofGenStart = Date.now();
    const { nonce, requestTimestamp } =
      providedNonce && providedTimestamp
        ? { nonce: providedNonce, requestTimestamp: providedTimestamp }
        : await zkIdServer.createChallenge();
    const requestTimestampMs = Date.parse(requestTimestamp);
    const proof = await generateNationalityProof(
      signedCredential.credential,
      targetNationality,
      nonce,
      requestTimestampMs,
      NATIONALITY_WASM_PATH,
      NATIONALITY_ZKEY_PATH
    );
    const proofGenTime = Date.now() - proofGenStart;

    // Wrap in ProofResponse with a fresh nonce
    const proofResponse: ProofResponse = {
      proof,
      nonce,
      claimType: 'nationality',
      credentialId,
      signedCredential,
      requestTimestamp,
    };

    // Verify the proof
    const verifyStart = Date.now();
    const clientIp = req.ip || req.socket.remoteAddress || 'unknown';
    const result = await zkIdServer.verifyProof(proofResponse, clientIp);
    const verifyTime = Date.now() - verifyStart;
    const totalTime = Date.now() - proofGenStart;

    if (result.verified) {
      const nationalityName = getNationalityName(targetNationality);
      res.json({
        verified: true,
        message: `Nationality verification successful! User has nationality: ${nationalityName}`,
        timing: {
          proofGenerationMs: proofGenTime,
          verificationMs: verifyTime,
          totalMs: totalTime,
        },
        privacy: {
          revealed: [`Nationality = ${nationalityName} (${targetNationality})`],
          hidden: ['Birth year', 'Age', 'Other attributes'],
        },
        proofDetails: {
          system: 'Groth16',
          curve: 'BN128',
          proofSize: `${JSON.stringify(proof.proof).length} bytes`,
        },
      });
    } else {
      res.json({
        verified: false,
        message: result.error || 'Nationality verification failed',
        timing: {
          proofGenerationMs: proofGenTime,
          verificationMs: verifyTime,
          totalMs: totalTime,
        },
      });
    }
  } catch (error) {
    console.error('Error in demo nationality verification:', error);
    // Check if this is a circuit assertion failure (user doesn't have the target nationality)
    const errorMsg = error instanceof Error ? error.message : 'Unknown error';
    const isAssertionFailure = errorMsg.includes('Assert Failed');

    res.status(400).json({
      verified: false,
      message: isAssertionFailure
        ? `Nationality verification failed: User does not have the target nationality`
        : `Failed to generate or verify proof: ${errorMsg}`,
    });
  }
});

/**
 * Demo endpoint: Generate and verify revocable age proof
 */
app.post('/api/demo/verify-age-revocable', async (req, res) => {
  try {
    const { credentialId, minAge, nonce: providedNonce, requestTimestamp: providedTimestamp } = req.body;

    if (!credentialId || minAge === undefined) {
      return res.status(400).json({
        error: 'Missing required fields: credentialId, minAge',
      });
    }

    // Validate minAge
    if (!Number.isInteger(minAge) || minAge < 0 || minAge > 150) {
      return res.status(400).json({
        error: 'Invalid minAge: must be a number between 0 and 150',
      });
    }

    // Look up stored credential
    const signedCredential = issuedCredentials.get(credentialId);
    if (!signedCredential) {
      return res.status(404).json({
        error: 'Credential not found',
      });
    }

    // Get Merkle witness from the valid credential tree
    const witness = await validCredentialTree.getWitness(signedCredential.credential.commitment);
    if (!witness) {
      return res.status(400).json({
        error: 'Credential not found in valid credential tree (possibly revoked)',
      });
    }

    // Generate proof (this is the expensive operation)
    const proofGenStart = Date.now();
    const { nonce, requestTimestamp } =
      providedNonce && providedTimestamp
        ? { nonce: providedNonce, requestTimestamp: providedTimestamp }
        : await zkIdServer.createChallenge();
    const requestTimestampMs = Date.parse(requestTimestamp);
    const proof = await generateAgeProofRevocable(
      signedCredential.credential,
      minAge,
      nonce,
      requestTimestampMs,
      witness,
      AGE_REVOCABLE_WASM_PATH,
      AGE_REVOCABLE_ZKEY_PATH
    );
    const proofGenTime = Date.now() - proofGenStart;

    // Wrap in ProofResponse with a fresh nonce
    const proofResponse: ProofResponse = {
      proof,
      nonce,
      claimType: 'age-revocable',
      credentialId,
      signedCredential,
      requestTimestamp,
    };

    // Verify the proof
    const verifyStart = Date.now();
    const clientIp = req.ip || req.socket.remoteAddress || 'unknown';
    const result = await zkIdServer.verifyProof(proofResponse, clientIp);
    const verifyTime = Date.now() - verifyStart;
    const totalTime = Date.now() - proofGenStart;

    if (result.verified) {
      res.json({
        verified: true,
        message: `Revocable age verification successful! User is at least ${minAge} years old and credential is valid (not revoked).`,
        timing: {
          proofGenerationMs: proofGenTime,
          verificationMs: verifyTime,
          totalMs: totalTime,
        },
        privacy: {
          revealed: [`Age >= ${minAge}`, 'Credential is in valid set'],
          hidden: ['Exact birth year', 'Nationality', 'Other attributes'],
        },
        proofDetails: {
          system: 'Groth16',
          curve: 'BN128',
          proofSize: `${JSON.stringify(proof.proof).length} bytes`,
          merkleRoot: proof.publicSignals.merkleRoot,
        },
      });
    } else {
      res.json({
        verified: false,
        message: result.error || 'Revocable age verification failed',
        timing: {
          proofGenerationMs: proofGenTime,
          verificationMs: verifyTime,
          totalMs: totalTime,
        },
      });
    }
  } catch (error) {
    console.error('Error in demo revocable age verification:', error);
    // Check if this is a circuit assertion failure (user too young)
    const errorMsg = error instanceof Error ? error.message : 'Unknown error';
    const isAssertionFailure = errorMsg.includes('Assert Failed');

    res.status(400).json({
      verified: false,
      message: isAssertionFailure
        ? `Age verification failed: User is younger than ${req.body.minAge}`
        : `Failed to generate or verify proof: ${errorMsg}`,
    });
  }
});

/**
 * Demo endpoint: Generate and verify signed nationality proof
 */
app.post('/api/demo/verify-nationality-signed', async (req, res) => {
  try {
    const { credentialId, targetNationality, nonce: providedNonce, requestTimestamp: providedTimestamp } = req.body;

    if (!credentialId || targetNationality === undefined) {
      return res.status(400).json({
        error: 'Missing required fields: credentialId, targetNationality',
      });
    }

    if (!Number.isInteger(targetNationality) || targetNationality < 1 || targetNationality > 999) {
      return res.status(400).json({
        error: 'Invalid targetNationality: must be a number between 1 and 999',
      });
    }

    const signedCredential = issuedCircuitCredentials.get(credentialId);
    if (!signedCredential) {
      return res.status(404).json({
        error: 'Signed-circuit credential not found',
      });
    }

    const proofGenStart = Date.now();
    const { nonce, requestTimestamp } =
      providedNonce && providedTimestamp
        ? { nonce: providedNonce, requestTimestamp: providedTimestamp }
        : await zkIdServer.createChallenge();
    const requestTimestampMs = Date.parse(requestTimestamp);
    const signatureInputs = circuitIssuer.getSignatureInputs(signedCredential);

    const proof = await generateNationalityProofSigned(
      signedCredential.credential,
      targetNationality,
      nonce,
      requestTimestampMs,
      signatureInputs,
      NATIONALITY_SIGNED_WASM_PATH,
      NATIONALITY_SIGNED_ZKEY_PATH
    );
    const proofGenTime = Date.now() - proofGenStart;

    const signedRequest: SignedProofRequest = {
      claimType: 'nationality',
      issuer: signedCredential.issuer,
      nonce,
      requestTimestamp,
      proof,
    };

    const verifyStart = Date.now();
    const clientIp = req.ip || req.socket.remoteAddress || 'unknown';
    const result = await zkIdServer.verifySignedProof(signedRequest, clientIp);
    const verifyTime = Date.now() - verifyStart;
    const totalTime = Date.now() - proofGenStart;

    if (result.verified) {
      const nationalityName = getNationalityName(targetNationality);
      res.json({
        verified: true,
        message: `Signed nationality verification successful! User has nationality: ${nationalityName}`,
        timing: {
          proofGenerationMs: proofGenTime,
          verificationMs: verifyTime,
          totalMs: totalTime,
        },
        privacy: {
          revealed: [`Nationality = ${nationalityName} (${targetNationality})`],
          hidden: ['Birth year', 'Age', 'Other attributes'],
        },
        proofDetails: {
          system: 'Groth16',
          curve: 'BN128',
          proofSize: `${JSON.stringify(proof.proof).length} bytes`,
          issuerVerification: 'In-circuit (BabyJub EdDSA)',
        },
      });
    } else {
      res.json({
        verified: false,
        message: result.error || 'Signed nationality verification failed',
        timing: {
          proofGenerationMs: proofGenTime,
          verificationMs: verifyTime,
          totalMs: totalTime,
        },
      });
    }
  } catch (error) {
    console.error('Error in demo signed nationality verification:', error);
    const errorMsg = error instanceof Error ? error.message : 'Unknown error';
    const isAssertionFailure = errorMsg.includes('Assert Failed');

    res.status(400).json({
      verified: false,
      message: isAssertionFailure
        ? `Signed nationality verification failed: User does not meet the target nationality requirement`
        : `Failed to generate or verify signed proof: ${errorMsg}`,
    });
  }
});

// Helper function to get nationality name
function getNationalityName(code: number): string {
  const names: { [key: number]: string } = {
    840: 'United States',
    826: 'United Kingdom',
    124: 'Canada',
    276: 'Germany',
    250: 'France',
    392: 'Japan',
  };
  return names[code] || `Country ${code}`;
}

/**
 * Demo endpoint: Revoke a credential (admin only - would require auth in production)
 */
app.post('/api/revoke-credential', async (req, res) => {
  try {
    const { credentialId } = req.body;

    if (!credentialId) {
      return res.status(400).json({
        error: 'Missing credentialId',
      });
    }

    const signedCredential = issuedCredentials.get(credentialId);
    const circuitCredential = issuedCircuitCredentials.get(credentialId);
    const credential = signedCredential?.credential || circuitCredential?.credential;
    if (!credential) {
      return res.status(404).json({
        error: 'Credential not found',
      });
    }

    await revocationStore.revoke(credential.commitment);

    // Remove from valid credential tree for revocable proofs
    await validCredentialTree.remove(credential.commitment);

    res.json({
      success: true,
      message: 'Credential revoked successfully',
    });
  } catch (error) {
    console.error('Error revoking credential:', error);
    res.status(500).json({
      error: 'Failed to revoke credential',
      details: error instanceof Error ? error.message : 'Unknown error',
    });
  }
});

/**
 * Health check endpoint
 */
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    issuer: 'Demo Government ID Authority',
    protocolVersion: PROTOCOL_VERSION,
  });
});

// Start server
  app.listen(PORT, () => {
    console.log(`\n🚀 ZK-ID Demo Web App running at http://localhost:${PORT}`);
    console.log(`\nFeatures:`);
    console.log(`  ✓ Credential issuance with Ed25519 signatures`);
    console.log(`  ✓ Zero-knowledge age and nationality verification`);
    console.log(`  ✓ Credential revocation support`);
    console.log(`  ✓ Real-time telemetry and logging`);
    console.log(`  ✓ Signed-circuit verification (issuer signatures in-circuit)`);
    console.log(`\nEndpoints:`);
    console.log(`  POST /api/issue-credential`);
    console.log(`  POST /api/issue-credential-signed`);
    console.log(`  GET  /api/challenge`);
    console.log(`  POST /api/verify-age`);
    console.log(`  POST /api/verify-nationality`);
    console.log(`  POST /api/demo/verify-age`);
    console.log(`  POST /api/demo/verify-nationality`);
    console.log(`  POST /api/demo/verify-age-signed`);
    console.log(`  POST /api/demo/verify-nationality-signed`);
    console.log(`  POST /api/revoke-credential`);
    console.log(`  GET  /api/health\n`);
  });
}

main().catch((error) => {
  console.error('Failed to start demo server:', error);
  process.exit(1);
});
