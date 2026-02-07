import express from 'express';
import { join } from 'path';
import { CredentialIssuer } from '@zk-id/issuer';
import { ZkIdServer, InMemoryNonceStore } from '@zk-id/sdk';
import { ProofResponse, InMemoryRevocationStore } from '@zk-id/core';

const app = express();
const PORT = 3000;

// Middleware
app.use(express.json());
app.use(express.static(join(__dirname, 'public')));

// Create a test issuer (in production, this would use secure key management)
const issuer = CredentialIssuer.createTestIssuer('Demo Government ID Authority');
const revocationStore = new InMemoryRevocationStore();
issuer.setRevocationStore(revocationStore);

// Setup ZK-ID server for verification
const zkIdServer = new ZkIdServer({
  verificationKeyPath: join(__dirname, '../../../packages/circuits/build/age-verify_verification_key.json'),
  nationalityVerificationKeyPath: join(__dirname, '../../../packages/circuits/build/nationality-verify_verification_key.json'),
  nonceStore: new InMemoryNonceStore(),
  revocationStore,
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
 * Demo endpoint: Verify age proof
 */
app.post('/api/verify-age', async (req, res) => {
  try {
    const proofResponse: ProofResponse = req.body;
    const clientIp = req.ip || req.socket.remoteAddress || 'unknown';

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

    await issuer.revokeCredential(credentialId);

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
  console.log(`\nEndpoints:`);
  console.log(`  POST /api/issue-credential`);
  console.log(`  POST /api/verify-age`);
  console.log(`  POST /api/verify-nationality`);
  console.log(`  POST /api/revoke-credential`);
  console.log(`  GET  /api/health\n`);
});
