import express from 'express';
import rateLimit from 'express-rate-limit';
import { join } from 'path';
import { CredentialIssuer } from '@zk-id/issuer';
import {
  ZkIdServer,
  InMemoryNonceStore,
  InMemoryIssuerRegistry,
  InMemoryChallengeStore,
} from '@zk-id/sdk';
import {
  ProofResponse,
  InMemoryRevocationStore,
  InMemoryValidCredentialTree,
  PROTOCOL_VERSION,
  isProtocolCompatible,
  SCENARIOS,
} from '@zk-id/core';

async function main() {
  const app = express();
  const PORT = Number(process.env.PORT) || 3000;

  // Circuit paths for static file serving
  const CIRCUITS_BASE = join(__dirname, '../../../packages/circuits/build');

  // Middleware
  app.use(express.json({ limit: '100kb' }));
  app.use(express.static(join(__dirname, 'public')));
  app.use('/circuits', express.static(CIRCUITS_BASE));

  // Protocol version header middleware
  app.use((req, res, next) => {
    res.setHeader('X-ZkId-Protocol-Version', PROTOCOL_VERSION);
    const clientVersion = req.get('X-ZkId-Protocol-Version');
    if (clientVersion && !isProtocolCompatible(PROTOCOL_VERSION, clientVersion)) {
      return res.status(400).json({
        error: 'Incompatible protocol version',
        clientVersion,
        serverVersion: PROTOCOL_VERSION,
      });
    }
    next();
  });

  const getClientProtocolVersion = (req: express.Request): string | undefined =>
    req.get('X-ZkId-Protocol-Version') ?? undefined;

  // Basic rate limiting for API endpoints (tune via env for real deployments)
  const apiLimiter = rateLimit({
    windowMs: 60 * 1000,
    limit: Number(process.env.API_RATE_LIMIT || 60),
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests, please try again later.' },
  });

  // Create a test issuer (in production, this would use secure key management)
  const issuerName = 'Demo Government ID Authority';
  const issuer = CredentialIssuer.createTestIssuer(issuerName);
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
    verificationKeyPath: join(
      __dirname,
      '../../../packages/circuits/build/age-verify_verification_key.json',
    ),
    nationalityVerificationKeyPath: join(
      __dirname,
      '../../../packages/circuits/build/nationality-verify_verification_key.json',
    ),
    signedVerificationKeyPath: join(
      __dirname,
      '../../../packages/circuits/build/age-verify-signed_verification_key.json',
    ),
    signedNationalityVerificationKeyPath: join(
      __dirname,
      '../../../packages/circuits/build/nationality-verify-signed_verification_key.json',
    ),
    revocableVerificationKeyPath: join(
      __dirname,
      '../../../packages/circuits/build/age-verify-revocable_verification_key.json',
    ),
    nonceStore: new InMemoryNonceStore(),
    challengeStore: new InMemoryChallengeStore(),
    challengeTtlMs: 5 * 60 * 1000,
    revocationStore,
    validCredentialTree,
    issuerRegistry,
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
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const issuedCredentials = new Map<string, any>();

  /**
   * Demo endpoint: Issue a credential
   * In production, this would:
   * - Require authentication
   * - Verify user's identity through KYC
   * - Rate limit requests
   */
  app.post('/api/issue-credential', apiLimiter, async (req, res) => {
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
  app.get('/api/challenge', apiLimiter, async (_req, res) => {
    const challenge = await zkIdServer.createChallenge();
    res.json(challenge);
  });

  /**
   * Demo endpoint: Verify age proof
   */
  app.post('/api/verify-age', apiLimiter, async (req, res) => {
    try {
      const proofResponse: ProofResponse = req.body;
      const clientIp = req.ip || req.socket.remoteAddress || 'unknown';
      if (!proofResponse.nonce || !proofResponse.requestTimestamp) {
        return res.status(400).json({
          verified: false,
          error:
            'Missing nonce or requestTimestamp. Fetch /api/challenge before generating a proof.',
        });
      }

      // Verify the proof
      const result = await zkIdServer.verifyProof(
        proofResponse,
        clientIp,
        getClientProtocolVersion(req),
      );

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
  app.post('/api/verify-nationality', apiLimiter, async (req, res) => {
    try {
      const proofResponse: ProofResponse = req.body;
      const clientIp = req.ip || req.socket.remoteAddress || 'unknown';
      if (!proofResponse.nonce || !proofResponse.requestTimestamp) {
        return res.status(400).json({
          verified: false,
          error:
            'Missing nonce or requestTimestamp. Fetch /api/challenge before generating a proof.',
        });
      }

      // Verify the proof
      const result = await zkIdServer.verifyProof(
        proofResponse,
        clientIp,
        getClientProtocolVersion(req),
      );

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
  app.post('/api/revoke-credential', apiLimiter, async (req, res) => {
    try {
      const { credentialId } = req.body;

      if (!credentialId) {
        return res.status(400).json({
          error: 'Missing credentialId',
        });
      }

      const signedCredential = issuedCredentials.get(credentialId);
      if (!signedCredential) {
        return res.status(404).json({
          error: 'Credential not found',
        });
      }

      await revocationStore.revoke(signedCredential.credential.commitment);

      // Remove from valid credential tree for revocable proofs
      await validCredentialTree.remove(signedCredential.credential.commitment);

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
   * Revocation root endpoint (root + version metadata)
   */
  app.get('/api/revocation/root', apiLimiter, async (_req, res) => {
    try {
      const info = await validCredentialTree.getRootInfo();
      res.json(info);
    } catch (error) {
      console.error('Error fetching revocation root:', error);
      res.status(500).json({
        error: 'Failed to fetch revocation root',
        details: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  });

  /**
   * Scenario endpoint: Verify US voting eligibility (age >= 18 AND nationality = USA)
   */
  app.post('/api/verify-voting-eligibility', apiLimiter, async (req, res) => {
    try {
      const scenario = SCENARIOS.VOTING_ELIGIBILITY_US;
      const { proofs } = req.body as { proofs: ProofResponse[] };

      if (!proofs || !Array.isArray(proofs) || proofs.length !== scenario.claims.length) {
        return res.status(400).json({
          error: `Expected ${scenario.claims.length} proofs for ${scenario.name}`,
        });
      }

      // Verify each proof in the scenario
      const results = await Promise.all(
        proofs.map(async (proof) => {
          try {
            const result = await zkIdServer.verifyProof(
              proof,
              undefined,
              getClientProtocolVersion(req),
            );
            return result.verified;
          } catch {
            return false;
          }
        }),
      );

      // All proofs must pass for scenario to be satisfied
      const allVerified = results.every((r: boolean) => r);

      res.json({
        verified: allVerified,
        scenario: scenario.name,
        message: allVerified
          ? 'Voting eligibility verified'
          : 'Voting eligibility verification failed',
      });
    } catch (error) {
      console.error('Error verifying voting eligibility:', error);
      res.status(500).json({
        error: 'Verification failed',
        details: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  });

  /**
   * Scenario endpoint: Verify senior discount eligibility (age >= 65)
   */
  app.post('/api/verify-senior-discount', apiLimiter, async (req, res) => {
    try {
      const scenario = SCENARIOS.SENIOR_DISCOUNT;
      const { proofs } = req.body as { proofs: ProofResponse[] };

      if (!proofs || !Array.isArray(proofs) || proofs.length !== scenario.claims.length) {
        return res.status(400).json({
          error: `Expected ${scenario.claims.length} proof for ${scenario.name}`,
        });
      }

      // Verify the age proof
      const proof = proofs[0];
      let verified = false;

      try {
        const result = await zkIdServer.verifyProof(
          proof,
          undefined,
          getClientProtocolVersion(req),
        );
        verified = result.verified;
      } catch {
        verified = false;
      }

      res.json({
        verified,
        scenario: scenario.name,
        message: verified ? 'Senior discount eligibility verified' : 'Senior discount verification failed',
      });
    } catch (error) {
      console.error('Error verifying senior discount:', error);
      res.status(500).json({
        error: 'Verification failed',
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
    console.log(`  ✓ Client-side ZK proof generation in browser`);
    console.log(`  ✓ Credential issuance with Ed25519 signatures`);
    console.log(`  ✓ Zero-knowledge age and nationality verification`);
    console.log(`  ✓ Credential revocation support`);
    console.log(`  ✓ Real-time telemetry and logging`);
    console.log(`\nEndpoints:`);
    console.log(`  POST /api/issue-credential`);
    console.log(`  GET  /api/challenge`);
    console.log(`  POST /api/verify-age`);
    console.log(`  POST /api/verify-nationality`);
    console.log(`  POST /api/revoke-credential`);
    console.log(`  GET  /api/revocation/root`);
    console.log(`  GET  /api/health\n`);
  });
}

main().catch((error) => {
  console.error('Failed to start demo server:', error);
  process.exit(1);
});
