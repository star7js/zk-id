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
  MultiClaimResponse,
  InMemoryRevocationStore,
  InMemoryValidCredentialTree,
  SignedCredential,
  PROTOCOL_VERSION,
  isProtocolCompatible,
  SCENARIOS,
  getScenarioById,
  verifyScenario,
} from '@zk-id/core';

async function main() {
  const app = express();
  const PORT = Number(process.env.PORT) || 3000;

  // Circuit paths for static file serving
  const CIRCUITS_BASE = join(__dirname, '../../../packages/circuits/build');

  // CORS configuration for production
  const LOCALHOST_ORIGIN = 'http://localhost:4321';
  const GITHUB_PAGES_ORIGIN = 'https://star7js.github.io';
  const CUSTOM_DOMAIN_ORIGIN = 'https://zk-id.io';
  const CUSTOM_DOMAIN_HTTP_ORIGIN = 'http://zk-id.io';

  app.use((req, res, next) => {
    const origin = req.headers.origin;
    // Explicit origin mapping prevents reflective CORS headers.
    if (origin === LOCALHOST_ORIGIN) {
      res.header('Access-Control-Allow-Origin', LOCALHOST_ORIGIN);
      res.header('Vary', 'Origin');
      res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
      res.header('Access-Control-Allow-Headers', 'Content-Type, X-ZkId-Protocol-Version');
    } else if (origin === GITHUB_PAGES_ORIGIN) {
      res.header('Access-Control-Allow-Origin', GITHUB_PAGES_ORIGIN);
      res.header('Vary', 'Origin');
      res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
      res.header('Access-Control-Allow-Headers', 'Content-Type, X-ZkId-Protocol-Version');
    } else if (origin === CUSTOM_DOMAIN_ORIGIN) {
      res.header('Access-Control-Allow-Origin', CUSTOM_DOMAIN_ORIGIN);
      res.header('Vary', 'Origin');
      res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
      res.header('Access-Control-Allow-Headers', 'Content-Type, X-ZkId-Protocol-Version');
    } else if (origin === CUSTOM_DOMAIN_HTTP_ORIGIN) {
      res.header('Access-Control-Allow-Origin', CUSTOM_DOMAIN_HTTP_ORIGIN);
      res.header('Vary', 'Origin');
      res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
      res.header('Access-Control-Allow-Headers', 'Content-Type, X-ZkId-Protocol-Version');
    }
    if (req.method === 'OPTIONS') {
      return res.sendStatus(200);
    }
    next();
  });

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
    verboseErrors: false,
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

  // --- Request body shape validators ---

  const isNonEmptyString = (v: unknown): v is string => typeof v === 'string' && v.length > 0;

  /**
   * Validates that a request body has the shape of a ProofResponse at runtime.
   * Returns an error string if invalid, null if OK.
   */
  const validateProofResponseShape = (body: unknown): string | null => {
    if (body == null || typeof body !== 'object' || Array.isArray(body)) {
      return 'Request body must be a JSON object';
    }
    const obj = body as Record<string, unknown>;

    if (!isNonEmptyString(obj.claimType)) return 'Missing or invalid claimType';
    if (!isNonEmptyString(obj.nonce)) return 'Missing or invalid nonce';
    if (!isNonEmptyString(obj.requestTimestamp)) return 'Missing or invalid requestTimestamp';

    if (obj.proof == null || typeof obj.proof !== 'object' || Array.isArray(obj.proof)) {
      return 'Missing or invalid proof object';
    }
    return null;
  };

  /**
   * Validates that a request body has the shape of a MultiClaimResponse at runtime.
   * Returns an error string if invalid, null if OK.
   */
  const validateMultiClaimResponseShape = (body: unknown): string | null => {
    if (body == null || typeof body !== 'object' || Array.isArray(body)) {
      return 'Request body must be a JSON object';
    }
    const obj = body as Record<string, unknown>;

    if (!isNonEmptyString(obj.nonce)) return 'Missing or invalid nonce';
    if (!isNonEmptyString(obj.requestTimestamp)) return 'Missing or invalid requestTimestamp';
    if (!isNonEmptyString(obj.credentialId)) return 'Missing or invalid credentialId';

    if (!Array.isArray(obj.proofs)) return 'proofs must be an array';
    for (let i = 0; i < obj.proofs.length; i += 1) {
      const p = obj.proofs[i] as Record<string, unknown> | undefined;
      if (p == null || typeof p !== 'object') return `proofs[${i}] must be an object`;
      if (!isNonEmptyString(p.claimType)) return `proofs[${i}].claimType is required`;
      if (p.proof == null || typeof p.proof !== 'object') return `proofs[${i}].proof is required`;
    }
    return null;
  };

  /**
   * Validates that a body.proofs is a non-empty array of proof-shaped objects.
   * Returns an error string if invalid, null if OK.
   */
  const validateProofsArrayShape = (body: unknown): string | null => {
    if (body == null || typeof body !== 'object' || Array.isArray(body)) {
      return 'Request body must be a JSON object';
    }
    const obj = body as Record<string, unknown>;
    if (!Array.isArray(obj.proofs) || obj.proofs.length === 0) {
      return 'proofs must be a non-empty array';
    }
    for (let i = 0; i < obj.proofs.length; i += 1) {
      const err = validateProofResponseShape(obj.proofs[i]);
      if (err) return `proofs[${i}]: ${err}`;
    }
    return null;
  };

  // Store issued credentials (in-memory for demo - production would use database)
  const issuedCredentials = new Map<string, SignedCredential>();

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

      if (birthYear == null || nationality == null) {
        return res.status(400).json({
          error: 'Missing required fields: birthYear, nationality',
        });
      }

      if (typeof birthYear !== 'number' || !Number.isInteger(birthYear)) {
        return res.status(400).json({
          error: 'birthYear must be an integer',
        });
      }

      if (typeof nationality !== 'number' || !Number.isInteger(nationality)) {
        return res.status(400).json({
          error: 'nationality must be an integer',
        });
      }

      if (userId !== undefined && (typeof userId !== 'string' || userId.length > 256)) {
        return res.status(400).json({
          error: 'userId must be a string of at most 256 characters',
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
      res.status(500).json({ error: 'Failed to issue credential' });
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
      const shapeError = validateProofResponseShape(req.body);
      if (shapeError) {
        return res.status(400).json({ verified: false, error: shapeError });
      }
      const proofResponse: ProofResponse = req.body;
      const clientIp = req.ip || req.socket.remoteAddress || 'unknown';

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
      res.status(500).json({ verified: false, error: 'Failed to verify proof' });
    }
  });

  /**
   * Demo endpoint: Verify nationality proof
   */
  app.post('/api/verify-nationality', apiLimiter, async (req, res) => {
    try {
      const shapeError = validateProofResponseShape(req.body);
      if (shapeError) {
        return res.status(400).json({ verified: false, error: shapeError });
      }
      const proofResponse: ProofResponse = req.body;
      const clientIp = req.ip || req.socket.remoteAddress || 'unknown';

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
      res.status(500).json({ verified: false, error: 'Failed to verify proof' });
    }
  });

  /**
   * Demo endpoint: Revoke a credential (admin only - would require auth in production)
   */
  app.post('/api/revoke-credential', apiLimiter, async (req, res) => {
    try {
      const { credentialId } = req.body;

      if (!isNonEmptyString(credentialId) || credentialId.length > 256) {
        return res.status(400).json({
          error: 'credentialId must be a non-empty string (max 256 characters)',
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
      res.status(500).json({ error: 'Failed to revoke credential' });
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
      res.status(500).json({ error: 'Failed to fetch revocation root' });
    }
  });

  const validateScenarioProofs = (
    scenario: typeof SCENARIOS.VOTING_ELIGIBILITY_US,
    proofs: Array<{
      label?: string;
      claimType?: string;
      proof?: {
        proofType?: string;
        publicSignals?: Record<string, unknown> | string[];
      };
    }>,
    requireLabels: boolean,
  ): string | null => {
    if (!proofs || !Array.isArray(proofs) || proofs.length !== scenario.claims.length) {
      return `Expected ${scenario.claims.length} proofs for ${scenario.name}`;
    }

    for (let i = 0; i < proofs.length; i += 1) {
      const expected = scenario.claims[i];
      const proof = proofs[i];

      if (requireLabels && proof.label !== expected.label) {
        return `Expected proof ${i + 1} label '${expected.label}' for ${scenario.name}`;
      }
      if (!expected || proof.claimType !== expected.claimType) {
        return `Expected proof ${i + 1} to be '${expected?.claimType}' for ${scenario.name}`;
      }
      const proofType = proof.proof?.proofType;
      if (proofType && proofType !== expected.claimType) {
        return `Proof ${i + 1} proofType '${proofType}' does not match claimType '${expected.claimType}'`;
      }

      const publicSignals = proof.proof?.publicSignals ?? {};
      // Skip validation for array-type publicSignals (e.g., range proofs)
      if (Array.isArray(publicSignals)) {
        continue;
      }
      if (expected.claimType === 'age' || expected.claimType === 'age-revocable') {
        const minAge = Number(publicSignals.minAge);
        if (Number.isNaN(minAge) || minAge !== expected.minAge) {
          return `Expected proof ${i + 1} minAge ${expected.minAge} for ${scenario.name}`;
        }
      }
      if (expected.claimType === 'nationality') {
        const targetNationality = Number(publicSignals.targetNationality);
        if (Number.isNaN(targetNationality) || targetNationality !== expected.targetNationality) {
          return `Expected proof ${i + 1} nationality ${expected.targetNationality} for ${scenario.name}`;
        }
      }
    }

    return null;
  };

  /**
   * Scenario endpoint: Verify built-in scenario bundle via multi-claim response.
   */
  app.post('/api/verify-scenario', apiLimiter, async (req, res) => {
    try {
      const { scenarioId, response } = req.body as {
        scenarioId?: string;
        response?: MultiClaimResponse;
      };

      if (!isNonEmptyString(scenarioId)) {
        return res.status(400).json({
          error: 'scenarioId must be a non-empty string',
        });
      }

      if (!response) {
        return res.status(400).json({
          error: 'Missing response',
        });
      }

      const responseShapeError = validateMultiClaimResponseShape(response);
      if (responseShapeError) {
        return res.status(400).json({ error: responseShapeError });
      }

      const scenario = getScenarioById(scenarioId);
      if (!scenario) {
        return res.status(404).json({
          error: 'Unknown scenario',
        });
      }

      const validationError = validateScenarioProofs(scenario, response.proofs, true);
      if (validationError) {
        return res.status(400).json({
          error: validationError,
        });
      }

      const clientIp = req.ip || req.socket.remoteAddress || 'unknown';
      const result = await zkIdServer.verifyMultiClaim(
        response,
        clientIp,
        getClientProtocolVersion(req),
      );

      const scenarioResult = verifyScenario(scenario, result);

      res.json({
        scenario: scenario.name,
        ...scenarioResult,
      });
    } catch (error) {
      console.error('Error verifying scenario:', error);
      res.status(500).json({ error: 'Scenario verification failed' });
    }
  });

  /**
   * Scenario endpoint: Verify US voting eligibility (age >= 18 AND nationality = USA)
   */
  app.post('/api/verify-voting-eligibility', apiLimiter, async (req, res) => {
    try {
      const scenario = SCENARIOS.VOTING_ELIGIBILITY_US;
      const proofsShapeError = validateProofsArrayShape(req.body);
      if (proofsShapeError) {
        return res.status(400).json({ error: proofsShapeError });
      }
      const { proofs } = req.body as { proofs: ProofResponse[] };
      const clientIp = req.ip || req.socket.remoteAddress || 'unknown';

      const validationError = validateScenarioProofs(scenario, proofs, false);
      if (validationError) {
        return res.status(400).json({
          error: validationError,
        });
      }

      // Verify each proof in the scenario
      const results = await Promise.all(
        proofs.map(async (proof) => {
          try {
            const result = await zkIdServer.verifyProof(
              proof,
              clientIp,
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
      res.status(500).json({ error: 'Verification failed' });
    }
  });

  /**
   * Scenario endpoint: Verify senior discount eligibility (age >= 65)
   */
  app.post('/api/verify-senior-discount', apiLimiter, async (req, res) => {
    try {
      const scenario = SCENARIOS.SENIOR_DISCOUNT;
      const proofsShapeError = validateProofsArrayShape(req.body);
      if (proofsShapeError) {
        return res.status(400).json({ error: proofsShapeError });
      }
      const { proofs } = req.body as { proofs: ProofResponse[] };
      const clientIp = req.ip || req.socket.remoteAddress || 'unknown';

      const validationError = validateScenarioProofs(scenario, proofs, false);
      if (validationError) {
        return res.status(400).json({
          error: validationError,
        });
      }

      // Verify the age proof
      const proof = proofs[0];
      let verified = false;

      try {
        const result = await zkIdServer.verifyProof(proof, clientIp, getClientProtocolVersion(req));
        verified = result.verified;
      } catch {
        verified = false;
      }

      res.json({
        verified,
        scenario: scenario.name,
        message: verified
          ? 'Senior discount eligibility verified'
          : 'Senior discount verification failed',
      });
    } catch (error) {
      console.error('Error verifying senior discount:', error);
      res.status(500).json({ error: 'Verification failed' });
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
  // Bind to 0.0.0.0 for container/Railway deployment
  const HOST = process.env.HOST || '0.0.0.0';
  app.listen(PORT, HOST, () => {
    console.log(`\n🚀 ZK-ID Demo Web App running at http://${HOST}:${PORT}`);
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
    console.log(`  POST /api/verify-scenario`);
    console.log(`  POST /api/revoke-credential`);
    console.log(`  GET  /api/revocation/root`);
    console.log(`  GET  /api/health\n`);
  });
}

main().catch((error) => {
  console.error('Failed to start demo server:', error);
  process.exit(1);
});
