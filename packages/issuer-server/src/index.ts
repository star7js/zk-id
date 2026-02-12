import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import dotenv from 'dotenv';
import { ManagedCredentialIssuer, InMemoryIssuerKeyManager } from '@zk-id/issuer';
import { InMemoryRevocationStore } from '@zk-id/core';
import { createPublicKey, generateKeyPairSync, KeyObject } from 'crypto';

dotenv.config();

const PORT = process.env.PORT || 3001;
const API_KEY = process.env.API_KEY || 'dev-api-key-change-in-production';
const ISSUER_NAME = process.env.ISSUER_NAME || 'zk-id Reference Issuer';

// Rate limiting configuration
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
});

// Initialize Express app
const app = express();

// Middleware
app.use(helmet());
app.use(
  cors({
    origin: process.env.CORS_ORIGIN || '*',
    credentials: true,
  }),
);
app.use(express.json());
app.use(limiter);

// API key authentication middleware
function requireApiKey(req: Request, res: Response, next: NextFunction) {
  const apiKey = req.headers['x-api-key'];

  if (!apiKey || apiKey !== API_KEY) {
    return res.status(401).json({
      error: 'Unauthorized',
      message: 'Valid API key required',
    });
  }

  next();
}

// Request logging middleware
function requestLogger(req: Request, res: Response, next: NextFunction) {
  const timestamp = new Date().toISOString();
  console.log(`[${timestamp}] ${req.method} ${req.path}`);
  next();
}

app.use(requestLogger);

// Initialize issuer
let issuer: ManagedCredentialIssuer;
let issuerPublicKey: KeyObject;

function initializeIssuer() {
  try {
    // Check if private key is provided via environment
    const privateKeyPem = process.env.ISSUER_PRIVATE_KEY;
    const publicKeyPem = process.env.ISSUER_PUBLIC_KEY;

    let privateKey: KeyObject;
    let publicKey: KeyObject;

    if (privateKeyPem && publicKeyPem) {
      // Use provided keys
      privateKey = createPublicKey({
        key: Buffer.from(privateKeyPem, 'base64'),
        format: 'der',
        type: 'pkcs8',
      });
      publicKey = createPublicKey({
        key: Buffer.from(publicKeyPem, 'base64'),
        format: 'der',
        type: 'spki',
      });
      console.log('Using provided Ed25519 keys');
    } else {
      // Generate new keys (for development only)
      console.warn('WARN: No keys provided, generating new Ed25519 keys (NOT FOR PRODUCTION)');
      const keyPair = generateKeyPairSync('ed25519', {
        publicKeyEncoding: { type: 'spki', format: 'der' },
        privateKeyEncoding: { type: 'pkcs8', format: 'der' },
      });

      privateKey = createPublicKey({
        key: keyPair.privateKey,
        format: 'der',
        type: 'pkcs8',
      });
      publicKey = createPublicKey({
        key: keyPair.publicKey,
        format: 'der',
        type: 'spki',
      });

      // Log keys in base64 for configuration
      console.log('\nGenerated Keys (save these to environment variables):');
      console.log('ISSUER_PRIVATE_KEY=' + Buffer.from(keyPair.privateKey).toString('base64'));
      console.log('ISSUER_PUBLIC_KEY=' + Buffer.from(keyPair.publicKey).toString('base64'));
      console.log('');
    }

    // Create key manager
    const keyManager = new InMemoryIssuerKeyManager(ISSUER_NAME, privateKey, publicKey);

    // Create issuer with revocation support
    const revocationStore = new InMemoryRevocationStore();
    issuer = new ManagedCredentialIssuer(keyManager);
    issuer.setRevocationStore(revocationStore);

    issuerPublicKey = publicKey;

    console.log(`Issuer initialized: ${ISSUER_NAME}`);
  } catch (error) {
    console.error('Failed to initialize issuer:', error);
    process.exit(1);
  }
}

initializeIssuer();

// Health check endpoint
app.get('/health', (req: Request, res: Response) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    issuer: ISSUER_NAME,
  });
});

// Get issuer public key
app.get('/public-key', (req: Request, res: Response) => {
  const publicKeyDer = issuerPublicKey.export({ type: 'spki', format: 'der' });
  const publicKeyBase64 = Buffer.from(publicKeyDer).toString('base64');

  res.json({
    issuer: ISSUER_NAME,
    publicKey: publicKeyBase64,
    format: 'Ed25519-SPKI-DER',
  });
});

// Issue credential
app.post('/issue', requireApiKey, async (req: Request, res: Response) => {
  try {
    const { birthYear, nationality, userId, expiresAt } = req.body;

    // Validate inputs
    if (!birthYear || typeof birthYear !== 'number') {
      return res.status(400).json({
        error: 'Invalid request',
        message: 'birthYear is required and must be a number',
      });
    }

    if (!nationality || typeof nationality !== 'number') {
      return res.status(400).json({
        error: 'Invalid request',
        message: 'nationality is required and must be a number (ISO 3166-1 numeric)',
      });
    }

    if (!userId || typeof userId !== 'string') {
      return res.status(400).json({
        error: 'Invalid request',
        message: 'userId is required and must be a string',
      });
    }

    // Validate expiration date if provided
    if (expiresAt) {
      const expirationDate = new Date(expiresAt);
      if (isNaN(expirationDate.getTime())) {
        return res.status(400).json({
          error: 'Invalid request',
          message: 'expiresAt must be a valid ISO 8601 date string',
        });
      }

      if (expirationDate <= new Date()) {
        return res.status(400).json({
          error: 'Invalid request',
          message: 'expiresAt must be in the future',
        });
      }
    }

    // Issue credential
    const signedCredential = await issuer.issueCredential(birthYear, nationality, userId);

    // Add expiration if provided
    if (expiresAt) {
      signedCredential.expiresAt = expiresAt;
    }

    console.log(`Issued credential for user ${userId}`);

    res.json({
      success: true,
      credential: signedCredential,
    });
  } catch (error) {
    console.error('Error issuing credential:', error);
    res.status(500).json({
      error: 'Internal server error',
      message: 'Failed to issue credential',
    });
  }
});

// Revoke credential
app.post('/revoke', requireApiKey, async (req: Request, res: Response) => {
  try {
    const { commitment } = req.body;

    if (!commitment || typeof commitment !== 'string') {
      return res.status(400).json({
        error: 'Invalid request',
        message: 'commitment is required and must be a string',
      });
    }

    await issuer.revokeCredential(commitment);

    console.log(`Revoked credential: ${commitment}`);

    res.json({
      success: true,
      message: 'Credential revoked',
      commitment,
    });
  } catch (error) {
    console.error('Error revoking credential:', error);
    res.status(500).json({
      error: 'Internal server error',
      message: 'Failed to revoke credential',
    });
  }
});

// Get credential status
app.get('/status/:commitment', async (req: Request, res: Response) => {
  try {
    const { commitment } = req.params;

    if (!issuer.getRevocationStore()) {
      return res.status(501).json({
        error: 'Not implemented',
        message: 'Revocation checking is not enabled',
      });
    }

    const isRevoked = await issuer.getRevocationStore()!.isRevoked(commitment);

    res.json({
      commitment,
      revoked: isRevoked,
      status: isRevoked ? 'revoked' : 'active',
    });
  } catch (error) {
    console.error('Error checking credential status:', error);
    res.status(500).json({
      error: 'Internal server error',
      message: 'Failed to check credential status',
    });
  }
});

// Error handling middleware
app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
  console.error('Unhandled error:', err);
  res.status(500).json({
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'production' ? 'An error occurred' : err.message,
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`\n🚀 zk-id Issuer Server`);
  console.log(`   Port: ${PORT}`);
  console.log(`   Issuer: ${ISSUER_NAME}`);
  console.log(`   Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`\n📍 Endpoints:`);
  console.log(`   GET  /health       - Health check`);
  console.log(`   GET  /public-key   - Get issuer public key`);
  console.log(`   POST /issue        - Issue credential (requires API key)`);
  console.log(`   POST /revoke       - Revoke credential (requires API key)`);
  console.log(`   GET  /status/:commitment - Check credential status`);
  console.log(
    `\n🔑 API Key: Set X-Api-Key header to ${API_KEY === 'dev-api-key-change-in-production' ? 'your API key' : '***'}`,
  );
  console.log('');
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('SIGINT received, shutting down gracefully');
  process.exit(0);
});
