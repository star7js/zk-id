/**
 * OpenID4VP Verifier Demo Server
 *
 * Demonstrates how to use the OpenID4VPVerifier to create
 * standards-compliant authorization requests and verify presentations.
 */

import express from 'express';
import cors from 'cors';
import QRCode from 'qrcode';
import { ZkIdServer, OpenID4VPVerifier, InMemoryIssuerRegistry } from '@zk-id/sdk';
import { createPublicKey } from 'crypto';

const PORT = process.env.PORT || 3002;

const app = express();
app.use(cors({
  origin: ['http://localhost:3000', 'http://localhost:3001'],
  credentials: true,
}));
app.use(express.json());

// Initialize ZkIdServer (standard verification)
const zkIdServer = new ZkIdServer({
  verificationKeyPath: '../../packages/circuits/verification_key.json',
  issuerRegistry: new InMemoryIssuerRegistry([
    /* Add issuer public keys here */
  ]),
});

// Wrap with OpenID4VP verifier
const verifier = new OpenID4VPVerifier({
  zkIdServer,
  verifierUrl: `http://localhost:${PORT}`,
  verifierId: 'demo-verifier',
  callbackUrl: `http://localhost:${PORT}/openid4vp/callback`,
});

// Create authorization request for age verification
app.get('/auth/request', async (req, res) => {
  try {
    const minAge = parseInt(req.query.minAge as string) || 18;
    const authRequest = verifier.createAgeVerificationRequest(minAge);

    // Generate QR code for mobile wallets
    const authUrl = `openid4vp://?${new URLSearchParams({
      presentation_definition: JSON.stringify(authRequest.presentation_definition),
      response_uri: authRequest.response_uri,
      nonce: authRequest.nonce,
      client_id: authRequest.client_id,
      state: authRequest.state,
    })}`;

    const qrCode = await QRCode.toDataURL(authUrl);

    res.json({
      authRequest,
      authUrl,
      qrCode,
    });
  } catch (error) {
    console.error('Error creating authorization request:', error);
    res.status(500).json({ error: 'Failed to create authorization request' });
  }
});

// Handle presentation submission (OpenID4VP callback)
app.post('/openid4vp/callback', async (req, res) => {
  try {
    const presentationResponse = req.body;

    const result = await verifier.verifyPresentation(presentationResponse, req.ip);

    if (result.verified) {
      console.log('✅ Presentation verified successfully');
      res.json({
        status: 'success',
        verified: true,
        message: 'Age verified',
      });
    } else {
      console.log('❌ Presentation verification failed:', result.error);
      res.status(400).json({
        status: 'failed',
        verified: false,
        error: result.error,
      });
    }
  } catch (error) {
    console.error('Error verifying presentation:', error);
    res.status(500).json({
      status: 'error',
      error: 'Internal server error',
    });
  }
});

// Root endpoint - redirect to UI
app.get('/', (req, res) => {
  res.redirect('http://localhost:3000');
});

// Health check
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'openid4vp-verifier',
    port: PORT,
  });
});

app.listen(PORT, () => {
  console.log(`\n🔍 OpenID4VP Verifier`);
  console.log(`   Port: ${PORT}`);
  console.log(`   Authorization endpoint: http://localhost:${PORT}/auth/request`);
  console.log(`   Callback endpoint: http://localhost:${PORT}/openid4vp/callback`);
  console.log('');
});
