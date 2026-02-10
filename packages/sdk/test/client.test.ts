import { expect } from 'chai';
import { ZkIdClient, WalletConnector, InMemoryWallet } from '../src/client';
import { ProofRequest, SignedCredential } from '@zk-id/core';

describe('SDK Client Tests', () => {
  const mockSignedCredential: SignedCredential = {
    credential: {
      id: 'test-cred',
      birthYear: 1990,
      nationality: 840,
      salt: '00',
      commitment: '123',
      createdAt: new Date().toISOString(),
    },
    issuer: 'TestIssuer',
    signature: 'invalid-signature',
    issuedAt: new Date().toISOString(),
  };

  describe('ZkIdClient', () => {
    describe('Construction', () => {
      it('should create with config', () => {
        const client = new ZkIdClient({
          verificationEndpoint: 'http://localhost:3000/verify',
        });

        expect(client).to.be.instanceOf(ZkIdClient);
      });
    });

    describe('hasWallet()', () => {
      it('should return false when no wallet connector configured', async () => {
        const client = new ZkIdClient({
          verificationEndpoint: 'http://localhost:3000/verify',
        });

        const hasWallet = await client.hasWallet();

        expect(hasWallet).to.be.false;
      });

      it('should return true when wallet connector reports available', async () => {
        const mockWallet: WalletConnector = {
          isAvailable: async () => true,
          requestProof: async (req) => ({
            credentialId: 'test-cred',
            claimType: req.claimType,
            proof: {} as any,
            signedCredential: mockSignedCredential,
            nonce: req.nonce,
            requestTimestamp: req.timestamp,
          }),
        };

        const client = new ZkIdClient({
          verificationEndpoint: 'http://localhost:3000/verify',
          walletConnector: mockWallet,
        });

        const hasWallet = await client.hasWallet();

        expect(hasWallet).to.be.true;
      });

      it('should return false when wallet connector reports unavailable', async () => {
        const mockWallet: WalletConnector = {
          isAvailable: async () => false,
          requestProof: async (req) => ({
            credentialId: 'test-cred',
            claimType: req.claimType,
            proof: {} as any,
            signedCredential: mockSignedCredential,
            nonce: req.nonce,
            requestTimestamp: req.timestamp,
          }),
        };

        const client = new ZkIdClient({
          verificationEndpoint: 'http://localhost:3000/verify',
          walletConnector: mockWallet,
        });

        const hasWallet = await client.hasWallet();

        expect(hasWallet).to.be.false;
      });
    });

    describe('verifyAge()', () => {
      it('should call wallet connector with correct ProofRequest', async () => {
        let capturedRequest: ProofRequest | null = null;

        const mockWallet: WalletConnector = {
          isAvailable: async () => true,
          requestProof: async (req) => {
            capturedRequest = req;
            return {
              credentialId: 'test-cred',
              claimType: req.claimType,
              proof: {} as any,
              signedCredential: mockSignedCredential,
              nonce: req.nonce,
              requestTimestamp: req.timestamp,
            };
          },
        };

        // Mock fetch
        (global as any).fetch = async (_url: string, _options: any) => ({
          ok: true,
          json: async () => ({ verified: true }),
          statusText: 'OK',
        });

        const client = new ZkIdClient({
          verificationEndpoint: 'http://localhost:3000/verify',
          walletConnector: mockWallet,
        });

        await client.verifyAge(18);

        expect(capturedRequest).to.not.be.null;
        expect(capturedRequest!.claimType).to.equal('age');
        expect(capturedRequest!.minAge).to.equal(18);
        expect(capturedRequest!.nonce).to.be.a('string');
        expect(capturedRequest!.nonce.length).to.be.greaterThan(0);
      });

      it('should submit proof to verification endpoint', async () => {
        let capturedUrl: string | null = null;
        let capturedBody: any = null;

        const mockWallet: WalletConnector = {
          isAvailable: async () => true,
          requestProof: async (req) => ({
            credentialId: 'test-cred',
            claimType: req.claimType,
            proof: {} as any,
            signedCredential: mockSignedCredential,
            nonce: req.nonce,
            requestTimestamp: req.timestamp,
          }),
        };

        // Mock fetch
        (global as any).fetch = async (url: string, options: any) => {
          capturedUrl = url;
          capturedBody = JSON.parse(options.body);
          return {
            ok: true,
            json: async () => ({ verified: true }),
            statusText: 'OK',
          };
        };

        const client = new ZkIdClient({
          verificationEndpoint: 'http://localhost:3000/verify',
          walletConnector: mockWallet,
        });

        await client.verifyAge(21);

        expect(capturedUrl).to.equal('http://localhost:3000/verify');
        expect(capturedBody).to.not.be.null;
        expect(capturedBody.credentialId).to.equal('test-cred');
      });

      it('should return true when backend returns verified: true', async () => {
        const mockWallet: WalletConnector = {
          isAvailable: async () => true,
          requestProof: async (req) => ({
            credentialId: 'test-cred',
            claimType: req.claimType,
            proof: {} as any,
            signedCredential: mockSignedCredential,
            nonce: req.nonce,
            requestTimestamp: req.timestamp,
          }),
        };

        // Mock fetch
        (global as any).fetch = async (_url: string, _options: any) => ({
          ok: true,
          json: async () => ({ verified: true }),
          statusText: 'OK',
          headers: {
            get: (name: string) => (name === 'X-ZkId-Protocol-Version' ? 'zk-id/1.0-draft' : null),
          },
        });

        const client = new ZkIdClient({
          verificationEndpoint: 'http://localhost:3000/verify',
          walletConnector: mockWallet,
        });

        const result = await client.verifyAge(18);

        expect(result).to.be.true;
      });

      it('should return false when backend returns verified: false', async () => {
        const mockWallet: WalletConnector = {
          isAvailable: async () => true,
          requestProof: async (req) => ({
            credentialId: 'test-cred',
            claimType: req.claimType,
            proof: {} as any,
            signedCredential: mockSignedCredential,
            nonce: req.nonce,
            requestTimestamp: req.timestamp,
          }),
        };

        // Mock fetch
        (global as any).fetch = async (_url: string, _options: any) => ({
          ok: true,
          json: async () => ({ verified: false }),
          statusText: 'OK',
          headers: {
            get: (name: string) => (name === 'X-ZkId-Protocol-Version' ? 'zk-id/1.0-draft' : null),
          },
        });

        const client = new ZkIdClient({
          verificationEndpoint: 'http://localhost:3000/verify',
          walletConnector: mockWallet,
        });

        const result = await client.verifyAge(18);

        expect(result).to.be.false;
      });

      it('should return false when wallet throws error', async () => {
        const mockWallet: WalletConnector = {
          isAvailable: async () => true,
          requestProof: async (_req) => {
            throw new Error('Wallet error');
          },
        };

        const client = new ZkIdClient({
          verificationEndpoint: 'http://localhost:3000/verify',
          walletConnector: mockWallet,
        });

        const result = await client.verifyAge(18);

        expect(result).to.be.false;
      });

      it('should return false when no wallet configured', async () => {
        const client = new ZkIdClient({
          verificationEndpoint: 'http://localhost:3000/verify',
        });

        const result = await client.verifyAge(18);

        expect(result).to.be.false;
      });

      it('should include protocol header by default in non-browser environments', async () => {
        let capturedHeaders: Record<string, string> | null = null;

        const mockWallet: WalletConnector = {
          isAvailable: async () => true,
          requestProof: async (req) => ({
            credentialId: 'test-cred',
            claimType: req.claimType,
            proof: {} as any,
            signedCredential: mockSignedCredential,
            nonce: req.nonce,
            requestTimestamp: req.timestamp,
          }),
        };

        (global as any).fetch = async (_url: string, options: any) => {
          capturedHeaders = options.headers;
          return {
            ok: true,
            json: async () => ({ verified: true }),
            statusText: 'OK',
            headers: {
              get: () => null,
            },
          };
        };

        const client = new ZkIdClient({
          verificationEndpoint: 'http://localhost:3000/verify',
          walletConnector: mockWallet,
        });

        await client.verifyAge(18);

        expect(capturedHeaders).to.have.property('X-ZkId-Protocol-Version');
      });

      it('should omit protocol header when policy is never', async () => {
        let capturedHeaders: Record<string, string> | null = null;

        const mockWallet: WalletConnector = {
          isAvailable: async () => true,
          requestProof: async (req) => ({
            credentialId: 'test-cred',
            claimType: req.claimType,
            proof: {} as any,
            signedCredential: mockSignedCredential,
            nonce: req.nonce,
            requestTimestamp: req.timestamp,
          }),
        };

        (global as any).fetch = async (_url: string, options: any) => {
          capturedHeaders = options.headers;
          return {
            ok: true,
            json: async () => ({ verified: true }),
            statusText: 'OK',
            headers: {
              get: () => null,
            },
          };
        };

        const client = new ZkIdClient({
          verificationEndpoint: 'http://localhost:3000/verify',
          walletConnector: mockWallet,
          protocolVersionHeader: 'never',
        });

        await client.verifyAge(18);

        expect(capturedHeaders).to.not.have.property('X-ZkId-Protocol-Version');
      });

      it('should omit protocol header for cross-origin when policy is same-origin', async () => {
        let capturedHeaders: Record<string, string> | null = null;
        const originalWindow = (global as any).window;
        (global as any).window = {
          location: {
            origin: 'https://app.example.com',
            href: 'https://app.example.com/',
          },
        };

        const mockWallet: WalletConnector = {
          isAvailable: async () => true,
          requestProof: async (req) => ({
            credentialId: 'test-cred',
            claimType: req.claimType,
            proof: {} as any,
            signedCredential: mockSignedCredential,
            nonce: req.nonce,
            requestTimestamp: req.timestamp,
          }),
        };

        (global as any).fetch = async (_url: string, options: any) => {
          capturedHeaders = options.headers;
          return {
            ok: true,
            json: async () => ({ verified: true }),
            statusText: 'OK',
            headers: {
              get: () => null,
            },
          };
        };

        const client = new ZkIdClient({
          verificationEndpoint: 'https://api.example.com/verify',
          walletConnector: mockWallet,
          protocolVersionHeader: 'same-origin',
        });

        await client.verifyAge(18);

        expect(capturedHeaders).to.not.have.property('X-ZkId-Protocol-Version');
        (global as any).window = originalWindow;
      });

      it('should include protocol header for cross-origin when policy is always', async () => {
        let capturedHeaders: Record<string, string> | null = null;
        const originalWindow = (global as any).window;
        (global as any).window = {
          location: {
            origin: 'https://app.example.com',
            href: 'https://app.example.com/',
          },
        };

        const mockWallet: WalletConnector = {
          isAvailable: async () => true,
          requestProof: async (req) => ({
            credentialId: 'test-cred',
            claimType: req.claimType,
            proof: {} as any,
            signedCredential: mockSignedCredential,
            nonce: req.nonce,
            requestTimestamp: req.timestamp,
          }),
        };

        (global as any).fetch = async (_url: string, options: any) => {
          capturedHeaders = options.headers;
          return {
            ok: true,
            json: async () => ({ verified: true }),
            statusText: 'OK',
            headers: {
              get: () => null,
            },
          };
        };

        const client = new ZkIdClient({
          verificationEndpoint: 'https://api.example.com/verify',
          walletConnector: mockWallet,
          protocolVersionHeader: 'always',
        });

        await client.verifyAge(18);

        expect(capturedHeaders).to.have.property('X-ZkId-Protocol-Version');
        (global as any).window = originalWindow;
      });
    });

    describe('verifyNationality()', () => {
      it('should call wallet connector with correct ProofRequest', async () => {
        let capturedRequest: ProofRequest | null = null;

        const mockWallet: WalletConnector = {
          isAvailable: async () => true,
          requestProof: async (req) => {
            capturedRequest = req;
            return {
              credentialId: 'test-cred',
              claimType: req.claimType,
              proof: {} as any,
              nonce: req.nonce,
              signedCredential: undefined,
              requestTimestamp: new Date().toISOString(),
            };
          },
        };

        // Mock fetch
        (global as any).fetch = async (_url: string, _options: any) => ({
          ok: true,
          json: async () => ({ verified: true }),
          statusText: 'OK',
        });

        const client = new ZkIdClient({
          verificationEndpoint: 'http://localhost:3000/verify',
          walletConnector: mockWallet,
        });

        await client.verifyNationality(840);

        expect(capturedRequest).to.not.be.null;
        expect(capturedRequest!.claimType).to.equal('nationality');
        expect(capturedRequest!.targetNationality).to.equal(840);
        expect(capturedRequest!.nonce).to.be.a('string');
      });

      it('should return true when backend returns verified: true', async () => {
        const mockWallet: WalletConnector = {
          isAvailable: async () => true,
          requestProof: async (req) => ({
            credentialId: 'test-cred',
            claimType: req.claimType,
            proof: {} as any,
            nonce: req.nonce,
            signedCredential: undefined,
            requestTimestamp: new Date().toISOString(),
          }),
        };

        // Mock fetch
        (global as any).fetch = async (_url: string, _options: any) => ({
          ok: true,
          json: async () => ({ verified: true }),
          statusText: 'OK',
          headers: {
            get: (name: string) => (name === 'X-ZkId-Protocol-Version' ? 'zk-id/1.0-draft' : null),
          },
        });

        const client = new ZkIdClient({
          verificationEndpoint: 'http://localhost:3000/verify',
          walletConnector: mockWallet,
        });

        const result = await client.verifyNationality(840);

        expect(result).to.be.true;
      });

      it('should return false when backend returns verified: false', async () => {
        const mockWallet: WalletConnector = {
          isAvailable: async () => true,
          requestProof: async (req) => ({
            credentialId: 'test-cred',
            claimType: req.claimType,
            proof: {} as any,
            nonce: req.nonce,
            signedCredential: undefined,
            requestTimestamp: new Date().toISOString(),
          }),
        };

        // Mock fetch
        (global as any).fetch = async (_url: string, _options: any) => ({
          ok: true,
          json: async () => ({ verified: false }),
          statusText: 'OK',
          headers: {
            get: (name: string) => (name === 'X-ZkId-Protocol-Version' ? 'zk-id/1.0-draft' : null),
          },
        });

        const client = new ZkIdClient({
          verificationEndpoint: 'http://localhost:3000/verify',
          walletConnector: mockWallet,
        });

        const result = await client.verifyNationality(840);

        expect(result).to.be.false;
      });
    });

    describe('fetchRevocationRootInfo()', () => {
      it('throws when revocationRootEndpoint is not configured', async () => {
        const client = new ZkIdClient({
          verificationEndpoint: 'http://localhost:3000/verify',
        });

        try {
          await client.fetchRevocationRootInfo();
          expect.fail('Should have thrown');
        } catch (error: any) {
          expect(error.message).to.include('revocationRootEndpoint');
        }
      });

      it('fetches root info from configured endpoint', async () => {
        const mockRoot = {
          root: '123',
          version: 2,
          updatedAt: new Date().toISOString(),
        };

        (global as any).fetch = async (url: string, options: any) => {
          expect(url).to.equal('http://localhost:3000/api/revocation/root');
          expect(options.method).to.equal('GET');
          return {
            ok: true,
            json: async () => mockRoot,
            statusText: 'OK',
            headers: {
              get: () => null,
            },
          };
        };

        const client = new ZkIdClient({
          verificationEndpoint: 'http://localhost:3000/verify',
          revocationRootEndpoint: 'http://localhost:3000/api/revocation/root',
        });

        const info = await client.fetchRevocationRootInfo();
        expect(info.root).to.equal('123');
        expect(info.version).to.equal(2);
      });

      it('returns extended fields (ttlSeconds, expiresAt, source)', async () => {
        const now = new Date().toISOString();
        const mockRoot = {
          root: '456',
          version: 3,
          updatedAt: now,
          ttlSeconds: 120,
          expiresAt: new Date(Date.parse(now) + 120_000).toISOString(),
          source: 'test-registry',
        };

        (global as any).fetch = async () => ({
          ok: true,
          json: async () => mockRoot,
          statusText: 'OK',
          headers: { get: () => null },
        });

        const client = new ZkIdClient({
          verificationEndpoint: 'http://localhost:3000/verify',
          revocationRootEndpoint: 'http://localhost:3000/api/revocation/root',
        });

        const info = await client.fetchRevocationRootInfo();
        expect(info.ttlSeconds).to.equal(120);
        expect(info.expiresAt).to.be.a('string');
        expect(info.source).to.equal('test-registry');
      });

      it('warns when root is stale and maxRevocationRootAgeMs is set', async () => {
        const staleDate = new Date(Date.now() - 600_000).toISOString(); // 10 min ago
        const mockRoot = {
          root: '789',
          version: 4,
          updatedAt: staleDate,
        };

        (global as any).fetch = async () => ({
          ok: true,
          json: async () => mockRoot,
          statusText: 'OK',
          headers: { get: () => null },
        });

        const warnings: string[] = [];
        const origWarn = console.warn;
        console.warn = (msg: string) => warnings.push(msg);

        const client = new ZkIdClient({
          verificationEndpoint: 'http://localhost:3000/verify',
          revocationRootEndpoint: 'http://localhost:3000/api/revocation/root',
          maxRevocationRootAgeMs: 60_000, // 1 min
        });

        const info = await client.fetchRevocationRootInfo();
        console.warn = origWarn;

        expect(info.root).to.equal('789');
        expect(warnings.length).to.be.greaterThan(0);
        expect(warnings[0]).to.include('stale');
      });

      it('does not warn when root is fresh', async () => {
        const freshDate = new Date().toISOString();
        const mockRoot = {
          root: '111',
          version: 5,
          updatedAt: freshDate,
        };

        (global as any).fetch = async () => ({
          ok: true,
          json: async () => mockRoot,
          statusText: 'OK',
          headers: { get: () => null },
        });

        const warnings: string[] = [];
        const origWarn = console.warn;
        console.warn = (msg: string) => warnings.push(msg);

        const client = new ZkIdClient({
          verificationEndpoint: 'http://localhost:3000/verify',
          revocationRootEndpoint: 'http://localhost:3000/api/revocation/root',
          maxRevocationRootAgeMs: 60_000,
        });

        await client.fetchRevocationRootInfo();
        console.warn = origWarn;

        expect(warnings.length).to.equal(0);
      });
    });

    describe('InMemoryWallet', () => {
      it('should report isAvailable() as true', async () => {
        const wallet = new InMemoryWallet({
          circuitPaths: {
            ageWasm: '/path/to/age.wasm',
            ageZkey: '/path/to/age.zkey',
          },
        });

        const available = await wallet.isAvailable();

        expect(available).to.be.true;
      });

      it('should store credential with addSignedCredential()', () => {
        const wallet = new InMemoryWallet({
          circuitPaths: {
            ageWasm: '/path/to/age.wasm',
            ageZkey: '/path/to/age.zkey',
          },
        });

        const credential = {
          id: 'test-cred-123',
          birthYear: 1990,
          nationality: 840,
          salt: 'abcdef',
          commitment: '12345',
          createdAt: new Date().toISOString(),
        };

        const signedCredential = {
          credential,
          issuer: 'TestIssuer',
          signature: 'fake-signature',
          issuedAt: new Date().toISOString(),
        };

        expect(() => wallet.addSignedCredential(signedCredential)).to.not.throw();
      });

      it('should throw clear error when requestProof() is called without credentials', async () => {
        const wallet = new InMemoryWallet({
          circuitPaths: {
            ageWasm: '/path/to/age.wasm',
            ageZkey: '/path/to/age.zkey',
          },
        });

        const request: ProofRequest = {
          claimType: 'age',
          minAge: 18,
          nonce: 'test-nonce',
          timestamp: new Date().toISOString(),
        };

        try {
          await wallet.requestProof(request);
          expect.fail('Should have thrown an error');
        } catch (error: any) {
          expect(error.message).to.include('No credentials stored');
        }
      });
    });
  });
});
