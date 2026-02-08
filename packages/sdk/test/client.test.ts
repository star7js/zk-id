import { expect } from 'chai';
import { ZkIdClient, WalletConnector, InMemoryWallet } from '../src/client';
import { ProofRequest, ProofResponse, SignedCredential } from '@zk-id/core';

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
        (global as any).fetch = async (url: string, options: any) => ({
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
        (global as any).fetch = async (url: string, options: any) => ({
          ok: true,
          json: async () => ({ verified: true }),
          statusText: 'OK',
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
        (global as any).fetch = async (url: string, options: any) => ({
          ok: true,
          json: async () => ({ verified: false }),
          statusText: 'OK',
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
          requestProof: async (req) => {
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
            };
          },
        };

        // Mock fetch
        (global as any).fetch = async (url: string, options: any) => ({
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
          }),
        };

        // Mock fetch
        (global as any).fetch = async (url: string, options: any) => ({
          ok: true,
          json: async () => ({ verified: true }),
          statusText: 'OK',
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
          }),
        };

        // Mock fetch
        (global as any).fetch = async (url: string, options: any) => ({
          ok: true,
          json: async () => ({ verified: false }),
          statusText: 'OK',
        });

        const client = new ZkIdClient({
          verificationEndpoint: 'http://localhost:3000/verify',
          walletConnector: mockWallet,
        });

        const result = await client.verifyNationality(840);

        expect(result).to.be.false;
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
