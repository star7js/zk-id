import { expect } from 'chai';
import { InMemoryNonceStore, SimpleRateLimiter, ZkIdServer, VerificationEvent } from '../src/server';
import { InMemoryRevocationStore } from '@zk-id/core';
import path from 'path';

describe('SDK Server Tests', () => {
  describe('InMemoryNonceStore', () => {
    let store: InMemoryNonceStore;

    beforeEach(() => {
      store = new InMemoryNonceStore();
    });

    it('should not have unused nonce', async () => {
      const nonce = 'test-nonce-123';
      const has = await store.has(nonce);
      expect(has).to.be.false;
    });

    it('should store and retrieve nonce', async () => {
      const nonce = 'test-nonce-456';

      await store.add(nonce);
      const has = await store.has(nonce);

      expect(has).to.be.true;
    });

    it('should handle multiple nonces', async () => {
      const nonce1 = 'nonce-1';
      const nonce2 = 'nonce-2';
      const nonce3 = 'nonce-3';

      await store.add(nonce1);
      await store.add(nonce2);

      expect(await store.has(nonce1)).to.be.true;
      expect(await store.has(nonce2)).to.be.true;
      expect(await store.has(nonce3)).to.be.false;
    });
  });

  describe('SimpleRateLimiter', () => {
    it('should allow requests within limit', async () => {
      const limiter = new SimpleRateLimiter(5, 60000);
      const identifier = 'user-123';

      for (let i = 0; i < 5; i++) {
        const allowed = await limiter.allowRequest(identifier);
        expect(allowed).to.be.true;
      }
    });

    it('should block requests exceeding limit', async () => {
      const limiter = new SimpleRateLimiter(3, 60000);
      const identifier = 'user-456';

      // First 3 should be allowed
      for (let i = 0; i < 3; i++) {
        const allowed = await limiter.allowRequest(identifier);
        expect(allowed).to.be.true;
      }

      // 4th should be blocked
      const blocked = await limiter.allowRequest(identifier);
      expect(blocked).to.be.false;
    });

    it('should track different identifiers independently', async () => {
      const limiter = new SimpleRateLimiter(2, 60000);

      await limiter.allowRequest('user-1');
      await limiter.allowRequest('user-1');

      await limiter.allowRequest('user-2');
      await limiter.allowRequest('user-2');

      // Both should be at limit
      expect(await limiter.allowRequest('user-1')).to.be.false;
      expect(await limiter.allowRequest('user-2')).to.be.false;
    });
  });

  describe('ZkIdServer', () => {
    const ageVerificationKeyPath = path.join(__dirname, '../../circuits/build/age-verify_verification_key.json');
    const nationalityVerificationKeyPath = path.join(__dirname, '../../circuits/build/nationality-verify_verification_key.json');

    describe('Construction', () => {
      it('should create successfully with valid verification key paths', () => {
        expect(() => {
          new ZkIdServer({
            verificationKeyPath: ageVerificationKeyPath,
            nationalityVerificationKeyPath: nationalityVerificationKeyPath,
          });
        }).to.not.throw();
      });
    });

    describe('Telemetry events', () => {
      it('should fire onVerification callback on verifyProof call', async () => {
        const server = new ZkIdServer({
          verificationKeyPath: ageVerificationKeyPath,
        });

        let eventReceived: VerificationEvent | null = null;
        server.onVerification((event) => {
          eventReceived = event;
        });

        // Submit an invalid proof (we just test the event emission)
        const mockProof = {
          credentialId: 'test-cred',
          claimType: 'age',
          proof: {
            proof: {
              pi_a: ['0', '0'],
              pi_b: [['0', '0'], ['0', '0']],
              pi_c: ['0', '0'],
              protocol: 'groth16',
              curve: 'bn128',
            },
            publicSignals: {
              currentYear: 2026,
              minAge: 18,
              credentialHash: '0',
            },
          },
          nonce: 'test-nonce',
        };

        await server.verifyProof(mockProof as any);

        expect(eventReceived).to.not.be.null;
      });

      it('should include timestamp, claimType, verified, verificationTimeMs in event', async () => {
        const server = new ZkIdServer({
          verificationKeyPath: ageVerificationKeyPath,
        });

        let eventReceived: VerificationEvent | null = null;
        server.onVerification((event) => {
          eventReceived = event;
        });

        const mockProof = {
          credentialId: 'test-cred',
          claimType: 'age',
          proof: {
            proof: {
              pi_a: ['0', '0'],
              pi_b: [['0', '0'], ['0', '0']],
              pi_c: ['0', '0'],
              protocol: 'groth16',
              curve: 'bn128',
            },
            publicSignals: {
              currentYear: 2026,
              minAge: 18,
              credentialHash: '0',
            },
          },
          nonce: 'test-nonce',
        };

        await server.verifyProof(mockProof as any);

        expect(eventReceived).to.not.be.null;
        expect(eventReceived!.timestamp).to.be.a('string');
        expect(eventReceived!.claimType).to.equal('age');
        expect(eventReceived!.verified).to.be.a('boolean');
        expect(eventReceived!.verificationTimeMs).to.be.a('number');
        expect(eventReceived!.verificationTimeMs).to.be.greaterThanOrEqual(0);
      });

      it('should include clientIdentifier when provided', async () => {
        const server = new ZkIdServer({
          verificationKeyPath: ageVerificationKeyPath,
        });

        let eventReceived: VerificationEvent | null = null;
        server.onVerification((event) => {
          eventReceived = event;
        });

        const mockProof = {
          credentialId: 'test-cred',
          claimType: 'age',
          proof: {
            proof: {
              pi_a: ['0', '0'],
              pi_b: [['0', '0'], ['0', '0']],
              pi_c: ['0', '0'],
              protocol: 'groth16',
              curve: 'bn128',
            },
            publicSignals: {
              currentYear: 2026,
              minAge: 18,
              credentialHash: '0',
            },
          },
          nonce: 'test-nonce',
        };

        await server.verifyProof(mockProof as any, 'client-123');

        expect(eventReceived).to.not.be.null;
        expect(eventReceived!.clientIdentifier).to.equal('client-123');
      });

      it('should include error when verification fails', async () => {
        const server = new ZkIdServer({
          verificationKeyPath: ageVerificationKeyPath,
        });

        let eventReceived: VerificationEvent | null = null;
        server.onVerification((event) => {
          eventReceived = event;
        });

        const mockProof = {
          credentialId: 'test-cred',
          claimType: 'age',
          proof: {
            proof: {
              pi_a: ['0', '0'],
              pi_b: [['0', '0'], ['0', '0']],
              pi_c: ['0', '0'],
              protocol: 'groth16',
              curve: 'bn128',
            },
            publicSignals: {
              currentYear: 2026,
              minAge: 18,
              credentialHash: '0',
            },
          },
          nonce: 'test-nonce',
        };

        await server.verifyProof(mockProof as any);

        expect(eventReceived).to.not.be.null;
        expect(eventReceived!.verified).to.be.false;
        expect(eventReceived!.error).to.be.a('string');
      });
    });

    describe('Revocation integration', () => {
      it('should return verified: false with revocation error when credential is revoked', async () => {
        const revocationStore = new InMemoryRevocationStore();
        await revocationStore.revoke('revoked-cred');

        const server = new ZkIdServer({
          verificationKeyPath: ageVerificationKeyPath,
          revocationStore,
        });

        const mockProof = {
          credentialId: 'revoked-cred',
          claimType: 'age',
          proof: {
            proof: {
              pi_a: ['0', '0'],
              pi_b: [['0', '0'], ['0', '0']],
              pi_c: ['0', '0'],
              protocol: 'groth16',
              curve: 'bn128',
            },
            publicSignals: {
              currentYear: 2026,
              minAge: 18,
              credentialHash: '0',
            },
          },
          nonce: 'test-nonce',
        };

        const result = await server.verifyProof(mockProof as any);

        expect(result.verified).to.be.false;
        expect(result.error).to.equal('Credential has been revoked');
      });

      it('should not block non-revoked credentials', async () => {
        const revocationStore = new InMemoryRevocationStore();
        await revocationStore.revoke('other-cred');

        const server = new ZkIdServer({
          verificationKeyPath: ageVerificationKeyPath,
          revocationStore,
        });

        const mockProof = {
          credentialId: 'valid-cred',
          claimType: 'age',
          proof: {
            proof: {
              pi_a: ['0', '0'],
              pi_b: [['0', '0'], ['0', '0']],
              pi_c: ['0', '0'],
              protocol: 'groth16',
              curve: 'bn128',
            },
            publicSignals: {
              currentYear: 2026,
              minAge: 18,
              credentialHash: '0',
            },
          },
          nonce: 'test-nonce',
        };

        const result = await server.verifyProof(mockProof as any);

        // Should fail for other reasons (invalid proof), but NOT revocation
        expect(result.error).to.not.equal('Credential has been revoked');
      });

      it('should fire telemetry event for revoked credentials', async () => {
        const revocationStore = new InMemoryRevocationStore();
        await revocationStore.revoke('revoked-cred');

        const server = new ZkIdServer({
          verificationKeyPath: ageVerificationKeyPath,
          revocationStore,
        });

        let eventReceived: VerificationEvent | null = null;
        server.onVerification((event) => {
          eventReceived = event;
        });

        const mockProof = {
          credentialId: 'revoked-cred',
          claimType: 'age',
          proof: {
            proof: {
              pi_a: ['0', '0'],
              pi_b: [['0', '0'], ['0', '0']],
              pi_c: ['0', '0'],
              protocol: 'groth16',
              curve: 'bn128',
            },
            publicSignals: {
              currentYear: 2026,
              minAge: 18,
              credentialHash: '0',
            },
          },
          nonce: 'test-nonce',
        };

        await server.verifyProof(mockProof as any);

        expect(eventReceived).to.not.be.null;
        expect(eventReceived!.verified).to.be.false;
        expect(eventReceived!.error).to.equal('Credential has been revoked');
      });
    });

    describe('Rate limiting integration', () => {
      it('should return verified: false with rate limit error when limit exceeded', async () => {
        const rateLimiter = new SimpleRateLimiter(2, 60000);
        const server = new ZkIdServer({
          verificationKeyPath: ageVerificationKeyPath,
          rateLimiter,
        });

        const mockProof = {
          credentialId: 'test-cred',
          claimType: 'age',
          proof: {
            proof: {
              pi_a: ['0', '0'],
              pi_b: [['0', '0'], ['0', '0']],
              pi_c: ['0', '0'],
              protocol: 'groth16',
              curve: 'bn128',
            },
            publicSignals: {
              currentYear: 2026,
              minAge: 18,
              credentialHash: '0',
            },
          },
          nonce: 'test-nonce',
        };

        // Use up the rate limit
        await server.verifyProof(mockProof as any, 'client-123');
        await server.verifyProof(mockProof as any, 'client-123');

        // Third request should be rate limited
        const result = await server.verifyProof(mockProof as any, 'client-123');

        expect(result.verified).to.be.false;
        expect(result.error).to.equal('Rate limit exceeded');
      });
    });

    describe('Nonce replay protection', () => {
      it('should return error on second submission with same nonce', async () => {
        const nonceStore = new InMemoryNonceStore();
        // Pre-populate the nonce store to simulate a used nonce
        await nonceStore.add('duplicate-nonce');

        const server = new ZkIdServer({
          verificationKeyPath: ageVerificationKeyPath,
          nonceStore,
        });

        const mockProof = {
          credentialId: 'test-cred',
          claimType: 'age',
          proof: {
            proof: {
              pi_a: ['0', '0'],
              pi_b: [['0', '0'], ['0', '0']],
              pi_c: ['0', '0'],
              protocol: 'groth16',
              curve: 'bn128',
            },
            publicSignals: {
              currentYear: 2026,
              minAge: 18,
              credentialHash: '0',
            },
          },
          nonce: 'duplicate-nonce',
        };

        // Submit with already-used nonce
        const result = await server.verifyProof(mockProof as any);

        expect(result.verified).to.be.false;
        expect(result.error).to.include('Nonce already used');
      });
    });

    describe('Unknown claim type', () => {
      it('should return error for unknown claim type', async () => {
        const server = new ZkIdServer({
          verificationKeyPath: ageVerificationKeyPath,
        });

        const mockProof = {
          credentialId: 'test-cred',
          claimType: 'unknown',
          proof: {
            proof: {
              pi_a: ['0', '0'],
              pi_b: [['0', '0'], ['0', '0']],
              pi_c: ['0', '0'],
              protocol: 'groth16',
              curve: 'bn128',
            },
            publicSignals: {
              currentYear: 2026,
              minAge: 18,
              credentialHash: '0',
            },
          },
          nonce: 'test-nonce',
        };

        const result = await server.verifyProof(mockProof as any);

        expect(result.verified).to.be.false;
        expect(result.error).to.equal('Unknown claim type');
      });
    });
  });
});
