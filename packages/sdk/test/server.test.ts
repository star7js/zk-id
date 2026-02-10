import { expect } from 'chai';
import path from 'path';
import { generateKeyPairSync, sign } from 'crypto';
import {
  ZkIdServer,
  IssuerRegistry,
  InMemoryIssuerRegistry,
  InMemoryNonceStore,
  validateProofResponsePayload,
  validateSignedProofRequestPayload,
} from '../src/server';
import {
  AgeProof,
  AgeProofRevocable,
  ProofResponse,
  SignedCredential,
  credentialSignaturePayload,
} from '@zk-id/core';

function makeAgeProof(
  credentialHash: string,
  minAge: number,
  nonce: string,
  requestTimestamp: number,
): AgeProof {
  return {
    proofType: 'age',
    proof: {
      pi_a: ['1', '2'],
      pi_b: [
        ['3', '4'],
        ['5', '6'],
      ],
      pi_c: ['7', '8'],
      protocol: 'groth16',
      curve: 'bn128',
    },
    publicSignals: {
      currentYear: new Date().getFullYear(),
      minAge,
      credentialHash,
      nonce,
      requestTimestamp,
    },
  };
}

function makeAgeProofRevocable(
  credentialHash: string,
  merkleRoot: string,
  minAge: number,
  nonce: string,
  requestTimestamp: number,
): AgeProofRevocable {
  return {
    proofType: 'age-revocable',
    proof: {
      pi_a: ['1', '2'],
      pi_b: [
        ['3', '4'],
        ['5', '6'],
      ],
      pi_c: ['7', '8'],
      protocol: 'groth16',
      curve: 'bn128',
    },
    publicSignals: {
      currentYear: new Date().getFullYear(),
      minAge,
      credentialHash,
      merkleRoot,
      nonce,
      requestTimestamp,
    },
  };
}

function makeSignedCredential(commitment: string, issuer = 'TestIssuer') {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const credential = {
    id: 'cred-1',
    birthYear: 1990,
    nationality: 840,
    salt: '00',
    commitment,
    createdAt: new Date().toISOString(),
  };

  const issuedAt = new Date().toISOString();
  const payload = credentialSignaturePayload(credential, issuer, issuedAt);
  const signature = sign(null, Buffer.from(payload), privateKey).toString('base64');

  const signedCredential: SignedCredential = {
    credential,
    issuer,
    signature,
    issuedAt,
  };

  return { signedCredential, publicKey };
}

function getVerificationKeyPath(): string {
  return path.resolve(__dirname, '../../circuits/build/age-verify_verification_key.json');
}

describe('ZkIdServer - protocol enforcement', () => {
  it('rejects when protocol version is missing in strict mode', async () => {
    const server = new ZkIdServer({
      verificationKeyPath: getVerificationKeyPath(),
      requireSignedCredentials: false,
      protocolVersionPolicy: 'strict',
      verboseErrors: true,
    });

    const proofResponse: ProofResponse = {
      credentialId: 'cred-1',
      claimType: 'age',
      proof: makeAgeProof('123', 18, 'nonce-1', Date.now()),
      nonce: 'nonce-1',
      requestTimestamp: new Date().toISOString(),
    } as ProofResponse;

    const result = await server.verifyProof(proofResponse);
    expect(result.verified).to.equal(false);
    expect(result.error).to.equal('Missing protocol version');
  });

  it('rejects when protocol version is incompatible in strict mode', async () => {
    const server = new ZkIdServer({
      verificationKeyPath: getVerificationKeyPath(),
      requireSignedCredentials: false,
      protocolVersionPolicy: 'strict',
      verboseErrors: true,
    });

    const proofResponse: ProofResponse = {
      credentialId: 'cred-1',
      claimType: 'age',
      proof: makeAgeProof('123', 18, 'nonce-1', Date.now()),
      nonce: 'nonce-1',
      requestTimestamp: new Date().toISOString(),
    } as ProofResponse;

    const result = await server.verifyProof(proofResponse, undefined, 'zk-id/2.0');
    expect(result.verified).to.equal(false);
    expect(result.error).to.equal('Incompatible protocol version');
  });

  it('warn mode allows incompatible protocol versions to continue', async () => {
    const server = new ZkIdServer({
      verificationKeyPath: getVerificationKeyPath(),
      requireSignedCredentials: false,
      protocolVersionPolicy: 'warn',
    });

    const proofResponse: ProofResponse = {
      credentialId: 'cred-1',
      claimType: 'age',
      proof: makeAgeProof('123', 18, 'nonce-1', Date.now()),
      nonce: 'nonce-1',
      requestTimestamp: new Date().toISOString(),
    } as ProofResponse;

    const result = await server.verifyProof(proofResponse, undefined, 'zk-id/2.0');
    expect(result.verified).to.equal(false);
    expect(result.error).to.not.equal('Incompatible protocol version');
    expect(result.error).to.not.equal('Missing protocol version');
  });

  it('rejects signed proof when protocol version is incompatible in strict mode', async () => {
    const server = new ZkIdServer({
      verificationKeyPath: getVerificationKeyPath(),
      requireSignedCredentials: false,
      protocolVersionPolicy: 'strict',
      verboseErrors: true,
      validatePayloads: false, // Disable to test protocol version check
    });

    const signedRequest = {
      claimType: 'age',
      issuer: 'TestIssuer',
      nonce: 'nonce-1',
      requestTimestamp: new Date().toISOString(),
      proof: {} as any,
    };

    const result = await server.verifySignedProof(signedRequest as any, undefined, 'zk-id/2.0');
    expect(result.verified).to.equal(false);
    expect(result.error).to.equal('Incompatible protocol version');
  });
});

describe('ZkIdServer - signature and policy enforcement', () => {
  it('rejects proof when signed credential is missing', async () => {
    const server = new ZkIdServer({
      verificationKeyPath: getVerificationKeyPath(),
      issuerPublicKeys: {},
      verboseErrors: true,
      validatePayloads: false, // Disable to test signed credential check
    });

    const proofResponse = {
      credentialId: 'cred-1',
      claimType: 'age',
      proof: makeAgeProof('123', 18, 'nonce-1', Date.now()),
      nonce: 'nonce-1',
      requestTimestamp: new Date().toISOString(),
    } as ProofResponse;

    const result = await server.verifyProof(proofResponse);
    expect(result.verified).to.equal(false);
    expect(result.error).to.equal('Signed credential required');
  });

  it('rejects proof when credential signature is invalid', async () => {
    const { signedCredential } = makeSignedCredential('123');
    const { publicKey } = generateKeyPairSync('ed25519');

    const server = new ZkIdServer({
      verificationKeyPath: getVerificationKeyPath(),
      issuerPublicKeys: { TestIssuer: publicKey },
      verboseErrors: true,
    });

    const proofResponse: ProofResponse = {
      credentialId: signedCredential.credential.id,
      claimType: 'age',
      proof: makeAgeProof('123', 18, 'nonce-2', Date.now()),
      signedCredential,
      nonce: 'nonce-2',
      requestTimestamp: new Date().toISOString(),
    };

    const result = await server.verifyProof(proofResponse);
    expect(result.verified).to.equal(false);
    expect(result.error).to.equal('Invalid credential signature');
  });

  it('rejects proof when credential commitment does not match proof', async () => {
    const { signedCredential, publicKey } = makeSignedCredential('999');

    const server = new ZkIdServer({
      verificationKeyPath: getVerificationKeyPath(),
      issuerPublicKeys: { TestIssuer: publicKey },
      verboseErrors: true,
    });

    const proofResponse: ProofResponse = {
      credentialId: signedCredential.credential.id,
      claimType: 'age',
      proof: makeAgeProof('123', 18, 'nonce-3', Date.now()),
      signedCredential,
      nonce: 'nonce-3',
      requestTimestamp: new Date().toISOString(),
    };

    const result = await server.verifyProof(proofResponse);
    expect(result.verified).to.equal(false);
    expect(result.error).to.equal('Credential commitment mismatch');
  });

  it('enforces required minimum age policy', async () => {
    const { signedCredential, publicKey } = makeSignedCredential('123');

    const server = new ZkIdServer({
      verificationKeyPath: getVerificationKeyPath(),
      issuerPublicKeys: { TestIssuer: publicKey },
      requiredMinAge: 21,
      verboseErrors: true,
    });

    const proofResponse: ProofResponse = {
      credentialId: signedCredential.credential.id,
      claimType: 'age',
      proof: makeAgeProof('123', 18, 'nonce-4', Date.now()),
      signedCredential,
      nonce: 'nonce-4',
      requestTimestamp: new Date().toISOString(),
    };

    const result = await server.verifyProof(proofResponse);
    expect(result.verified).to.equal(false);
    expect(result.error).to.equal('Proof does not satisfy required minimum age');
  });

  it('enforces required nationality policy', async () => {
    const { signedCredential, publicKey } = makeSignedCredential('123');

    const server = new ZkIdServer({
      verificationKeyPath: getVerificationKeyPath(),
      issuerPublicKeys: { TestIssuer: publicKey },
      requiredPolicy: { nationality: 840 },
      verboseErrors: true,
    });

    const proofResponse: ProofResponse = {
      credentialId: signedCredential.credential.id,
      claimType: 'nationality',
      proof: {
        proofType: 'nationality' as const,
        proof: {
          pi_a: ['1', '2'],
          pi_b: [
            ['3', '4'],
            ['5', '6'],
          ],
          pi_c: ['7', '8'],
          protocol: 'groth16',
          curve: 'bn128',
        },
        publicSignals: {
          targetNationality: 826,
          credentialHash: '123',
          nonce: 'nonce-nat',
          requestTimestamp: Date.now(),
        },
      },
      signedCredential,
      nonce: 'nonce-nat',
      requestTimestamp: new Date().toISOString(),
    };

    const result = await server.verifyProof(proofResponse);
    expect(result.verified).to.equal(false);
    expect(result.error).to.equal('Proof does not satisfy required nationality');
  });

  it('rejects proof when nonce does not match request nonce', async () => {
    const { signedCredential, publicKey } = makeSignedCredential('123');

    const server = new ZkIdServer({
      verificationKeyPath: getVerificationKeyPath(),
      issuerPublicKeys: { TestIssuer: publicKey },
      verboseErrors: true,
    });

    const proofResponse: ProofResponse = {
      credentialId: signedCredential.credential.id,
      claimType: 'age',
      proof: makeAgeProof('123', 18, 'proof-nonce', Date.now()),
      signedCredential,
      nonce: 'request-nonce',
      requestTimestamp: new Date().toISOString(),
    };

    const result = await server.verifyProof(proofResponse);
    expect(result.verified).to.equal(false);
    expect(result.error).to.equal('Proof nonce does not match request nonce');
  });

  it('rejects proof when issuer key is expired', async () => {
    const { signedCredential, publicKey } = makeSignedCredential('123');

    const registry: IssuerRegistry = {
      async getIssuer() {
        return {
          issuer: 'TestIssuer',
          publicKey,
          status: 'active',
          validTo: new Date(Date.now() - 1000).toISOString(),
        };
      },
    };

    const server = new ZkIdServer({
      verificationKeyPath: getVerificationKeyPath(),
      issuerRegistry: registry,
      verboseErrors: true,
    });

    const proofResponse: ProofResponse = {
      credentialId: signedCredential.credential.id,
      claimType: 'age',
      proof: makeAgeProof('123', 18, 'nonce-5', Date.now()),
      signedCredential,
      nonce: 'nonce-5',
      requestTimestamp: new Date().toISOString(),
    };

    const result = await server.verifyProof(proofResponse);
    expect(result.verified).to.equal(false);
    expect(result.error).to.equal('Issuer key expired');
  });

  it('rejects proof when issuer is suspended', async () => {
    const { signedCredential, publicKey } = makeSignedCredential('123');

    const registry: IssuerRegistry = {
      async getIssuer() {
        return {
          issuer: 'TestIssuer',
          publicKey,
          status: 'suspended',
        };
      },
    };

    const server = new ZkIdServer({
      verificationKeyPath: getVerificationKeyPath(),
      issuerRegistry: registry,
      verboseErrors: true,
    });

    const proofResponse: ProofResponse = {
      credentialId: signedCredential.credential.id,
      claimType: 'age',
      proof: makeAgeProof('123', 18, 'nonce-6', Date.now()),
      signedCredential,
      nonce: 'nonce-6',
      requestTimestamp: new Date().toISOString(),
    };

    const result = await server.verifyProof(proofResponse);
    expect(result.verified).to.equal(false);
    expect(result.error).to.equal('Issuer is not active');
  });

  it('rejects proof when request timestamp is too old', async () => {
    const { signedCredential, publicKey } = makeSignedCredential('123');

    const server = new ZkIdServer({
      verificationKeyPath: getVerificationKeyPath(),
      issuerPublicKeys: { TestIssuer: publicKey },
      maxRequestAgeMs: 1000,
      verboseErrors: true,
    });

    const oldMs = Date.now() - 10_000;
    const proofResponse: ProofResponse = {
      credentialId: signedCredential.credential.id,
      claimType: 'age',
      proof: makeAgeProof('123', 18, 'nonce-7', oldMs),
      signedCredential,
      nonce: 'nonce-7',
      requestTimestamp: new Date(oldMs).toISOString(),
    };

    const result = await server.verifyProof(proofResponse);
    expect(result.verified).to.equal(false);
    expect(result.error).to.equal('Request timestamp is too old');
  });

  it('rejects proof when request timestamp is in the future (beyond allowed skew)', async () => {
    const { signedCredential, publicKey } = makeSignedCredential('123');

    const server = new ZkIdServer({
      verificationKeyPath: getVerificationKeyPath(),
      issuerPublicKeys: { TestIssuer: publicKey },
      maxFutureSkewMs: 1000, // Allow 1 second of clock skew
      verboseErrors: true,
    });

    // Create a timestamp 10 seconds in the future (beyond the 1 second skew)
    const futureMs = Date.now() + 10_000;
    const proofResponse: ProofResponse = {
      credentialId: signedCredential.credential.id,
      claimType: 'age',
      proof: makeAgeProof('123', 18, 'nonce-8', futureMs),
      signedCredential,
      nonce: 'nonce-8',
      requestTimestamp: new Date(futureMs).toISOString(),
    };

    const result = await server.verifyProof(proofResponse);
    expect(result.verified).to.equal(false);
    expect(result.error).to.equal('Request timestamp is too far in the future');
  });

  it('accepts proof with small future timestamp within allowed skew', async () => {
    const { signedCredential, publicKey } = makeSignedCredential('123');

    const server = new ZkIdServer({
      verificationKeyPath: getVerificationKeyPath(),
      issuerPublicKeys: { TestIssuer: publicKey },
      maxFutureSkewMs: 5000, // Allow 5 seconds of clock skew
      maxRequestAgeMs: 60000,
    });

    // Create a timestamp 2 seconds in the future (within the 5 second skew)
    const futureMs = Date.now() + 2000;
    const proofResponse: ProofResponse = {
      credentialId: signedCredential.credential.id,
      claimType: 'age',
      proof: makeAgeProof('123', 18, 'nonce-9', futureMs),
      signedCredential,
      nonce: 'nonce-9',
      requestTimestamp: new Date(futureMs).toISOString(),
    };

    const result = await server.verifyProof(proofResponse);
    // The proof will fail verification (it's a fake proof), but it should NOT
    // fail due to timestamp validation. This tests that small future timestamps
    // within the allowed skew are accepted by the timestamp validator.
    expect(result.verified).to.equal(false);
    expect(result.error).to.not.include('timestamp');
    expect(result.error).to.not.include('future');
  });
});

describe('ZkIdServer - revocation root info', () => {
  it('returns root info when valid credential tree is configured', async () => {
    const tree = {
      add: async () => undefined,
      remove: async () => undefined,
      contains: async () => true,
      getRoot: async () => '123',
      getRootInfo: async () => ({
        root: '123',
        version: 1,
        updatedAt: new Date().toISOString(),
      }),
      getWitness: async () => null,
      size: async () => 1,
    };

    const server = new ZkIdServer({
      verificationKeys: { age: {} as any },
      requireSignedCredentials: false,
      validCredentialTree: tree as any,
    });

    const info = await server.getRevocationRootInfo();
    expect(info.root).to.be.a('string');
    expect(info.version).to.equal(1);
    expect(info.updatedAt).to.be.a('string');
  });

  it('includes ttlSeconds and expiresAt with default TTL', async () => {
    const now = new Date().toISOString();
    const tree = {
      add: async () => undefined,
      remove: async () => undefined,
      contains: async () => true,
      getRoot: async () => '456',
      getRootInfo: async () => ({
        root: '456',
        version: 3,
        updatedAt: now,
      }),
      getWitness: async () => null,
      size: async () => 2,
    };

    const server = new ZkIdServer({
      verificationKeys: { age: {} as any },
      requireSignedCredentials: false,
      validCredentialTree: tree as any,
    });

    const info = await server.getRevocationRootInfo();
    expect(info.ttlSeconds).to.equal(300);
    expect(info.expiresAt).to.be.a('string');
    const expiresMs = Date.parse(info.expiresAt!);
    const updatedMs = Date.parse(now);
    expect(expiresMs - updatedMs).to.equal(300 * 1000);
  });

  it('uses custom TTL and source from config', async () => {
    const now = new Date().toISOString();
    const tree = {
      add: async () => undefined,
      remove: async () => undefined,
      contains: async () => true,
      getRoot: async () => '789',
      getRootInfo: async () => ({
        root: '789',
        version: 5,
        updatedAt: now,
      }),
      getWitness: async () => null,
      size: async () => 1,
    };

    const server = new ZkIdServer({
      verificationKeys: { age: {} as any },
      requireSignedCredentials: false,
      validCredentialTree: tree as any,
      revocationRootTtlSeconds: 60,
      revocationRootSource: 'test-issuer',
    });

    const info = await server.getRevocationRootInfo();
    expect(info.ttlSeconds).to.equal(60);
    expect(info.source).to.equal('test-issuer');
    const expiresMs = Date.parse(info.expiresAt!);
    const updatedMs = Date.parse(now);
    expect(expiresMs - updatedMs).to.equal(60 * 1000);
  });

  it('populates TTL fields even when tree lacks getRootInfo', async () => {
    const tree = {
      add: async () => undefined,
      remove: async () => undefined,
      contains: async () => true,
      getRoot: async () => '111',
      getWitness: async () => null,
      size: async () => 0,
    };

    const server = new ZkIdServer({
      verificationKeys: { age: {} as any },
      requireSignedCredentials: false,
      validCredentialTree: tree as any,
    });

    const info = await server.getRevocationRootInfo();
    expect(info.root).to.equal('111');
    expect(info.version).to.equal(0);
    expect(info.ttlSeconds).to.equal(300);
    expect(info.expiresAt).to.be.a('string');
  });
});

describe('ZkIdServer - revocation root staleness', () => {
  it('rejects revocable proof when root is stale', async () => {
    const staleDate = new Date(Date.now() - 120_000).toISOString(); // 2 min ago
    const tree = {
      add: async () => undefined,
      remove: async () => undefined,
      contains: async () => false,
      getRoot: async () => '0',
      getRootInfo: async () => ({
        root: '0',
        version: 1,
        updatedAt: staleDate,
      }),
      getWitness: async () => null,
      size: async () => 0,
    };

    const server = new ZkIdServer({
      requireSignedCredentials: false,
      verificationKeys: {
        age: {} as any,
        ageRevocable: {} as any,
      },
      validCredentialTree: tree as any,
      maxRevocationRootAgeMs: 60_000, // 1 min max
      verboseErrors: true,
    });

    const timestamp = Date.now();
    const proofResponse: ProofResponse = {
      credentialId: 'cred-1',
      claimType: 'age-revocable',
      proof: makeAgeProofRevocable('123', '0', 18, 'nonce-stale', timestamp),
      nonce: 'nonce-stale',
      requestTimestamp: new Date(timestamp).toISOString(),
    } as ProofResponse;

    const result = await server.verifyProof(proofResponse);
    expect(result.verified).to.equal(false);
    expect(result.error).to.equal('Revocation root is stale');
  });

  it('allows revocable proof when root is fresh', async () => {
    const freshDate = new Date().toISOString();
    const tree = {
      add: async () => undefined,
      remove: async () => undefined,
      contains: async () => false,
      getRoot: async () => '0',
      getRootInfo: async () => ({
        root: '0',
        version: 1,
        updatedAt: freshDate,
      }),
      getWitness: async () => null,
      size: async () => 0,
    };

    const server = new ZkIdServer({
      requireSignedCredentials: false,
      verificationKeys: {
        age: {} as any,
        ageRevocable: {} as any,
      },
      validCredentialTree: tree as any,
      maxRevocationRootAgeMs: 60_000, // 1 min max
    });

    const timestamp = Date.now();
    const proofResponse: ProofResponse = {
      credentialId: 'cred-1',
      claimType: 'age-revocable',
      proof: makeAgeProofRevocable('123', '0', 18, 'nonce-fresh', timestamp),
      nonce: 'nonce-fresh',
      requestTimestamp: new Date(timestamp).toISOString(),
    } as ProofResponse;

    const result = await server.verifyProof(proofResponse);
    // Should get past staleness check — will fail at proof verification (expected)
    expect(result.error).to.not.equal('Revocation root is stale');
  });
});

describe('InMemoryIssuerRegistry', () => {
  function makeKeyPair() {
    return generateKeyPairSync('ed25519');
  }

  describe('metadata fields', () => {
    it('stores and returns jurisdiction, policyUrl, auditUrl', async () => {
      const { publicKey } = makeKeyPair();
      const registry = new InMemoryIssuerRegistry([
        {
          issuer: 'gov-issuer',
          publicKey,
          status: 'active',
          jurisdiction: 'US',
          policyUrl: 'https://issuer.example.gov/policy',
          auditUrl: 'https://audit.example.com/report/123',
        },
      ]);

      const record = await registry.getIssuer('gov-issuer');
      expect(record).to.not.be.null;
      expect(record!.jurisdiction).to.equal('US');
      expect(record!.policyUrl).to.equal('https://issuer.example.gov/policy');
      expect(record!.auditUrl).to.equal('https://audit.example.com/report/123');
    });

    it('returns null for unknown issuer', async () => {
      const registry = new InMemoryIssuerRegistry();
      const record = await registry.getIssuer('unknown');
      expect(record).to.be.null;
    });
  });

  describe('key rotation', () => {
    it('returns the active record within its validity window', async () => {
      const { publicKey: oldKey } = makeKeyPair();
      const { publicKey: newKey } = makeKeyPair();
      const now = new Date();
      const past = new Date(now.getTime() - 86400_000); // 1 day ago
      const future = new Date(now.getTime() + 86400_000); // 1 day from now

      const registry = new InMemoryIssuerRegistry([
        {
          issuer: 'rotating',
          publicKey: oldKey,
          status: 'active',
          validFrom: past.toISOString(),
          validTo: new Date(now.getTime() - 1000).toISOString(), // expired 1s ago
        },
        {
          issuer: 'rotating',
          publicKey: newKey,
          status: 'active',
          validFrom: now.toISOString(),
          validTo: future.toISOString(),
        },
      ]);

      const record = await registry.getIssuer('rotating');
      expect(record).to.not.be.null;
      // Should return the new key (currently valid)
      expect(record!.publicKey).to.equal(newKey);
    });

    it('supports overlapping validity windows during rotation', async () => {
      const { publicKey: oldKey } = makeKeyPair();
      const { publicKey: newKey } = makeKeyPair();
      const now = new Date();
      const past = new Date(now.getTime() - 86400_000);
      const overlapEnd = new Date(now.getTime() + 3600_000); // overlap for 1 hour
      const future = new Date(now.getTime() + 86400_000);

      const registry = new InMemoryIssuerRegistry([
        {
          issuer: 'overlap',
          publicKey: oldKey,
          status: 'active',
          validFrom: past.toISOString(),
          validTo: overlapEnd.toISOString(),
        },
        {
          issuer: 'overlap',
          publicKey: newKey,
          status: 'active',
          validFrom: now.toISOString(),
          validTo: future.toISOString(),
        },
      ]);

      // Both are valid; getIssuer returns the first match (old key still valid)
      const record = await registry.getIssuer('overlap');
      expect(record).to.not.be.null;
      expect(record!.publicKey).to.equal(oldKey);
    });

    it('upsert adds a new record for rotation', async () => {
      const { publicKey: oldKey } = makeKeyPair();
      const { publicKey: newKey } = makeKeyPair();

      const registry = new InMemoryIssuerRegistry([
        {
          issuer: 'upsert-test',
          publicKey: oldKey,
          status: 'active',
          validFrom: '2026-01-01T00:00:00Z',
          validTo: '2026-06-01T00:00:00Z',
        },
      ]);

      registry.upsert({
        issuer: 'upsert-test',
        publicKey: newKey,
        status: 'active',
        validFrom: '2026-03-01T00:00:00Z',
        validTo: '2026-12-01T00:00:00Z',
      });

      const records = await registry.listRecords('upsert-test');
      expect(records).to.have.length(2);
    });

    it('listRecords returns all records for an issuer', async () => {
      const { publicKey: key1 } = makeKeyPair();
      const { publicKey: key2 } = makeKeyPair();

      const registry = new InMemoryIssuerRegistry([
        { issuer: 'multi', publicKey: key1, status: 'active', validFrom: '2026-01-01T00:00:00Z' },
        { issuer: 'multi', publicKey: key2, status: 'active', validFrom: '2026-06-01T00:00:00Z' },
      ]);

      const records = await registry.listRecords('multi');
      expect(records).to.have.length(2);
    });

    it('listRecords returns empty array for unknown issuer', async () => {
      const registry = new InMemoryIssuerRegistry();
      const records = await registry.listRecords('nope');
      expect(records).to.deep.equal([]);
    });
  });

  describe('suspension and deactivation', () => {
    it('suspend marks all records as suspended', async () => {
      const { publicKey: key1 } = makeKeyPair();
      const { publicKey: key2 } = makeKeyPair();

      const registry = new InMemoryIssuerRegistry([
        { issuer: 'sus-test', publicKey: key1, status: 'active' },
        { issuer: 'sus-test', publicKey: key2, status: 'active' },
      ]);

      registry.suspend('sus-test');

      const records = await registry.listRecords('sus-test');
      expect(records.every((r) => r.status === 'suspended')).to.be.true;

      // getIssuer should return first record (suspended) since no active match
      const record = await registry.getIssuer('sus-test');
      expect(record!.status).to.equal('suspended');
    });

    it('reactivate restores suspended records to active', async () => {
      const { publicKey } = makeKeyPair();
      const registry = new InMemoryIssuerRegistry([
        { issuer: 'react-test', publicKey, status: 'active' },
      ]);

      registry.suspend('react-test');
      expect((await registry.getIssuer('react-test'))!.status).to.equal('suspended');

      registry.reactivate('react-test');
      expect((await registry.getIssuer('react-test'))!.status).to.equal('active');
    });

    it('deactivate permanently revokes all records', async () => {
      const { publicKey } = makeKeyPair();
      const registry = new InMemoryIssuerRegistry([
        { issuer: 'deact-test', publicKey, status: 'active' },
      ]);

      registry.deactivate('deact-test');

      const record = await registry.getIssuer('deact-test');
      expect(record!.status).to.equal('revoked');
    });

    it('suspended issuer is rejected during verification', async () => {
      const { publicKey, privateKey } = makeKeyPair();
      const registry = new InMemoryIssuerRegistry([
        { issuer: 'SuspendedIssuer', publicKey, status: 'suspended' },
      ]);

      const server = new ZkIdServer({
        verificationKeys: { age: {} as any },
        requireSignedCredentials: true,
        issuerRegistry: registry,
        verboseErrors: true,
      });

      const commitment = '12345';
      const signature = sign(null, Buffer.from(commitment), privateKey).toString('base64');
      const timestamp = Date.now();

      const proofResponse: ProofResponse = {
        credentialId: 'cred-1',
        claimType: 'age',
        proof: makeAgeProof(commitment, 18, 'nonce-sus', timestamp),
        signedCredential: {
          credential: {
            id: 'cred-1',
            birthYear: 1990,
            nationality: 840,
            salt: '00',
            commitment,
            createdAt: new Date().toISOString(),
          },
          issuer: 'SuspendedIssuer',
          signature,
          issuedAt: new Date().toISOString(),
        },
        nonce: 'nonce-sus',
        requestTimestamp: new Date(timestamp).toISOString(),
      } as ProofResponse;

      const result = await server.verifyProof(proofResponse);
      expect(result.verified).to.equal(false);
      expect(result.error).to.equal('Issuer is not active');
    });
  });
});

// ---------------------------------------------------------------------------
// Payload validation helpers (T-007)
// ---------------------------------------------------------------------------

describe('validateProofResponsePayload', () => {
  it('returns empty array for valid payload', () => {
    const valid = {
      credentialId: 'cred-1',
      claimType: 'age',
      proof: {
        proof: { pi_a: ['1'], pi_b: [['2']], pi_c: ['3'], protocol: 'groth16', curve: 'bn128' },
        publicSignals: {
          currentYear: 2026,
          minAge: 18,
          credentialHash: 'h',
          nonce: 'n',
          requestTimestamp: 123,
        },
      },
      signedCredential: {
        credential: {},
        issuer: 'test',
        signature: 'sig',
        issuedAt: '2026-01-01T00:00:00Z',
      },
      nonce: 'nonce-1',
      requestTimestamp: '2026-01-01T00:00:00Z',
    };
    const errors = validateProofResponsePayload(valid);
    expect(errors).to.have.length(0);
  });

  it('rejects null body', () => {
    const errors = validateProofResponsePayload(null);
    expect(errors).to.have.length(1);
    expect(errors[0].field).to.equal('(root)');
  });

  it('rejects invalid claimType', () => {
    const errors = validateProofResponsePayload({
      claimType: 'invalid',
      nonce: 'n',
      requestTimestamp: '2026-01-01T00:00:00Z',
      proof: { proof: {}, publicSignals: {} },
      signedCredential: {},
    });
    expect(errors.some((e: { field: string }) => e.field === 'claimType')).to.equal(true);
  });

  it('rejects empty nonce', () => {
    const errors = validateProofResponsePayload({
      claimType: 'age',
      nonce: '',
      requestTimestamp: '2026-01-01T00:00:00Z',
      proof: { proof: {}, publicSignals: {} },
      signedCredential: {},
    });
    expect(errors.some((e: { field: string }) => e.field === 'nonce')).to.equal(true);
  });

  it('rejects missing proof object', () => {
    const errors = validateProofResponsePayload({
      claimType: 'age',
      nonce: 'n',
      requestTimestamp: '2026-01-01T00:00:00Z',
      signedCredential: {},
    });
    expect(errors.some((e: { field: string }) => e.field === 'proof')).to.equal(true);
  });

  it('rejects missing signedCredential', () => {
    const errors = validateProofResponsePayload({
      claimType: 'age',
      nonce: 'n',
      requestTimestamp: '2026-01-01T00:00:00Z',
      proof: { proof: {}, publicSignals: {} },
    });
    expect(errors.some((e: { field: string }) => e.field === 'signedCredential')).to.equal(true);
  });

  it('allows missing signedCredential when requireSignedCredential is false', () => {
    const errors = validateProofResponsePayload(
      {
        claimType: 'age',
        nonce: 'n',
        requestTimestamp: '2026-01-01T00:00:00Z',
        proof: { proof: {}, publicSignals: {} },
      },
      false,
    );
    expect(errors.some((e: { field: string }) => e.field === 'signedCredential')).to.equal(false);
  });

  it('rejects missing nested proof.proof', () => {
    const errors = validateProofResponsePayload({
      claimType: 'age',
      nonce: 'n',
      requestTimestamp: '2026-01-01T00:00:00Z',
      proof: { publicSignals: {} },
      signedCredential: {},
    });
    expect(errors.some((e: { field: string }) => e.field === 'proof.proof')).to.equal(true);
  });
});

describe('validateSignedProofRequestPayload', () => {
  it('returns empty array for valid payload', () => {
    const valid = {
      claimType: 'age',
      issuer: 'test-issuer',
      nonce: 'nonce-1',
      requestTimestamp: '2026-01-01T00:00:00Z',
      proof: {
        proof: { pi_a: ['1'], pi_b: [['2']], pi_c: ['3'], protocol: 'groth16', curve: 'bn128' },
        publicSignals: {
          currentYear: 2026,
          minAge: 18,
          credentialHash: 'h',
          nonce: 'n',
          requestTimestamp: 123,
          issuerPublicKey: ['pk'],
        },
      },
    };
    const errors = validateSignedProofRequestPayload(valid);
    expect(errors).to.have.length(0);
  });

  it('rejects invalid claimType', () => {
    const errors = validateSignedProofRequestPayload({
      claimType: 'age-revocable',
      issuer: 'i',
      nonce: 'n',
      requestTimestamp: 'ts',
      proof: { proof: {}, publicSignals: {} },
    });
    expect(errors.some((e: { field: string }) => e.field === 'claimType')).to.equal(true);
  });

  it('rejects missing issuer', () => {
    const errors = validateSignedProofRequestPayload({
      claimType: 'age',
      nonce: 'n',
      requestTimestamp: 'ts',
      proof: { proof: {}, publicSignals: {} },
    });
    expect(errors.some((e: { field: string }) => e.field === 'issuer')).to.equal(true);
  });

  it('rejects null body', () => {
    const errors = validateSignedProofRequestPayload(null);
    expect(errors).to.have.length(1);
  });
});

describe('ZkIdServer - validatePayloads integration', () => {
  it('rejects invalid payload when validatePayloads is true', async () => {
    const server = new ZkIdServer({
      verificationKeys: { age: {} as any },
      validatePayloads: true,
      verboseErrors: true,
    });

    const result = await server.verifyProof({} as any);
    expect(result.verified).to.equal(false);
    expect(result.error).to.match(/Invalid payload/);
  });

  it('does not validate payload when validatePayloads is false', async () => {
    const server = new ZkIdServer({
      verificationKeys: { age: {} as any },
      validatePayloads: false,
      requireSignedCredentials: false,
    });

    // This will fail at the proof verification level, not at payload validation
    const proofResponse = makeValidProofResponse();
    const result = await server.verifyProof(proofResponse);
    // Should NOT contain "Invalid payload" - it should fail deeper in the verification pipeline
    if (result.error) {
      expect(result.error).to.not.match(/Invalid payload/);
    }
  });
});

function makeValidProofResponse(): ProofResponse {
  return {
    credentialId: 'cred-1',
    claimType: 'age',
    proof: makeAgeProof('hash-1', 18, 'nonce-vp', Date.now()),
    signedCredential: {
      credential: {
        id: 'cred-1',
        birthYear: 2000,
        nationality: 840,
        salt: 'salt',
        commitment: 'hash-1',
        createdAt: new Date().toISOString(),
      },
      issuer: 'test-issuer',
      signature: 'sig',
      issuedAt: new Date().toISOString(),
    },
    nonce: 'nonce-vp',
    requestTimestamp: new Date().toISOString(),
  };
}

// ---------------------------------------------------------------------------
// sanitizeError tests (Fix 4a)
// ---------------------------------------------------------------------------

describe('ZkIdServer - sanitizeError', () => {
  it('returns generic error in non-verbose mode for signature errors', async () => {
    const server = new ZkIdServer({
      verificationKeys: { age: {} as any },
      verboseErrors: false,
      requireSignedCredentials: false,
    });

    const timestamp = Date.now();
    const proofResponse: ProofResponse = {
      credentialId: 'cred-1',
      claimType: 'age',
      proof: makeAgeProof('hash-1', 18, 'nonce-sig', timestamp),
      nonce: 'nonce-sig',
      requestTimestamp: new Date(timestamp).toISOString(),
    } as ProofResponse;

    const result = await server.verifyProof(proofResponse);
    expect(result.verified).to.equal(false);
    expect(result.error).to.equal('Verification failed');
  });

  it('returns generic error in non-verbose mode for timestamp errors', async () => {
    const server = new ZkIdServer({
      verificationKeys: { age: {} as any },
      verboseErrors: false,
      requireSignedCredentials: false,
      maxRequestAgeMs: 1000,
    });

    const timestamp = Date.now() - 5000; // 5 seconds ago (stale)
    const proofResponse: ProofResponse = {
      credentialId: 'cred-1',
      claimType: 'age',
      proof: makeAgeProof('hash-1', 18, 'nonce-ts', timestamp),
      nonce: 'nonce-ts',
      requestTimestamp: new Date(timestamp).toISOString(),
    } as ProofResponse;

    const result = await server.verifyProof(proofResponse);
    expect(result.verified).to.equal(false);
    expect(result.error).to.equal('Request expired or invalid');
  });

  it('returns generic error in non-verbose mode for nonce errors', async () => {
    const server = new ZkIdServer({
      verificationKeys: { age: {} as any },
      verboseErrors: false,
      requireSignedCredentials: false,
    });

    const timestamp = Date.now();
    const proofResponse: ProofResponse = {
      credentialId: 'cred-1',
      claimType: 'age',
      proof: makeAgeProof('hash-1', 18, 'wrong-nonce', timestamp),
      nonce: 'different-nonce',
      requestTimestamp: new Date(timestamp).toISOString(),
    } as ProofResponse;

    const result = await server.verifyProof(proofResponse);
    expect(result.verified).to.equal(false);
    expect(result.error).to.equal('Request expired or invalid');
  });

  it('returns generic error in non-verbose mode for payload errors', async () => {
    const server = new ZkIdServer({
      verificationKeys: { age: {} as any },
      verboseErrors: false,
      validatePayloads: true,
    });

    const result = await server.verifyProof({} as any);
    expect(result.verified).to.equal(false);
    expect(result.error).to.equal('Invalid request format');
  });

  it('returns original error in verbose mode', async () => {
    const server = new ZkIdServer({
      verificationKeys: { age: {} as any },
      verboseErrors: true,
      requireSignedCredentials: false,
      maxRequestAgeMs: 1000,
    });

    const timestamp = Date.now() - 5000; // 5 seconds ago (stale)
    const proofResponse: ProofResponse = {
      credentialId: 'cred-1',
      claimType: 'age',
      proof: makeAgeProof('hash-1', 18, 'nonce-verbose', timestamp),
      nonce: 'nonce-verbose',
      requestTimestamp: new Date(timestamp).toISOString(),
    } as ProofResponse;

    const result = await server.verifyProof(proofResponse);
    expect(result.verified).to.equal(false);
    expect(result.error).to.include('Request timestamp is too old');
  });
});

// ---------------------------------------------------------------------------
// rotationGracePeriodMs tests (Fix 4b)
// ---------------------------------------------------------------------------

describe('InMemoryIssuerRegistry - rotationGracePeriodMs', () => {
  function makeKeyPair() {
    return generateKeyPairSync('ed25519');
  }

  it('accepts key within validity window (baseline)', async () => {
    const { publicKey } = makeKeyPair();
    const now = new Date();
    const past = new Date(now.getTime() - 86400_000); // 1 day ago
    const future = new Date(now.getTime() + 86400_000); // 1 day from now

    const registry = new InMemoryIssuerRegistry([
      {
        issuer: 'grace-baseline',
        publicKey,
        status: 'active',
        validFrom: past.toISOString(),
        validTo: future.toISOString(),
      },
    ]);

    const record = await registry.getIssuer('grace-baseline');
    expect(record).to.not.be.null;
    expect(record!.publicKey).to.equal(publicKey);
  });

  it('expired key with no grace period falls through to fallback', async () => {
    const { publicKey: expiredKey } = makeKeyPair();
    const now = new Date();
    const past = new Date(now.getTime() - 86400_000); // 1 day ago
    const justExpired = new Date(now.getTime() - 1000); // 1 second ago

    const registry = new InMemoryIssuerRegistry([
      {
        issuer: 'grace-nograce',
        publicKey: expiredKey,
        status: 'active',
        validFrom: past.toISOString(),
        validTo: justExpired.toISOString(),
        // No rotationGracePeriodMs set
      },
    ]);

    const record = await registry.getIssuer('grace-nograce');
    // Falls back to first record (the expired one)
    expect(record).to.not.be.null;
    expect(record!.publicKey).to.equal(expiredKey);
  });

  it('expired key within grace period is accepted', async () => {
    const { publicKey } = makeKeyPair();
    const now = new Date();
    const past = new Date(now.getTime() - 86400_000); // 1 day ago
    const recentlyExpired = new Date(now.getTime() - 30_000); // 30 seconds ago

    const registry = new InMemoryIssuerRegistry([
      {
        issuer: 'grace-within',
        publicKey,
        status: 'active',
        validFrom: past.toISOString(),
        validTo: recentlyExpired.toISOString(),
        rotationGracePeriodMs: 60_000, // 1 minute grace period
      },
    ]);

    const record = await registry.getIssuer('grace-within');
    expect(record).to.not.be.null;
    expect(record!.publicKey).to.equal(publicKey);
  });

  it('expired key beyond grace period falls through to fallback', async () => {
    const { publicKey: oldKey } = makeKeyPair();
    const now = new Date();
    const past = new Date(now.getTime() - 86400_000); // 1 day ago
    const longExpired = new Date(now.getTime() - 120_000); // 2 minutes ago

    const registry = new InMemoryIssuerRegistry([
      {
        issuer: 'grace-beyond',
        publicKey: oldKey,
        status: 'active',
        validFrom: past.toISOString(),
        validTo: longExpired.toISOString(),
        rotationGracePeriodMs: 60_000, // 1 minute grace period (expired 2 min ago, so beyond grace)
      },
    ]);

    const record = await registry.getIssuer('grace-beyond');
    // Falls back to first record
    expect(record).to.not.be.null;
    expect(record!.publicKey).to.equal(oldKey);
  });

  it('non-active key with grace period is NOT accepted', async () => {
    const { publicKey: revokedKey } = makeKeyPair();
    const { publicKey: fallbackKey } = makeKeyPair();
    const now = new Date();
    const past = new Date(now.getTime() - 86400_000);
    const recentlyExpired = new Date(now.getTime() - 30_000); // 30 seconds ago

    const registry = new InMemoryIssuerRegistry([
      {
        issuer: 'grace-revoked',
        publicKey: revokedKey,
        status: 'revoked', // Not active
        validFrom: past.toISOString(),
        validTo: recentlyExpired.toISOString(),
        rotationGracePeriodMs: 60_000, // Within grace period, but status is revoked
      },
      {
        issuer: 'grace-revoked',
        publicKey: fallbackKey,
        status: 'active',
        validFrom: past.toISOString(),
      },
    ]);

    const record = await registry.getIssuer('grace-revoked');
    expect(record).to.not.be.null;
    // Should NOT return the revoked key, even though it's within grace period
    // Status check takes priority
    expect(record!.publicKey).to.not.equal(revokedKey);
    expect(record!.publicKey).to.equal(fallbackKey);
  });

  it('does not fail verification when grace-period audit logger throws', async () => {
    const { signedCredential, publicKey } = makeSignedCredential('12345', 'grace-logger');
    const now = Date.now();
    const past = new Date(now - 86400_000);
    const recentlyExpired = new Date(now - 30_000);

    const registry = new InMemoryIssuerRegistry([
      {
        issuer: 'grace-logger',
        publicKey,
        status: 'active',
        validFrom: past.toISOString(),
        validTo: recentlyExpired.toISOString(),
        rotationGracePeriodMs: 60_000,
      },
    ]);

    const auditLogger = {
      log: () => {
        throw new Error('boom');
      },
    };

    const server = new ZkIdServer({
      verificationKeyPath: getVerificationKeyPath(),
      issuerRegistry: registry,
      auditLogger,
      verboseErrors: true,
    });

    const requestTimestampMs = Date.now();
    const proofResponse: ProofResponse = {
      credentialId: signedCredential.credential.id,
      claimType: 'age',
      proof: makeAgeProof(
        signedCredential.credential.commitment,
        18,
        'nonce-grace',
        requestTimestampMs,
      ),
      signedCredential,
      nonce: 'nonce-grace',
      requestTimestamp: new Date(requestTimestampMs).toISOString(),
    };

    const result = await server.verifyProof(proofResponse);
    expect(result).to.have.property('verified');
  });
});

describe('InMemoryNonceStore', () => {
  it('prunes expired nonces automatically', async () => {
    const store = new InMemoryNonceStore({ ttlMs: 10, pruneIntervalMs: 5 });
    await store.add('nonce-1');
    expect((store as any).nonces.size).to.equal(1);

    await new Promise((resolve) => setTimeout(resolve, 30));
    expect((store as any).nonces.size).to.equal(0);
    store.stop();
  });
});

// ---------------------------------------------------------------------------
// Grace period test for validateSignedCredentialBinding (Fix 3)
// ---------------------------------------------------------------------------

describe('validateSignedCredentialBinding - rotationGracePeriodMs', () => {
  function makeKeyPair() {
    return generateKeyPairSync('ed25519');
  }

  function makeSignedCredentialWithKey(
    commitment: string,
    issuer: string,
    privateKey: any,
  ): SignedCredential {
    const credential = {
      id: 'cred-grace-test',
      birthYear: 1990,
      nationality: 840,
      salt: '00',
      commitment,
      createdAt: new Date().toISOString(),
    };

    const issuedAt = new Date().toISOString();
    const payload = credentialSignaturePayload(credential, issuer, issuedAt);
    const signature = sign(null, Buffer.from(payload), privateKey).toString('base64');

    return {
      credential,
      issuer,
      signature,
      issuedAt,
    };
  }

  it('verifyProof accepts signed credential from issuer within grace period and emits audit log', async () => {
    const { publicKey, privateKey } = makeKeyPair();
    const issuerName = 'grace-test-issuer';
    const commitment = '123';

    // Create an issuer with an expired key but within grace period
    const now = new Date();
    const past = new Date(now.getTime() - 86400_000); // 1 day ago
    const recentlyExpired = new Date(now.getTime() - 30_000); // 30 seconds ago

    // Track audit log entries
    const auditLogs: any[] = [];
    const mockAuditLogger = {
      log: (entry: any) => {
        auditLogs.push(entry);
      },
    };

    const registry = new InMemoryIssuerRegistry(
      [
        {
          issuer: issuerName,
          publicKey,
          status: 'active',
          validFrom: past.toISOString(),
          validTo: recentlyExpired.toISOString(),
          rotationGracePeriodMs: 60_000, // 1 minute grace period
        },
      ],
      mockAuditLogger,
    );

    const server = new ZkIdServer({
      verificationKeyPath: getVerificationKeyPath(),
      issuerRegistry: registry,
      auditLogger: mockAuditLogger,
      verboseErrors: true,
    });

    // Create a signed credential from this issuer
    const signedCredential = makeSignedCredentialWithKey(commitment, issuerName, privateKey);

    // Create a proof response
    const requestTimestamp = Date.now();
    const proofResponse: ProofResponse = {
      credentialId: signedCredential.credential.id,
      claimType: 'age',
      proof: makeAgeProof(commitment, 18, 'nonce-grace-test', requestTimestamp),
      signedCredential,
      nonce: 'nonce-grace-test',
      requestTimestamp: new Date(requestTimestamp).toISOString(),
    };

    // Verify the proof (this should succeed due to grace period)
    const result = await server.verifyProof(proofResponse);

    // The verification should succeed (or at least not fail with "Issuer key expired")
    // Note: It may fail for other reasons (missing vkey, etc.) but not for expiry
    if (!result.verified && result.error === 'Issuer key expired') {
      throw new Error('Grace period was not applied in validateSignedCredentialBinding');
    }

    // Verify that an audit log entry with action 'grace_period_accept' was emitted
    const graceAcceptLogs = auditLogs.filter((log) => log.action === 'grace_period_accept');
    expect(graceAcceptLogs.length).to.be.greaterThan(
      0,
      'Expected at least one grace_period_accept audit log entry',
    );

    // Verify the audit log entry has the expected structure
    const graceLog = graceAcceptLogs[graceAcceptLogs.length - 1]; // Get the most recent one
    expect(graceLog.actor).to.equal(issuerName);
    expect(graceLog.target).to.equal(issuerName);
    expect(graceLog.success).to.equal(true);
    expect(graceLog.metadata).to.have.property('validTo');
    expect(graceLog.metadata).to.have.property('graceMs');
    expect(graceLog.metadata).to.have.property('expiredAgoMs');
  });
});

// ---------------------------------------------------------------------------
// validatePayloads default behavior (V-4 security fix)
// ---------------------------------------------------------------------------

describe('ZkIdServer - validatePayloads default true (V-4)', () => {
  it('validates payloads by default (no config)', async () => {
    const server = new ZkIdServer({
      verificationKeys: { age: {} as any },
      verboseErrors: true,
    });

    const result = await server.verifyProof({} as any);
    expect(result.verified).to.equal(false);
    expect(result.error).to.match(/Invalid payload/);
  });

  it('validates payloads when explicitly undefined', async () => {
    const server = new ZkIdServer({
      verificationKeys: { age: {} as any },
      validatePayloads: undefined,
      verboseErrors: true,
    });

    const result = await server.verifyProof({} as any);
    expect(result.verified).to.equal(false);
    expect(result.error).to.match(/Invalid payload/);
  });

  it('allows disabling validation with explicit false', async () => {
    const server = new ZkIdServer({
      verificationKeys: { age: {} as any },
      validatePayloads: false,
      requireSignedCredentials: false,
    });

    // Should skip validation and proceed to proof verification
    const timestamp = Date.now();
    const proofResponse: ProofResponse = {
      credentialId: 'cred-1',
      claimType: 'age',
      proof: makeAgeProof('hash-1', 18, 'nonce-1', timestamp),
      nonce: 'nonce-1',
      requestTimestamp: new Date(timestamp).toISOString(),
    } as ProofResponse;

    const result = await server.verifyProof(proofResponse);
    // Will fail at proof verification, not payload validation
    expect(result.verified).to.equal(false);
  });

  it('validates when explicitly set to true', async () => {
    const server = new ZkIdServer({
      verificationKeys: { age: {} as any },
      validatePayloads: true,
      verboseErrors: true,
    });

    const result = await server.verifyProof({} as any);
    expect(result.verified).to.equal(false);
    expect(result.error).to.match(/Invalid payload/);
  });
});

// ---------------------------------------------------------------------------
// sanitizeError additional paths
// ---------------------------------------------------------------------------

describe('ZkIdServer - sanitizeError additional paths', () => {
  it('sanitizes proof verification errors', async () => {
    const server = new ZkIdServer({
      verificationKeys: { age: {} as any },
      verboseErrors: false,
      requireSignedCredentials: false,
    });

    const timestamp = Date.now();
    const proofResponse: ProofResponse = {
      credentialId: 'cred-1',
      claimType: 'age',
      proof: makeAgeProof('hash-1', 18, 'nonce-proof', timestamp),
      nonce: 'nonce-proof',
      requestTimestamp: new Date(timestamp).toISOString(),
    } as ProofResponse;

    const result = await server.verifyProof(proofResponse);
    expect(result.verified).to.equal(false);
    expect(result.error).to.equal('Verification failed');
  });

  it('sanitizes issuer not found errors', async () => {
    const server = new ZkIdServer({
      verificationKeys: { age: {} as any },
      verboseErrors: false,
    });

    const timestamp = Date.now();
    const { signedCredential } = makeSignedCredential('hash-1', 'UnknownIssuer');
    const proofResponse: ProofResponse = {
      credentialId: 'cred-1',
      claimType: 'age',
      proof: makeAgeProof('hash-1', 18, 'nonce-issuer', timestamp),
      nonce: 'nonce-issuer',
      requestTimestamp: new Date(timestamp).toISOString(),
      signedCredential,
    } as ProofResponse;

    const result = await server.verifyProof(proofResponse);
    expect(result.verified).to.equal(false);
    expect(result.error).to.equal('Verification failed');
  });

  it('sanitizes revocation root errors', async () => {
    const server = new ZkIdServer({
      verificationKeys: { age: {} as any, ageRevocable: {} as any },
      verboseErrors: false,
      requireSignedCredentials: false,
      maxRevocationRootAgeMs: 1000,
    });

    const timestamp = Date.now();
    const proofResponse: ProofResponse = {
      credentialId: 'cred-1',
      claimType: 'age-revocable',
      proof: makeAgeProofRevocable('hash-1', 'root-1', 18, 'nonce-rev', timestamp),
      nonce: 'nonce-rev',
      requestTimestamp: new Date(timestamp).toISOString(),
      revocationRootTimestamp: new Date(timestamp - 5000).toISOString(), // 5 seconds ago
    } as ProofResponse;

    const result = await server.verifyProof(proofResponse);
    expect(result.verified).to.equal(false);
    expect(result.error).to.equal('Verification failed');
  });

  it('returns detailed error in verbose mode for missing fields', async () => {
    const server = new ZkIdServer({
      verificationKeys: { age: {} as any },
      verboseErrors: true,
      validatePayloads: true,
    });

    const result = await server.verifyProof({ claimType: 'age' } as any);
    expect(result.verified).to.equal(false);
    expect(result.error).to.include('Invalid payload');
  });

  it('returns detailed error in verbose mode for invalid types', async () => {
    const server = new ZkIdServer({
      verificationKeys: { age: {} as any },
      verboseErrors: true,
      validatePayloads: true,
    });

    const result = await server.verifyProof({
      claimType: 'age',
      nonce: 123, // Should be string
    } as any);
    expect(result.verified).to.equal(false);
    expect(result.error).to.include('Invalid payload');
  });
});
