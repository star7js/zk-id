import { expect } from 'chai';
import path from 'path';
import { generateKeyPairSync, sign } from 'crypto';
import { ZkIdServer, IssuerRegistry } from '../src/server';
import {
  AgeProof,
  ProofResponse,
  SignedCredential,
  credentialSignaturePayload,
} from '@zk-id/core';

function makeAgeProof(
  credentialHash: string,
  minAge: number,
  nonce: string,
  requestTimestamp: number
): AgeProof {
  return {
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

  const payload = credentialSignaturePayload(credential);
  const signature = sign(null, Buffer.from(payload), privateKey).toString('base64');

  const signedCredential: SignedCredential = {
    credential,
    issuer,
    signature,
    issuedAt: new Date().toISOString(),
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
    });

    const proofResponse: ProofResponse = {
      credentialId: signedCredential.credential.id,
      claimType: 'nationality',
      proof: {
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
    expect(result.error).to.equal('Request timestamp outside allowed window');
  });
});
