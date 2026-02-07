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

function makeAgeProof(credentialHash: string, minAge: number, nonce: string): AgeProof {
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

describe('ZkIdServer - signature and policy enforcement', () => {
  it('rejects proof when signed credential is missing', async () => {
    const server = new ZkIdServer({
      verificationKeyPath: getVerificationKeyPath(),
      issuerPublicKeys: {},
    });

    const proofResponse = {
      credentialId: 'cred-1',
      claimType: 'age',
      proof: makeAgeProof('123', 18, 'nonce-1'),
      nonce: 'nonce-1',
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
      proof: makeAgeProof('123', 18, 'nonce-2'),
      signedCredential,
      nonce: 'nonce-2',
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
      proof: makeAgeProof('123', 18, 'nonce-3'),
      signedCredential,
      nonce: 'nonce-3',
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
      proof: makeAgeProof('123', 18, 'nonce-4'),
      signedCredential,
      nonce: 'nonce-4',
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
        },
      },
      signedCredential,
      nonce: 'nonce-nat',
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
      proof: makeAgeProof('123', 18, 'proof-nonce'),
      signedCredential,
      nonce: 'request-nonce',
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
      proof: makeAgeProof('123', 18, 'nonce-5'),
      signedCredential,
      nonce: 'nonce-5',
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
      proof: makeAgeProof('123', 18, 'nonce-6'),
      signedCredential,
      nonce: 'nonce-6',
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

    const proofResponse: ProofResponse = {
      credentialId: signedCredential.credential.id,
      claimType: 'age',
      proof: makeAgeProof('123', 18, 'nonce-7'),
      signedCredential,
      nonce: 'nonce-7',
      requestTimestamp: new Date(Date.now() - 10_000).toISOString(),
    };

    const result = await server.verifyProof(proofResponse);
    expect(result.verified).to.equal(false);
    expect(result.error).to.equal('Request timestamp outside allowed window');
  });
});
