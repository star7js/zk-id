import { expect } from 'chai';
import { generateKeyPairSync, randomBytes, KeyObject, sign, verify } from 'crypto';
import {
  EnvelopeKeyManager,
  FileKeyManager,
  SealedKeyBundle,
} from '../src/kms';
import { ManagedCredentialIssuer } from '../src/managed-issuer';
import { CredentialIssuer } from '../src/issuer';
import { credentialSignaturePayload } from '@zk-id/core';

describe('KMS Integration', () => {
  describe('EnvelopeKeyManager', () => {
    let masterKey: Buffer;

    beforeEach(() => {
      masterKey = randomBytes(32);
    });

    it('should seal and unseal a key pair', async () => {
      const bundle = await EnvelopeKeyManager.seal('Test Issuer', masterKey);

      expect(bundle.issuerName).to.equal('Test Issuer');
      expect(bundle.encryptedPrivateKey).to.be.a('string');
      expect(bundle.iv).to.be.a('string');
      expect(bundle.authTag).to.be.a('string');
      expect(bundle.publicKeyPem).to.include('PUBLIC KEY');

      const manager = await EnvelopeKeyManager.unseal(bundle, masterKey);
      expect(manager.getIssuerName()).to.equal('Test Issuer');
      expect(manager.getPublicKey()).to.be.an.instanceOf(KeyObject);
    });

    it('should produce valid signatures after unseal', async () => {
      const bundle = await EnvelopeKeyManager.seal('Sig Issuer', masterKey);
      const manager = await EnvelopeKeyManager.unseal(bundle, masterKey);

      const payload = Buffer.from('test message');
      const signature = await manager.sign(payload);

      const isValid = verify(null, payload, manager.getPublicKey(), signature);
      expect(isValid).to.be.true;
    });

    it('should work with ManagedCredentialIssuer', async () => {
      const bundle = await EnvelopeKeyManager.seal('Managed Issuer', masterKey);
      const manager = await EnvelopeKeyManager.unseal(bundle, masterKey);
      const issuer = new ManagedCredentialIssuer(manager);

      const signed = await issuer.issueCredential(1990, 840);
      expect(signed.issuer).to.equal('Managed Issuer');
      expect(signed.signature).to.be.a('string');

      // Verify signature is valid (includes issuer binding)
      const payload = credentialSignaturePayload(signed.credential, signed.issuer, signed.issuedAt);
      const sig = Buffer.from(signed.signature, 'base64');
      const valid = verify(null, Buffer.from(payload), manager.getPublicKey(), sig);
      expect(valid).to.be.true;
    });

    it('should reject wrong master key on unseal', async () => {
      const bundle = await EnvelopeKeyManager.seal('Test', masterKey);
      const wrongKey = randomBytes(32);

      try {
        await EnvelopeKeyManager.unseal(bundle, wrongKey);
        expect.fail('Should have thrown');
      } catch (err: any) {
        expect(err.message).to.include('Unsupported state');
      }
    });

    it('should reject master key of wrong length', async () => {
      try {
        await EnvelopeKeyManager.seal('Test', Buffer.from('short'));
        expect.fail('Should have thrown');
      } catch (err: any) {
        expect(err.message).to.include('32 bytes');
      }
    });

    it('should produce different bundles each time (random IV)', async () => {
      const bundle1 = await EnvelopeKeyManager.seal('Test', masterKey);
      const bundle2 = await EnvelopeKeyManager.seal('Test', masterKey);

      expect(bundle1.iv).to.not.equal(bundle2.iv);
      expect(bundle1.encryptedPrivateKey).to.not.equal(
        bundle2.encryptedPrivateKey
      );
    });
  });

  describe('FileKeyManager', () => {
    let privateKey: KeyObject;
    let publicKey: KeyObject;
    let privateKeyPem: string;
    let publicKeyPem: string;

    before(() => {
      const pair = generateKeyPairSync('ed25519');
      privateKey = pair.privateKey;
      publicKey = pair.publicKey;
      privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
      publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }) as string;
    });

    it('should create from PEM strings', () => {
      const manager = FileKeyManager.fromPemStrings(
        'PEM Issuer',
        privateKeyPem,
        publicKeyPem
      );

      expect(manager.getIssuerName()).to.equal('PEM Issuer');
      expect(manager.getPublicKey()).to.be.an.instanceOf(KeyObject);
    });

    it('should produce valid signatures', async () => {
      const manager = FileKeyManager.fromPemStrings(
        'Sig PEM',
        privateKeyPem,
        publicKeyPem
      );

      const payload = Buffer.from('hello world');
      const signature = await manager.sign(payload);

      const isValid = verify(null, payload, manager.getPublicKey(), signature);
      expect(isValid).to.be.true;
    });

    it('should work with ManagedCredentialIssuer', async () => {
      const manager = FileKeyManager.fromPemStrings(
        'File Issuer',
        privateKeyPem,
        publicKeyPem
      );
      const issuer = new ManagedCredentialIssuer(manager);

      const signed = await issuer.issueCredential(1985, 826);
      expect(signed.issuer).to.equal('File Issuer');
      expect(signed.credential.birthYear).to.equal(1985);

      // Cross-verify with CredentialIssuer.verifySignature
      const isValid = CredentialIssuer.verifySignature(
        signed,
        manager.getPublicKey()
      );
      expect(isValid).to.be.true;
    });

    it('should reject invalid private key PEM', () => {
      const invalidPem = '-----BEGIN INVALID KEY-----\ngarbage\n-----END INVALID KEY-----';

      expect(() =>
        FileKeyManager.fromPemStrings('Test', invalidPem, publicKeyPem)
      ).to.throw();
    });

    it('should reject invalid public key PEM', () => {
      const invalidPem = '-----BEGIN INVALID KEY-----\ngarbage\n-----END INVALID KEY-----';

      expect(() =>
        FileKeyManager.fromPemStrings('Test', privateKeyPem, invalidPem)
      ).to.throw();
    });

    it('should reject empty PEM strings', () => {
      expect(() => FileKeyManager.fromPemStrings('Test', '', publicKeyPem)).to.throw();
      expect(() => FileKeyManager.fromPemStrings('Test', privateKeyPem, '')).to.throw();
    });

    it('should reject mismatched key pair', () => {
      const otherPair = generateKeyPairSync('ed25519');
      const otherPublicKeyPem = otherPair.publicKey.export({
        type: 'spki',
        format: 'pem',
      }) as string;

      // Create manager with mismatched keys
      const manager = FileKeyManager.fromPemStrings(
        'Mismatched',
        privateKeyPem,
        otherPublicKeyPem
      );

      // Signature will be valid with private key but won't verify with the public key
      const payload = Buffer.from('test');
      manager.sign(payload).then((signature) => {
        const isValid = verify(null, payload, manager.getPublicKey(), signature);
        expect(isValid).to.be.false; // Mismatched keys
      });
    });
  });

  describe('Key Rotation Scenarios', () => {
    it('should support transitioning from old to new keys', async () => {
      const masterKey = randomBytes(32);

      // Old key bundle (simulating existing production key)
      const oldBundle = await EnvelopeKeyManager.seal('Old Key', masterKey);
      const oldManager = await EnvelopeKeyManager.unseal(oldBundle, masterKey);

      // New key bundle (for rotation)
      const newBundle = await EnvelopeKeyManager.seal('New Key', masterKey);
      const newManager = await EnvelopeKeyManager.unseal(newBundle, masterKey);

      // Issue credential with old key
      const oldIssuer = new ManagedCredentialIssuer(oldManager);
      const credWithOldKey = await oldIssuer.issueCredential(1990, 840);

      // Verify with old key works
      const oldKeyValid = CredentialIssuer.verifySignature(
        credWithOldKey,
        oldManager.getPublicKey()
      );
      expect(oldKeyValid).to.be.true;

      // Verify with new key fails (different key)
      const newKeyValid = CredentialIssuer.verifySignature(
        credWithOldKey,
        newManager.getPublicKey()
      );
      expect(newKeyValid).to.be.false;

      // Issue new credential with new key
      const newIssuer = new ManagedCredentialIssuer(newManager);
      const credWithNewKey = await newIssuer.issueCredential(1990, 840);

      // Verify with new key works
      const newKeyValid2 = CredentialIssuer.verifySignature(
        credWithNewKey,
        newManager.getPublicKey()
      );
      expect(newKeyValid2).to.be.true;
    });

    it('should maintain old key availability during grace period', async () => {
      const masterKey = randomBytes(32);

      // Simulate having both old and new keys available
      const oldBundle = await EnvelopeKeyManager.seal('Old Key', masterKey);
      const newBundle = await EnvelopeKeyManager.seal('New Key', masterKey);

      const oldManager = await EnvelopeKeyManager.unseal(oldBundle, masterKey);
      const newManager = await EnvelopeKeyManager.unseal(newBundle, masterKey);

      // During grace period, old signatures should still verify
      const oldIssuer = new ManagedCredentialIssuer(oldManager);
      const oldCred = await oldIssuer.issueCredential(1995, 840);

      const stillValid = CredentialIssuer.verifySignature(
        oldCred,
        oldManager.getPublicKey()
      );
      expect(stillValid).to.be.true;

      // New credentials use new key
      const newIssuer = new ManagedCredentialIssuer(newManager);
      const newCred = await newIssuer.issueCredential(1995, 840);

      const newValid = CredentialIssuer.verifySignature(
        newCred,
        newManager.getPublicKey()
      );
      expect(newValid).to.be.true;
    });
  });

  describe('EnvelopeKeyManager - Additional Edge Cases', () => {
    it('should handle multiple seal/unseal cycles', async () => {
      const masterKey = randomBytes(32);

      for (let i = 0; i < 5; i++) {
        const bundle = await EnvelopeKeyManager.seal(`Issuer-${i}`, masterKey);
        const manager = await EnvelopeKeyManager.unseal(bundle, masterKey);

        expect(manager.getIssuerName()).to.equal(`Issuer-${i}`);

        const payload = Buffer.from(`message-${i}`);
        const signature = await manager.sign(payload);
        const isValid = verify(null, payload, manager.getPublicKey(), signature);
        expect(isValid).to.be.true;
      }
    });

    it('should produce unique keys for same issuer name', async () => {
      const masterKey = randomBytes(32);

      const bundle1 = await EnvelopeKeyManager.seal('Same Name', masterKey);
      const bundle2 = await EnvelopeKeyManager.seal('Same Name', masterKey);

      expect(bundle1.publicKeyPem).to.not.equal(bundle2.publicKeyPem);
      expect(bundle1.encryptedPrivateKey).to.not.equal(bundle2.encryptedPrivateKey);
    });

    it('should reject tampered encrypted key', async () => {
      const masterKey = randomBytes(32);
      const bundle = await EnvelopeKeyManager.seal('Test', masterKey);

      // Tamper with encrypted key
      const tamperedBundle: SealedKeyBundle = {
        ...bundle,
        encryptedPrivateKey: bundle.encryptedPrivateKey.replace(/.$/, 'X'),
      };

      try {
        await EnvelopeKeyManager.unseal(tamperedBundle, masterKey);
        expect.fail('Should have thrown');
      } catch (err: any) {
        expect(err.message).to.match(/Unsupported state|decrypt|auth/i);
      }
    });

    it('should reject tampered auth tag', async () => {
      const masterKey = randomBytes(32);
      const bundle = await EnvelopeKeyManager.seal('Test', masterKey);

      // Tamper with auth tag
      const tamperedBundle: SealedKeyBundle = {
        ...bundle,
        authTag: bundle.authTag.replace(/.$/, 'Y'),
      };

      try {
        await EnvelopeKeyManager.unseal(tamperedBundle, masterKey);
        expect.fail('Should have thrown');
      } catch (err: any) {
        expect(err.message).to.match(/Unsupported state|decrypt|auth/i);
      }
    });

    it('should handle issuer names with special characters', async () => {
      const masterKey = randomBytes(32);
      const specialNames = [
        'Test-Issuer_123',
        'Issuer (Production)',
        'Issuer@Domain.com',
        'Acme™ Corp',
      ];

      for (const name of specialNames) {
        const bundle = await EnvelopeKeyManager.seal(name, masterKey);
        const manager = await EnvelopeKeyManager.unseal(bundle, masterKey);

        expect(manager.getIssuerName()).to.equal(name);
      }
    });
  });

  describe('FileKeyManager - Additional Edge Cases', () => {
    it('should handle keys with different export formats', () => {
      const pair = generateKeyPairSync('ed25519');

      // PKCS8 format (standard)
      const pkcs8Private = pair.privateKey.export({
        type: 'pkcs8',
        format: 'pem',
      }) as string;

      // SPKI format (standard)
      const spkiPublic = pair.publicKey.export({
        type: 'spki',
        format: 'pem',
      }) as string;

      const manager = FileKeyManager.fromPemStrings('Test', pkcs8Private, spkiPublic);
      expect(manager.getPublicKey()).to.be.an.instanceOf(KeyObject);
    });

    it('should support multiple issuers with different keys', async () => {
      const issuers: Array<{ name: string; manager: FileKeyManager }> = [];

      for (let i = 0; i < 3; i++) {
        const pair = generateKeyPairSync('ed25519');
        const privatePem = pair.privateKey.export({
          type: 'pkcs8',
          format: 'pem',
        }) as string;
        const publicPem = pair.publicKey.export({
          type: 'spki',
          format: 'pem',
        }) as string;

        const manager = FileKeyManager.fromPemStrings(`Issuer-${i}`, privatePem, publicPem);
        issuers.push({ name: `Issuer-${i}`, manager });
      }

      // Each issuer should have unique keys
      for (let i = 0; i < issuers.length; i++) {
        for (let j = i + 1; j < issuers.length; j++) {
          const pub1 = issuers[i].manager
            .getPublicKey()
            .export({ type: 'spki', format: 'pem' });
          const pub2 = issuers[j].manager
            .getPublicKey()
            .export({ type: 'spki', format: 'pem' });

          expect(pub1).to.not.equal(pub2);
        }
      }
    });
  });

  describe('Cross-Manager Verification', () => {
    it('should verify credentials across different manager instances', async () => {
      const masterKey = randomBytes(32);

      // Create two issuers with different keys
      const bundle1 = await EnvelopeKeyManager.seal('Issuer A', masterKey);
      const bundle2 = await EnvelopeKeyManager.seal('Issuer B', masterKey);

      const managerA = await EnvelopeKeyManager.unseal(bundle1, masterKey);
      const managerB = await EnvelopeKeyManager.unseal(bundle2, masterKey);

      const issuerA = new ManagedCredentialIssuer(managerA);
      const issuerB = new ManagedCredentialIssuer(managerB);

      // Issue credentials
      const credFromA = await issuerA.issueCredential(1990, 840);
      const credFromB = await issuerB.issueCredential(1990, 840);

      // Verify with correct keys
      expect(CredentialIssuer.verifySignature(credFromA, managerA.getPublicKey())).to.be.true;
      expect(CredentialIssuer.verifySignature(credFromB, managerB.getPublicKey())).to.be.true;

      // Cross-verification should fail (different keys)
      expect(CredentialIssuer.verifySignature(credFromA, managerB.getPublicKey())).to.be.false;
      expect(CredentialIssuer.verifySignature(credFromB, managerA.getPublicKey())).to.be.false;
    });

    it('should maintain signature validity after re-unsealing', async () => {
      const masterKey = randomBytes(32);

      // Create and seal
      const bundle = await EnvelopeKeyManager.seal('Persistent Issuer', masterKey);
      const manager1 = await EnvelopeKeyManager.unseal(bundle, masterKey);
      const issuer1 = new ManagedCredentialIssuer(manager1);

      // Issue credential
      const credential = await issuer1.issueCredential(1995, 840);

      // Re-unseal the same bundle (simulating restart)
      const manager2 = await EnvelopeKeyManager.unseal(bundle, masterKey);

      // Verify with re-unsealed manager
      const isValid = CredentialIssuer.verifySignature(credential, manager2.getPublicKey());
      expect(isValid).to.be.true;
    });
  });
});
