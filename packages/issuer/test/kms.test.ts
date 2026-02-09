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
  });
});
