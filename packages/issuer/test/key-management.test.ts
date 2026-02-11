import { expect } from 'chai';
import { generateKeyPairSync, verify } from 'crypto';
import { InMemoryIssuerKeyManager } from '../src/key-management';

describe('InMemoryIssuerKeyManager', () => {
  let keyManager: InMemoryIssuerKeyManager;
  let publicKey: any;

  beforeEach(() => {
    const keyPair = generateKeyPairSync('ed25519');
    publicKey = keyPair.publicKey;
    keyManager = new InMemoryIssuerKeyManager('test-issuer', keyPair.privateKey, keyPair.publicKey);
  });

  describe('Core functionality', () => {
    it('should return the issuer name', () => {
      expect(keyManager.getIssuerName()).to.equal('test-issuer');
    });

    it('should return the public key', () => {
      const returnedKey = keyManager.getPublicKey();
      expect(returnedKey).to.equal(publicKey);
    });

    it('should sign and return a Buffer', async () => {
      const payload = Buffer.from('test message');
      const signature = await keyManager.sign(payload);

      expect(signature).to.be.instanceOf(Buffer);
      expect(signature.length).to.be.greaterThan(0);
    });

    it('should produce signatures that verify with the public key', async () => {
      const payload = Buffer.from('test message');
      const signature = await keyManager.sign(payload);
      const isValid = verify(null, payload, publicKey, signature);

      expect(isValid).to.be.true;
    });

    it('should produce different signatures for different payloads', async () => {
      const payload1 = Buffer.from('message 1');
      const payload2 = Buffer.from('message 2');

      const signature1 = await keyManager.sign(payload1);
      const signature2 = await keyManager.sign(payload2);

      expect(signature1.equals(signature2)).to.be.false;
    });
  });

  describe('Edge cases', () => {
    it('should handle empty payload', async () => {
      const emptyPayload = Buffer.from('');
      const signature = await keyManager.sign(emptyPayload);

      expect(signature).to.be.instanceOf(Buffer);
      expect(signature.length).to.be.greaterThan(0);
    });

    it('should handle large payloads', async () => {
      const largePayload = Buffer.alloc(10 * 1024); // 10KB
      largePayload.fill('a');

      const signature = await keyManager.sign(largePayload);
      const isValid = verify(null, largePayload, publicKey, signature);

      expect(isValid).to.be.true;
    });

    it('should not cross-verify with different key pairs', async () => {
      const otherKeyPair = generateKeyPairSync('ed25519');

      const payload = Buffer.from('test message');
      const signature = await keyManager.sign(payload);

      // Try to verify with a different public key
      const isValid = verify(null, payload, otherKeyPair.publicKey, signature);
      expect(isValid).to.be.false;
    });
  });

  describe('Interface compliance', () => {
    it('should implement all IssuerKeyManager methods', () => {
      expect(keyManager).to.have.property('getIssuerName');
      expect(keyManager).to.have.property('getPublicKey');
      expect(keyManager).to.have.property('sign');
      expect(typeof keyManager.getIssuerName).to.equal('function');
      expect(typeof keyManager.getPublicKey).to.equal('function');
      expect(typeof keyManager.sign).to.equal('function');
    });

    it('should return Promise<Buffer> from sign method', async () => {
      const payload = Buffer.from('test');
      const result = keyManager.sign(payload);

      expect(result).to.be.instanceOf(Promise);
      const signature = await result;
      expect(signature).to.be.instanceOf(Buffer);
    });
  });
});
