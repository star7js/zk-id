import { expect } from 'chai';
import {
  generateBBSKeyPair,
  signBBSMessages,
  verifyBBSSignature,
  deriveBBSDisclosureProof,
  verifyBBSDisclosureProof,
  encodeBBSMessage,
  decodeBBSMessage,
  credentialFieldsToBBSMessages,
  getDisclosedFields,
  serializeBBSProof,
  deserializeBBSProof,
  BBS_CREDENTIAL_FIELDS,
  BBSCredential,
} from '../src/bbs';

describe('BBS Selective Disclosure', () => {
  let keyPair: { secretKey: Uint8Array; publicKey: Uint8Array };

  before(async () => {
    keyPair = await generateBBSKeyPair();
  });

  describe('generateBBSKeyPair', () => {
    it('should generate a valid BBS key pair', () => {
      expect(keyPair.secretKey).to.be.instanceOf(Uint8Array);
      expect(keyPair.publicKey).to.be.instanceOf(Uint8Array);
      expect(keyPair.secretKey.length).to.be.greaterThan(0);
      expect(keyPair.publicKey.length).to.be.greaterThan(0);
    });

    it('should generate unique key pairs', async () => {
      const kp2 = await generateBBSKeyPair();
      expect(Buffer.from(kp2.secretKey).toString('hex'))
        .to.not.equal(Buffer.from(keyPair.secretKey).toString('hex'));
    });
  });

  describe('encodeBBSMessage / decodeBBSMessage', () => {
    it('should round-trip string values', () => {
      const msg = encodeBBSMessage('hello world');
      expect(decodeBBSMessage(msg)).to.equal('hello world');
    });

    it('should round-trip numeric values', () => {
      const msg = encodeBBSMessage(1990);
      expect(decodeBBSMessage(msg)).to.equal('1990');
    });

    it('should round-trip bigint values', () => {
      const msg = encodeBBSMessage(BigInt('12345678901234567890'));
      expect(decodeBBSMessage(msg)).to.equal('12345678901234567890');
    });
  });

  describe('signBBSMessages / verifyBBSSignature', () => {
    it('should sign and verify messages', async () => {
      const messages = [
        encodeBBSMessage('Alice'),
        encodeBBSMessage(30),
        encodeBBSMessage('US'),
      ];

      const signature = await signBBSMessages(
        keyPair.secretKey,
        keyPair.publicKey,
        messages,
      );

      expect(signature).to.be.instanceOf(Uint8Array);
      expect(signature.length).to.be.greaterThan(0);

      const valid = await verifyBBSSignature(
        keyPair.publicKey,
        signature,
        messages,
      );
      expect(valid).to.be.true;
    });

    it('should reject tampered messages', async () => {
      const messages = [
        encodeBBSMessage('Alice'),
        encodeBBSMessage(30),
      ];

      const signature = await signBBSMessages(
        keyPair.secretKey,
        keyPair.publicKey,
        messages,
      );

      const tampered = [
        encodeBBSMessage('Bob'),
        encodeBBSMessage(30),
      ];

      const valid = await verifyBBSSignature(
        keyPair.publicKey,
        signature,
        tampered,
      );
      expect(valid).to.be.false;
    });

    it('should reject wrong public key', async () => {
      const messages = [encodeBBSMessage('test')];
      const signature = await signBBSMessages(
        keyPair.secretKey,
        keyPair.publicKey,
        messages,
      );

      const otherKP = await generateBBSKeyPair();
      const valid = await verifyBBSSignature(
        otherKP.publicKey,
        signature,
        messages,
      );
      expect(valid).to.be.false;
    });
  });

  describe('credentialFieldsToBBSMessages', () => {
    it('should encode all credential fields in canonical order', () => {
      const fields = {
        id: 'cred-123',
        birthYear: 1990,
        nationality: 840,
        salt: 'abc123',
        issuedAt: '2026-01-01T00:00:00Z',
        issuer: 'Test Issuer',
      };

      const { messages, labels } = credentialFieldsToBBSMessages(fields);

      expect(messages).to.have.length(BBS_CREDENTIAL_FIELDS.length);
      expect(labels).to.deep.equal(BBS_CREDENTIAL_FIELDS);

      expect(decodeBBSMessage(messages[0])).to.equal('cred-123');
      expect(decodeBBSMessage(messages[1])).to.equal('1990');
      expect(decodeBBSMessage(messages[2])).to.equal('840');
      expect(decodeBBSMessage(messages[3])).to.equal('abc123');
      expect(decodeBBSMessage(messages[4])).to.equal('2026-01-01T00:00:00Z');
      expect(decodeBBSMessage(messages[5])).to.equal('Test Issuer');
    });

    it('should throw on missing fields', () => {
      expect(() => credentialFieldsToBBSMessages({ id: 'x' } as any))
        .to.throw(/Missing required credential field/);
    });
  });

  describe('Selective Disclosure', () => {
    let credential: BBSCredential;

    before(async () => {
      const fields = {
        id: 'cred-sd-001',
        birthYear: 1995,
        nationality: 276,
        salt: 'random-salt-value',
        issuedAt: '2026-02-09T12:00:00Z',
        issuer: 'Test Authority',
      };

      const { messages, labels } = credentialFieldsToBBSMessages(fields);
      const header = new Uint8Array();
      const signature = await signBBSMessages(
        keyPair.secretKey,
        keyPair.publicKey,
        messages,
        header,
      );

      credential = {
        id: 'cred-sd-001',
        messages,
        labels,
        signature,
        header,
        issuerPublicKey: keyPair.publicKey,
        fieldValues: fields,
      };
    });

    it('should derive and verify a proof disclosing nationality only', async () => {
      const proof = await deriveBBSDisclosureProof(credential, {
        disclose: ['nationality'],
      });

      expect(proof.disclosedIndexes).to.deep.equal([2]); // nationality is index 2
      expect(proof.disclosedLabels.get(2)).to.equal('nationality');

      const fields = getDisclosedFields(proof);
      expect(fields).to.deep.equal({ nationality: '276' });
      expect(fields).to.not.have.property('birthYear');
      expect(fields).to.not.have.property('salt');

      const valid = await verifyBBSDisclosureProof(proof);
      expect(valid).to.be.true;
    });

    it('should derive and verify a proof disclosing multiple fields', async () => {
      const proof = await deriveBBSDisclosureProof(credential, {
        disclose: ['id', 'nationality', 'issuer'],
      });

      expect(proof.disclosedIndexes).to.deep.equal([0, 2, 5]);

      const fields = getDisclosedFields(proof);
      expect(fields).to.deep.equal({
        id: 'cred-sd-001',
        nationality: '276',
        issuer: 'Test Authority',
      });

      const valid = await verifyBBSDisclosureProof(proof);
      expect(valid).to.be.true;
    });

    it('should derive and verify a proof with a nonce', async () => {
      const proof = await deriveBBSDisclosureProof(credential, {
        disclose: ['birthYear'],
        nonce: 'verifier-challenge-abc',
      });

      const valid = await verifyBBSDisclosureProof(proof);
      expect(valid).to.be.true;
    });

    it('should fail verification with tampered disclosed message', async () => {
      const proof = await deriveBBSDisclosureProof(credential, {
        disclose: ['nationality'],
      });

      // Tamper with the disclosed message
      proof.disclosedMessages.set(2, encodeBBSMessage(999));

      const valid = await verifyBBSDisclosureProof(proof);
      expect(valid).to.be.false;
    });

    it('should throw when no valid fields are specified', async () => {
      try {
        await deriveBBSDisclosureProof(credential, {
          disclose: ['nonexistent' as any],
        });
        expect.fail('Should have thrown');
      } catch (e: any) {
        expect(e.message).to.match(/No valid fields/);
      }
    });
  });

  describe('Serialization', () => {
    it('should round-trip a disclosure proof through JSON', async () => {
      const fields = {
        id: 'cred-serial-001',
        birthYear: 2000,
        nationality: 392,
        salt: 'ser-salt',
        issuedAt: '2026-02-09T00:00:00Z',
        issuer: 'Serialization Issuer',
      };

      const { messages, labels } = credentialFieldsToBBSMessages(fields);
      const header = new Uint8Array();
      const signature = await signBBSMessages(
        keyPair.secretKey,
        keyPair.publicKey,
        messages,
        header,
      );

      const credential: BBSCredential = {
        id: 'cred-serial-001',
        messages,
        labels,
        signature,
        header,
        issuerPublicKey: keyPair.publicKey,
        fieldValues: fields,
      };

      const proof = await deriveBBSDisclosureProof(credential, {
        disclose: ['id', 'nationality'],
        nonce: 'test-nonce',
      });

      // Serialize
      const serialized = serializeBBSProof(proof);
      expect(serialized.proof).to.be.a('string'); // base64
      expect(serialized.disclosedMessages).to.have.property('id');
      expect(serialized.disclosedMessages).to.have.property('nationality');

      // JSON round-trip
      const json = JSON.stringify(serialized);
      const parsed = JSON.parse(json);

      // Deserialize
      const restored = deserializeBBSProof(parsed);

      // Verify the restored proof
      const valid = await verifyBBSDisclosureProof(restored);
      expect(valid).to.be.true;
    });
  });

  describe('BBS_CREDENTIAL_FIELDS', () => {
    it('should define exactly 6 fields in canonical order', () => {
      expect(BBS_CREDENTIAL_FIELDS).to.deep.equal([
        'id', 'birthYear', 'nationality', 'salt', 'issuedAt', 'issuer',
      ]);
    });
  });
});
