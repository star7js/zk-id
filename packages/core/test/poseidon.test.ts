import { expect } from 'chai';
import { poseidonHash, poseidonHashHex } from '../src/poseidon';

describe('Poseidon Hash Tests', () => {
  describe('poseidonHash', () => {
    it('should compute hash for single input', async () => {
      const hash = await poseidonHash([123]);
      expect(typeof hash).to.equal('bigint');
      expect(hash > 0n).to.be.true;
    });

    it('should compute hash for multiple inputs', async () => {
      const hash = await poseidonHash([123, 456, 789]);
      expect(typeof hash).to.equal('bigint');
      expect(hash > 0n).to.be.true;
    });

    it('should be deterministic', async () => {
      const hash1 = await poseidonHash([123, 456]);
      const hash2 = await poseidonHash([123, 456]);
      expect(hash1).to.equal(hash2);
    });

    it('should produce different hashes for different inputs', async () => {
      const hash1 = await poseidonHash([123, 456]);
      const hash2 = await poseidonHash([123, 457]);
      const hash3 = await poseidonHash([124, 456]);

      expect(hash1).to.not.equal(hash2);
      expect(hash1).to.not.equal(hash3);
      expect(hash2).to.not.equal(hash3);
    });

    it('should handle large numbers', async () => {
      const bigNum = 999999999999999n;
      const hash = await poseidonHash([bigNum]);
      expect(typeof hash).to.equal('bigint');
      expect(hash > 0n).to.be.true;
    });

    it('should handle order sensitivity', async () => {
      const hash1 = await poseidonHash([1, 2, 3]);
      const hash2 = await poseidonHash([3, 2, 1]);
      expect(hash1).to.not.equal(hash2);
    });
  });

  describe('poseidonHashHex', () => {
    it('should return hex string with 0x prefix', async () => {
      const hash = await poseidonHashHex([123]);
      expect(hash).to.be.a('string');
      expect(hash).to.match(/^0x[0-9a-f]{64}$/);
    });

    it('should pad to 64 hex characters', async () => {
      const hash = await poseidonHashHex([1]);
      expect(hash.length).to.equal(66); // 0x + 64 chars
    });

    it('should be deterministic', async () => {
      const hash1 = await poseidonHashHex([123, 456]);
      const hash2 = await poseidonHashHex([123, 456]);
      expect(hash1).to.equal(hash2);
    });
  });

  describe('Integration with credentials', () => {
    it('should hash credential components', async () => {
      const birthYear = 1990;
      const salt = BigInt('0x1234567890abcdef');

      const hash = await poseidonHash([birthYear, salt]);
      expect(typeof hash).to.equal('bigint');
      expect(hash > 0n).to.be.true;
    });

    it('should produce unique hashes for different credentials', async () => {
      const hash1 = await poseidonHash([1990, BigInt('0x1111')]);
      const hash2 = await poseidonHash([1990, BigInt('0x2222')]);
      const hash3 = await poseidonHash([1991, BigInt('0x1111')]);

      expect(hash1).to.not.equal(hash2);
      expect(hash1).to.not.equal(hash3);
      expect(hash2).to.not.equal(hash3);
    });
  });
});
