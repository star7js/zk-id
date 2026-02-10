import { expect } from 'chai';
import { constantTimeEqual, constantTimeArrayEqual } from '../src/timing-safe';

describe('Timing-Safe Comparisons', () => {
  describe('constantTimeEqual', () => {
    it('should return true for identical strings', () => {
      expect(constantTimeEqual('hello', 'hello')).to.be.true;
      expect(constantTimeEqual('test123', 'test123')).to.be.true;
    });

    it('should return false for different strings with same length', () => {
      expect(constantTimeEqual('hello', 'world')).to.be.false;
      expect(constantTimeEqual('abc', 'xyz')).to.be.false;
    });

    it('should return false for strings with different lengths', () => {
      expect(constantTimeEqual('short', 'longer')).to.be.false;
      expect(constantTimeEqual('test', 'testing')).to.be.false;
    });

    it('should handle empty strings', () => {
      expect(constantTimeEqual('', '')).to.be.true;
      expect(constantTimeEqual('', 'x')).to.be.false;
    });

    it('should return false when one string is empty', () => {
      expect(constantTimeEqual('hello', '')).to.be.false;
      expect(constantTimeEqual('', 'world')).to.be.false;
    });

    it('should handle long strings', () => {
      const long1 = 'a'.repeat(1000);
      const long2 = 'a'.repeat(1000);
      const long3 = 'a'.repeat(999) + 'b';
      expect(constantTimeEqual(long1, long2)).to.be.true;
      expect(constantTimeEqual(long1, long3)).to.be.false;
    });

    it('should return false when last character differs', () => {
      expect(constantTimeEqual('test123', 'test124')).to.be.false;
      expect(constantTimeEqual('abcdefg', 'abcdefh')).to.be.false;
    });

    it('should handle unicode characters', () => {
      expect(constantTimeEqual('hello 世界', 'hello 世界')).to.be.true;
      expect(constantTimeEqual('emoji 😀', 'emoji 😀')).to.be.true;
      expect(constantTimeEqual('emoji 😀', 'emoji 😁')).to.be.false;
    });
  });

  describe('constantTimeArrayEqual', () => {
    it('should return true for identical arrays', () => {
      expect(constantTimeArrayEqual(['a', 'b', 'c'], ['a', 'b', 'c'])).to.be.true;
      expect(constantTimeArrayEqual(['test'], ['test'])).to.be.true;
    });

    it('should return false for arrays with different elements', () => {
      expect(constantTimeArrayEqual(['a', 'b', 'c'], ['a', 'b', 'd'])).to.be.false;
      expect(constantTimeArrayEqual(['hello'], ['world'])).to.be.false;
    });

    it('should return false for arrays with different lengths', () => {
      expect(constantTimeArrayEqual(['a', 'b'], ['a', 'b', 'c'])).to.be.false;
      expect(constantTimeArrayEqual(['x', 'y', 'z'], ['x', 'y'])).to.be.false;
    });

    it('should handle empty arrays', () => {
      expect(constantTimeArrayEqual([], [])).to.be.true;
      expect(constantTimeArrayEqual([], ['a'])).to.be.false;
      expect(constantTimeArrayEqual(['a'], [])).to.be.false;
    });

    it('should handle single-element arrays', () => {
      expect(constantTimeArrayEqual(['x'], ['x'])).to.be.true;
      expect(constantTimeArrayEqual(['x'], ['y'])).to.be.false;
    });

    it('should return false when last position differs', () => {
      expect(constantTimeArrayEqual(['a', 'b', 'c'], ['a', 'b', 'd'])).to.be.false;
      expect(constantTimeArrayEqual(['test', '123', 'end'], ['test', '123', 'fin'])).to.be.false;
    });
  });
});
