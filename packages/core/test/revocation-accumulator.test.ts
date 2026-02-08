import { expect } from 'chai';
import { InMemoryMerkleRevocationAccumulator } from '../src/revocation-accumulator';

describe('InMemoryMerkleRevocationAccumulator', () => {
  it('tracks revoked commitments and returns witnesses', async () => {
    const accumulator = new InMemoryMerkleRevocationAccumulator(3);
    const commitment = '123456789';

    expect(await accumulator.isRevoked(commitment)).to.equal(false);

    await accumulator.revoke(commitment);

    expect(await accumulator.isRevoked(commitment)).to.equal(true);

    const witness = await accumulator.getWitness(commitment);
    expect(witness).to.not.equal(null);
    expect(witness?.pathIndices.length).to.equal(3);
    expect(witness?.siblings.length).to.equal(3);
    expect(witness?.root).to.be.a('string');
  });

  it('returns null witness for unknown commitment', async () => {
    const accumulator = new InMemoryMerkleRevocationAccumulator(2);
    const witness = await accumulator.getWitness('999');
    expect(witness).to.equal(null);
  });
});
