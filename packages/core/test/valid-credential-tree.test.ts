import { expect } from 'chai';
import { InMemoryValidCredentialTree } from '../src/valid-credential-tree';

describe('InMemoryValidCredentialTree', () => {
  it('adds commitments and checks contains', async () => {
    const tree = new InMemoryValidCredentialTree(3);
    const commitment = '123456789';

    expect(await tree.contains(commitment)).to.equal(false);
    expect(await tree.size()).to.equal(0);

    await tree.add(commitment);

    expect(await tree.contains(commitment)).to.equal(true);
    expect(await tree.size()).to.equal(1);
  });

  it('returns null witness for unknown commitment', async () => {
    const tree = new InMemoryValidCredentialTree(2);
    const witness = await tree.getWitness('999');
    expect(witness).to.equal(null);
  });

  it('adding same commitment is idempotent', async () => {
    const tree = new InMemoryValidCredentialTree(3);
    const commitment = '123456789';

    await tree.add(commitment);
    const size1 = await tree.size();

    await tree.add(commitment);
    const size2 = await tree.size();

    expect(size1).to.equal(size2);
    expect(await tree.contains(commitment)).to.equal(true);
  });

  it('removes commitment and witness becomes null', async () => {
    const tree = new InMemoryValidCredentialTree(3);
    const commitment = '123456789';

    await tree.add(commitment);
    expect(await tree.contains(commitment)).to.equal(true);
    expect(await tree.getWitness(commitment)).to.not.equal(null);

    await tree.remove(commitment);
    expect(await tree.contains(commitment)).to.equal(false);
    expect(await tree.getWitness(commitment)).to.equal(null);
  });

  it('removing commitment updates root', async () => {
    const tree = new InMemoryValidCredentialTree(3);
    const commitment1 = '111';
    const commitment2 = '222';

    await tree.add(commitment1);
    await tree.add(commitment2);
    const rootBefore = await tree.getRoot();

    await tree.remove(commitment1);
    const rootAfter = await tree.getRoot();

    expect(rootBefore).to.not.equal(rootAfter);
  });

  it('remaining credential still valid after sibling removal', async () => {
    const tree = new InMemoryValidCredentialTree(3);
    const commitment1 = '111';
    const commitment2 = '222';

    await tree.add(commitment1);
    await tree.add(commitment2);

    await tree.remove(commitment1);

    expect(await tree.contains(commitment1)).to.equal(false);
    expect(await tree.contains(commitment2)).to.equal(true);

    const witness = await tree.getWitness(commitment2);
    expect(witness).to.not.equal(null);
    expect(witness?.pathIndices.length).to.equal(3);
    expect(witness?.siblings.length).to.equal(3);
  });

  it('removing non-existent commitment is no-op', async () => {
    const tree = new InMemoryValidCredentialTree(3);
    const commitment = '123456789';

    const sizeBefore = await tree.size();
    await tree.remove(commitment);
    const sizeAfter = await tree.size();

    expect(sizeBefore).to.equal(sizeAfter);
    expect(await tree.contains(commitment)).to.equal(false);
  });

  it('normalizes commitment formats for lookups', async () => {
    const tree = new InMemoryValidCredentialTree(3);
    await tree.add('0x10');

    expect(await tree.contains('16')).to.equal(true);
    expect(await tree.contains('0x10')).to.equal(true);

    await tree.remove('16');
    expect(await tree.contains('0x10')).to.equal(false);
  });

  it('tracks root version on mutations', async () => {
    const tree = new InMemoryValidCredentialTree(3);
    const commitment = '123456789';

    const info0 = await tree.getRootInfo();
    expect(info0.version).to.equal(0);

    await tree.add(commitment);
    const info1 = await tree.getRootInfo();
    expect(info1.version).to.equal(1);

    await tree.add(commitment); // idempotent
    const info2 = await tree.getRootInfo();
    expect(info2.version).to.equal(1);

    await tree.remove(commitment);
    const info3 = await tree.getRootInfo();
    expect(info3.version).to.equal(2);
  });

  it('throws when tree capacity overflows', async () => {
    const tree = new InMemoryValidCredentialTree(2); // max 4 leaves
    await tree.add('1');
    await tree.add('2');
    await tree.add('3');
    await tree.add('4');

    try {
      await tree.add('5');
      expect.fail('Should have thrown');
    } catch (err: any) {
      expect(err.message).to.include('tree is full');
    }
  });

  it('rejects invalid depth', () => {
    expect(() => new InMemoryValidCredentialTree(0)).to.throw('Invalid Merkle depth');
    expect(() => new InMemoryValidCredentialTree(21)).to.throw('Invalid Merkle depth');
  });
});
