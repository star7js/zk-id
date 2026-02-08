import { InMemoryMerkleRevocationAccumulator } from '@zk-id/core';

async function run() {
  const accumulator = new InMemoryMerkleRevocationAccumulator(4);
  const revokedCommitment = '123456789';

  await accumulator.revoke(revokedCommitment);

  const root = await accumulator.getRoot();
  const witness = await accumulator.getWitness(revokedCommitment);

  console.log('Revocation root:', root);
  console.log('Revocation witness:', witness);
}

run().catch((err) => {
  console.error('Revocation accumulator demo failed:', err);
  process.exit(1);
});
