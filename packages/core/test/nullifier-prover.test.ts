import { strict as assert } from 'assert';
import { createCredential } from '../src/credential';
import { generateNullifierProof } from '../src/prover';
import { BN128_FIELD_ORDER } from '../src/validation';

describe('generateNullifierProof', () => {
  it('rejects non-numeric scopeHash', async () => {
    const credential = await createCredential(1990, 840);
    await assert.rejects(
      () => generateNullifierProof(credential, 'not-a-number', 'missing', 'missing'),
      /scopeHash/
    );
  });

  it('rejects out-of-field scopeHash', async () => {
    const credential = await createCredential(1990, 840);
    const tooLarge = (BN128_FIELD_ORDER + 1n).toString();
    await assert.rejects(
      () => generateNullifierProof(credential, tooLarge, 'missing', 'missing'),
      /scopeHash/
    );
  });
});
