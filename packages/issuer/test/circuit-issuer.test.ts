import { expect } from 'chai';
import { CircuitCredentialIssuer } from '../src/circuit-issuer';

describe('CircuitCredentialIssuer Tests', () => {
  it('should issue a circuit-signed credential with bit arrays', async () => {
    const issuer = await CircuitCredentialIssuer.createTestIssuer('Circuit Issuer');
    const signed = await issuer.issueCredential(1990, 840);

    expect(signed.issuer).to.equal('Circuit Issuer');
    expect(signed.issuerPublicKey).to.have.lengthOf(256);
    expect(signed.signature.R8).to.have.lengthOf(256);
    expect(signed.signature.S).to.have.lengthOf(256);

    for (const bit of signed.issuerPublicKey) {
      expect(bit === '0' || bit === '1').to.be.true;
    }
  });
});
