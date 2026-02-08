import { expect } from 'chai';
import fs from 'fs';
import path from 'path';
import { ZkIdServer, StaticVerificationKeyProvider } from '../src/server';

function getVerificationKeyPath(): string {
  return path.resolve(__dirname, '../../circuits/build/age-verify_verification_key.json');
}

describe('ZkIdServer key provider', () => {
  it('creates server using a verification key provider', async () => {
    const key = JSON.parse(fs.readFileSync(getVerificationKeyPath(), 'utf8'));
    const provider = new StaticVerificationKeyProvider({ age: key });

    const server = await ZkIdServer.createWithKeyProvider({
      verificationKeyProvider: provider,
      requireSignedCredentials: false,
    });

    expect(server).to.be.instanceOf(ZkIdServer);
  });
});
