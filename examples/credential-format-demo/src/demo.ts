import { CredentialIssuer, toExternalCredentialFormat, fromExternalCredentialFormat } from '@zk-id/issuer';

async function main() {
  const issuer = CredentialIssuer.createTestIssuer('Format Demo Issuer');

  const signedCredential = await issuer.issueCredential(1990, 840);

  // Convert to an external credential format
  const converted = toExternalCredentialFormat(signedCredential, 'did:example:demo');

  // Convert back to internal format (salt must be supplied)
  const roundTrip = fromExternalCredentialFormat(
    converted,
    signedCredential.credential.id,
    signedCredential.credential.salt,
    signedCredential.credential.createdAt
  );

  console.log('Issuer:', roundTrip.issuer);
  console.log('Credential ID:', roundTrip.credential.id);
  console.log('Commitment:', roundTrip.credential.commitment);
}

main().catch((error) => {
  console.error('Demo failed:', error);
  process.exit(1);
});
