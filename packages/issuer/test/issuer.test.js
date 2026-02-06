"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const chai_1 = require("chai");
const issuer_1 = require("../src/issuer");
describe('CredentialIssuer Tests', () => {
    let issuer;
    beforeEach(() => {
        issuer = issuer_1.CredentialIssuer.createTestIssuer('Test Government ID Authority');
    });
    describe('issueCredential', () => {
        it('should issue a valid signed credential', async () => {
            const birthYear = 1990;
            const signed = await issuer.issueCredential(birthYear);
            (0, chai_1.expect)(signed).to.have.property('credential');
            (0, chai_1.expect)(signed).to.have.property('issuer', 'Test Government ID Authority');
            (0, chai_1.expect)(signed).to.have.property('signature');
            (0, chai_1.expect)(signed).to.have.property('issuedAt');
            (0, chai_1.expect)(signed.credential.birthYear).to.equal(birthYear);
            (0, chai_1.expect)(signed.signature).to.be.a('string');
            (0, chai_1.expect)(signed.signature).to.have.lengthOf(64); // SHA256 hex
        });
        it('should issue credentials with unique IDs', async () => {
            const signed1 = await issuer.issueCredential(1990);
            const signed2 = await issuer.issueCredential(1990);
            (0, chai_1.expect)(signed1.credential.id).to.not.equal(signed2.credential.id);
        });
        it('should issue credentials for different birth years', async () => {
            const signed1 = await issuer.issueCredential(1980);
            const signed2 = await issuer.issueCredential(1990);
            const signed3 = await issuer.issueCredential(2000);
            (0, chai_1.expect)(signed1.credential.birthYear).to.equal(1980);
            (0, chai_1.expect)(signed2.credential.birthYear).to.equal(1990);
            (0, chai_1.expect)(signed3.credential.birthYear).to.equal(2000);
        });
        it('should include userId in audit log when provided', async () => {
            const userId = 'user123';
            const signed = await issuer.issueCredential(1990, userId);
            (0, chai_1.expect)(signed).to.be.ok;
            // Audit logging tested separately
        });
        it('should handle current year birth date', async () => {
            const currentYear = new Date().getFullYear();
            const signed = await issuer.issueCredential(currentYear);
            (0, chai_1.expect)(signed.credential.birthYear).to.equal(currentYear);
        });
    });
    describe('verifySignature', () => {
        it('should verify a valid signature', async () => {
            const signed = await issuer.issueCredential(1990);
            // Get the signing key from the issuer config (in production this would be separate)
            const signingKey = issuer.config.signingKey;
            const isValid = issuer_1.CredentialIssuer.verifySignature(signed, signingKey);
            (0, chai_1.expect)(isValid).to.be.true;
        });
        it('should reject an invalid signature', async () => {
            const signed = await issuer.issueCredential(1990);
            // Tamper with the signature
            const tamperedSigned = {
                ...signed,
                signature: 'invalid_signature_12345678901234567890123456789012345678901234',
            };
            const signingKey = issuer.config.signingKey;
            const isValid = issuer_1.CredentialIssuer.verifySignature(tamperedSigned, signingKey);
            (0, chai_1.expect)(isValid).to.be.false;
        });
        it('should reject with wrong signing key', async () => {
            const signed = await issuer.issueCredential(1990);
            const wrongKey = 'wrong_key_1234567890abcdef1234567890abcdef12345678';
            const isValid = issuer_1.CredentialIssuer.verifySignature(signed, wrongKey);
            (0, chai_1.expect)(isValid).to.be.false;
        });
        it('should reject if credential is modified', async () => {
            const signed = await issuer.issueCredential(1990);
            // Modify the credential commitment
            const modifiedSigned = {
                ...signed,
                credential: {
                    ...signed.credential,
                    commitment: 'modified_commitment',
                },
            };
            const signingKey = issuer.config.signingKey;
            const isValid = issuer_1.CredentialIssuer.verifySignature(modifiedSigned, signingKey);
            (0, chai_1.expect)(isValid).to.be.false;
        });
    });
    describe('createTestIssuer', () => {
        it('should create an issuer with name', () => {
            const testIssuer = issuer_1.CredentialIssuer.createTestIssuer('Test Authority');
            (0, chai_1.expect)(testIssuer).to.be.instanceOf(issuer_1.CredentialIssuer);
        });
        it('should create issuers with different keys', () => {
            const issuer1 = issuer_1.CredentialIssuer.createTestIssuer('Authority 1');
            const issuer2 = issuer_1.CredentialIssuer.createTestIssuer('Authority 2');
            const publicKey1 = issuer1.config.publicKey;
            const publicKey2 = issuer2.config.publicKey;
            (0, chai_1.expect)(publicKey1).to.not.equal(publicKey2);
        });
        it('should create issuers that can issue credentials', async () => {
            const testIssuer = issuer_1.CredentialIssuer.createTestIssuer('Test Authority');
            const signed = await testIssuer.issueCredential(1995);
            (0, chai_1.expect)(signed.issuer).to.equal('Test Authority');
            (0, chai_1.expect)(signed.credential.birthYear).to.equal(1995);
        });
    });
    describe('Integration Tests', () => {
        it('should issue and verify credential end-to-end', async () => {
            const birthYear = 1985;
            const userId = 'user456';
            // Issue credential
            const signed = await issuer.issueCredential(birthYear, userId);
            // Verify signature
            const signingKey = issuer.config.signingKey;
            const isValid = issuer_1.CredentialIssuer.verifySignature(signed, signingKey);
            (0, chai_1.expect)(isValid).to.be.true;
            (0, chai_1.expect)(signed.credential.birthYear).to.equal(birthYear);
        });
        it('should handle multiple issuers independently', async () => {
            const issuer1 = issuer_1.CredentialIssuer.createTestIssuer('Issuer 1');
            const issuer2 = issuer_1.CredentialIssuer.createTestIssuer('Issuer 2');
            const signed1 = await issuer1.issueCredential(1990);
            const signed2 = await issuer2.issueCredential(1990);
            const signingKey1 = issuer1.config.signingKey;
            const signingKey2 = issuer2.config.signingKey;
            // Each issuer can verify their own credentials
            (0, chai_1.expect)(issuer_1.CredentialIssuer.verifySignature(signed1, signingKey1)).to.be.true;
            (0, chai_1.expect)(issuer_1.CredentialIssuer.verifySignature(signed2, signingKey2)).to.be.true;
            // But not each other's credentials
            (0, chai_1.expect)(issuer_1.CredentialIssuer.verifySignature(signed1, signingKey2)).to.be.false;
            (0, chai_1.expect)(issuer_1.CredentialIssuer.verifySignature(signed2, signingKey1)).to.be.false;
        });
    });
});
