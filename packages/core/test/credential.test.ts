import { expect } from 'chai';
import { createCredential, validateCredential, deriveCommitment } from '../src/credential';

describe('Credential Tests', () => {
  describe('createCredential', () => {
    it('should create a valid credential', async () => {
      const credential = await createCredential(1990, 840);

      expect(credential).to.have.property('id');
      expect(credential).to.have.property('birthYear', 1990);
      expect(credential).to.have.property('nationality', 840);
      expect(credential).to.have.property('salt');
      expect(credential).to.have.property('commitment');
      expect(credential).to.have.property('createdAt');

      expect(credential.id).to.have.lengthOf(32); // 16 bytes hex
      expect(credential.salt).to.have.lengthOf(64); // 32 bytes hex
      expect(credential.commitment).to.be.a('string');
    });

    it('should create unique credentials', async () => {
      const cred1 = await createCredential(1990, 840);
      const cred2 = await createCredential(1990, 840);

      expect(cred1.id).to.not.equal(cred2.id);
      expect(cred1.salt).to.not.equal(cred2.salt);
      expect(cred1.commitment).to.not.equal(cred2.commitment);
    });

    it('should reject invalid birth years', async () => {
      try {
        await createCredential(1800, 840);
        throw new Error('Should have thrown');
      } catch (error: any) {
        expect(error.message).to.include('Invalid birth year');
      }

      try {
        await createCredential(2050, 840);
        throw new Error('Should have thrown');
      } catch (error: any) {
        expect(error.message).to.include('Invalid birth year');
      }
    });

    it('should reject invalid nationality codes', async () => {
      try {
        await createCredential(1990, 0);
        throw new Error('Should have thrown');
      } catch (error: any) {
        expect(error.message).to.include('Invalid nationality code');
      }

      try {
        await createCredential(1990, 1000);
        throw new Error('Should have thrown');
      } catch (error: any) {
        expect(error.message).to.include('Invalid nationality code');
      }
    });

    it('should handle current year', async () => {
      const currentYear = new Date().getFullYear();
      const credential = await createCredential(currentYear, 840);
      expect(credential.birthYear).to.equal(currentYear);
    });

    it('should create different commitments for different nationalities', async () => {
      const cred1 = await createCredential(1990, 840); // USA
      const cred2 = await createCredential(1990, 826); // UK

      expect(cred1.commitment).to.not.equal(cred2.commitment);
    });
  });

  describe('validateCredential', () => {
    it('should validate a good credential', async () => {
      const credential = await createCredential(1995, 840);
      expect(validateCredential(credential)).to.be.true;
    });

    it('should reject credential with missing fields', async () => {
      const credential = await createCredential(1995, 840);

      const noId = { ...credential, id: '' };
      expect(validateCredential(noId)).to.be.false;

      const noSalt = { ...credential, salt: '' };
      expect(validateCredential(noSalt)).to.be.false;

      const noCommitment = { ...credential, commitment: '' };
      expect(validateCredential(noCommitment)).to.be.false;
    });

    it('should reject credential with invalid birth year', async () => {
      const credential = await createCredential(1995, 840);

      const invalid1 = { ...credential, birthYear: 1800 };
      expect(validateCredential(invalid1)).to.be.false;

      const invalid2 = { ...credential, birthYear: 2100 };
      expect(validateCredential(invalid2)).to.be.false;
    });

    it('should reject credential with invalid nationality', async () => {
      const credential = await createCredential(1995, 840);

      const invalid1 = { ...credential, nationality: 0 };
      expect(validateCredential(invalid1)).to.be.false;

      const invalid2 = { ...credential, nationality: 1000 };
      expect(validateCredential(invalid2)).to.be.false;
    });
  });

  describe('deriveCommitment', () => {
    it('should derive same commitment for same inputs', async () => {
      const birthYear = 1990;
      const nationality = 840;
      const salt = '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef';

      const commitment1 = await deriveCommitment(birthYear, nationality, salt);
      const commitment2 = await deriveCommitment(birthYear, nationality, salt);

      expect(commitment1).to.equal(commitment2);
    });

    it('should derive different commitments for different birth years', async () => {
      const nationality = 840;
      const salt = '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef';

      const commitment1 = await deriveCommitment(1990, nationality, salt);
      const commitment2 = await deriveCommitment(1991, nationality, salt);

      expect(commitment1).to.not.equal(commitment2);
    });

    it('should derive different commitments for different nationalities', async () => {
      const birthYear = 1990;
      const salt = '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef';

      const commitment1 = await deriveCommitment(birthYear, 840, salt);
      const commitment2 = await deriveCommitment(birthYear, 826, salt);

      expect(commitment1).to.not.equal(commitment2);
    });

    it('should derive different commitments for different salts', async () => {
      const birthYear = 1990;
      const nationality = 840;

      const commitment1 = await deriveCommitment(birthYear, nationality, 'aaaa');
      const commitment2 = await deriveCommitment(birthYear, nationality, 'bbbb');

      expect(commitment1).to.not.equal(commitment2);
    });

    it('should match commitment in created credential', async () => {
      const credential = await createCredential(1990, 840);
      const derived = await deriveCommitment(
        credential.birthYear,
        credential.nationality,
        credential.salt
      );

      expect(derived).to.equal(credential.commitment);
    });
  });
});
