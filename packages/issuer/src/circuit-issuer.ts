import { createCredential, Credential, CircuitSignatureInputs } from '@zk-id/core';
import { randomBytes } from 'crypto';
import { buildEddsa } from 'circomlibjs';
import { Scalar } from 'ffjavascript';

export interface CircuitSignedCredential {
  credential: Credential;
  issuer: string;
  issuerPublicKey: string[];
  signature: {
    R8: string[];
    S: string[];
  };
  issuedAt: string;
}

function bytesToBitsLE(bytes: Uint8Array): string[] {
  const bits: string[] = [];
  for (const byte of bytes) {
    for (let i = 0; i < 8; i++) {
      bits.push(((byte >> i) & 1).toString());
    }
  }
  return bits;
}

function bigintToBytesLE(value: bigint, length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  let v = value;
  for (let i = 0; i < length; i++) {
    bytes[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return bytes;
}

/** Typed interface for the circomlibjs EdDSA instance. */
interface EdDSA {
  prv2pub(privateKey: Uint8Array): [Uint8Array, Uint8Array];
  signPedersen(privateKey: Uint8Array, msg: Uint8Array): { R8: [Uint8Array, Uint8Array]; S: bigint };
  babyJub: { packPoint(point: [Uint8Array, Uint8Array]): Uint8Array };
}

export class CircuitCredentialIssuer {
  private issuerName: string;
  private eddsa: EdDSA;
  private privateKey: Uint8Array;
  private publicKey: [Uint8Array, Uint8Array];
  private publicKeyBits: string[];

  private constructor(issuerName: string, eddsa: EdDSA, privateKey: Uint8Array) {
    this.issuerName = issuerName;
    this.eddsa = eddsa;
    this.privateKey = privateKey;
    this.publicKey = eddsa.prv2pub(privateKey);
    const packed = eddsa.babyJub.packPoint(this.publicKey);
    this.publicKeyBits = bytesToBitsLE(packed);
  }

  static async createTestIssuer(name: string): Promise<CircuitCredentialIssuer> {
    const eddsa = await buildEddsa();
    const privateKey = randomBytes(32);
    return new CircuitCredentialIssuer(name, eddsa, privateKey);
  }

  getIssuerName(): string {
    return this.issuerName;
  }

  getIssuerPublicKeyBits(): string[] {
    return this.publicKeyBits;
  }

  async issueCredential(
    birthYear: number,
    nationality: number
  ): Promise<CircuitSignedCredential> {
    const credential = await createCredential(birthYear, nationality);
    const commitment = BigInt(credential.commitment);
    const msgBytes = bigintToBytesLE(commitment, 32);
    const signature = this.eddsa.signPedersen(this.privateKey, msgBytes);

    const R8packed = this.eddsa.babyJub.packPoint(signature.R8);
    const Sbytes = new Uint8Array(32);
    Scalar.toRprLE(Sbytes, 0, signature.S, 32);

    const signatureBits = {
      R8: bytesToBitsLE(R8packed),
      S: bytesToBitsLE(Sbytes),
    };

    return {
      credential,
      issuer: this.issuerName,
      issuerPublicKey: this.publicKeyBits,
      signature: signatureBits,
      issuedAt: new Date().toISOString(),
    };
  }

  getSignatureInputs(signed: CircuitSignedCredential): CircuitSignatureInputs {
    return {
      issuerPublicKey: signed.issuerPublicKey,
      signatureR8: signed.signature.R8,
      signatureS: signed.signature.S,
    };
  }
}
