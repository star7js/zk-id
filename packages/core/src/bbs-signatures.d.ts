declare module '@digitalbazaar/bbs-signatures' {
  export function generateKeyPair(opts: {
    ciphersuite?: string;
    seed?: Uint8Array;
  }): Promise<{ secretKey: Uint8Array; publicKey: Uint8Array }>;

  export function secretKeyToPublicKey(opts: {
    secretKey: Uint8Array;
    ciphersuite?: string;
  }): Promise<Uint8Array>;

  export function sign(opts: {
    secretKey: Uint8Array;
    publicKey?: Uint8Array;
    header: Uint8Array;
    messages: Uint8Array[];
    ciphersuite?: string;
  }): Promise<Uint8Array>;

  export function verifySignature(opts: {
    publicKey: Uint8Array;
    signature: Uint8Array;
    header: Uint8Array;
    messages: Uint8Array[];
    ciphersuite?: string;
  }): Promise<boolean>;

  export function deriveProof(opts: {
    publicKey: Uint8Array;
    signature: Uint8Array;
    header: Uint8Array;
    messages: Uint8Array[];
    presentationHeader: Uint8Array;
    disclosedMessageIndexes: number[];
    ciphersuite?: string;
  }): Promise<Uint8Array>;

  export function verifyProof(opts: {
    publicKey: Uint8Array;
    proof: Uint8Array;
    header: Uint8Array;
    presentationHeader: Uint8Array;
    disclosedMessages: Uint8Array[];
    disclosedMessageIndexes: number[];
    ciphersuite?: string;
  }): Promise<boolean>;

  export const CIPHERSUITES: {
    BLS12381_SHA256: string;
    BLS12381_SHAKE256: string;
  };
}
