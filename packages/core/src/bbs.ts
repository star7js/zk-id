/**
 * BBS+ Selective Disclosure
 *
 * Implements BBS signatures (IETF draft-irtf-cfrg-bbs-signatures) for
 * selective disclosure of credential fields.  Unlike ZK-SNARK proofs
 * which prove *predicates* about hidden values (e.g. "age >= 18"),
 * BBS proofs let a holder *reveal specific fields* from a signed
 * credential while keeping others hidden — without interaction with
 * the issuer.
 *
 * Uses @digitalbazaar/bbs-signatures (BLS12-381-SHA-256 ciphersuite).
 *
 * Typical flow:
 *   1. Issuer generates BBS key pair
 *   2. Issuer signs credential fields as ordered BBS messages
 *   3. Holder derives a disclosure proof revealing only selected fields
 *   4. Verifier checks the proof against the issuer's public key
 */

import { ZkIdProofError, ZkIdCredentialError } from './errors';
import type { BBSCredentialSchema, SerializedBBSCredential } from './bbs-schema';

// ---------------------------------------------------------------------------
// Lazy loader for ESM-only @digitalbazaar/bbs-signatures
// ---------------------------------------------------------------------------

interface BBSLib {
  generateKeyPair(opts: {
    ciphersuite: string;
  }): Promise<{ secretKey: Uint8Array; publicKey: Uint8Array }>;
  sign(opts: {
    secretKey: Uint8Array;
    publicKey: Uint8Array;
    header: Uint8Array;
    messages: Uint8Array[];
    ciphersuite: string;
  }): Promise<Uint8Array>;
  verifySignature(opts: {
    publicKey: Uint8Array;
    signature: Uint8Array;
    header: Uint8Array;
    messages: Uint8Array[];
    ciphersuite: string;
  }): Promise<boolean>;
  deriveProof(opts: {
    publicKey: Uint8Array;
    signature: Uint8Array;
    header: Uint8Array;
    messages: Uint8Array[];
    presentationHeader: Uint8Array;
    disclosedMessageIndexes: number[];
    ciphersuite: string;
  }): Promise<Uint8Array>;
  verifyProof(opts: {
    publicKey: Uint8Array;
    proof: Uint8Array;
    header: Uint8Array;
    presentationHeader: Uint8Array;
    disclosedMessages: Uint8Array[];
    disclosedMessageIndexes: number[];
    ciphersuite: string;
  }): Promise<boolean>;
}

let _bbs: BBSLib | null = null;

async function loadBBS(): Promise<BBSLib> {
  if (_bbs) return _bbs;
  _bbs = (await import('@digitalbazaar/bbs-signatures')) as unknown as BBSLib;
  return _bbs;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

export const BBS_CIPHERSUITE = 'BLS12-381-SHA-256';

/**
 * Standard field order for BBS credential messages.
 * Every BBS credential uses this canonical ordering so that issuers,
 * holders, and verifiers agree on which index maps to which field.
 */
export const BBS_CREDENTIAL_FIELDS = [
  'id',
  'birthYear',
  'nationality',
  'salt',
  'issuedAt',
  'issuer',
] as const;

export type BBSFieldName = (typeof BBS_CREDENTIAL_FIELDS)[number];

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface BBSKeyPair {
  secretKey: Uint8Array;
  publicKey: Uint8Array;
}

/**
 * A credential whose fields are individually signed with BBS.
 * The holder possesses the full credential (all messages + signature)
 * and can derive selective disclosure proofs from it.
 */
export interface BBSCredential {
  /** Unique credential identifier */
  id: string;
  /** Ordered BBS messages (one per field) */
  messages: Uint8Array[];
  /** Field labels matching each message index */
  labels: readonly string[];
  /** BBS signature over all messages */
  signature: Uint8Array;
  /** Header bound into the signature (may be empty) */
  header: Uint8Array;
  /** Issuer's BBS public key */
  issuerPublicKey: Uint8Array;
  /** Human-readable field values (for holder reference) */
  fieldValues: Record<string, string | number>;
  /** Optional schema identifier for schema-aware credentials */
  schemaId?: string;
}

/**
 * A selective disclosure request specifying which fields to reveal.
 */
export interface BBSDisclosureRequest {
  /** Field names to disclose (must be a subset of BBS_CREDENTIAL_FIELDS) */
  disclose: BBSFieldName[];
  /** Optional nonce from verifier to bind to this presentation */
  nonce?: string;
}

/**
 * A BBS selective disclosure proof sent to a verifier.
 * Contains only the revealed fields — hidden fields are cryptographically
 * concealed inside the proof.
 */
export interface BBSDisclosureProof {
  /** BBS proof bytes */
  proof: Uint8Array;
  /** Mapping from field index → revealed message */
  disclosedMessages: Map<number, Uint8Array>;
  /** Mapping from field index → field label */
  disclosedLabels: Map<number, string>;
  /** Indices of disclosed messages */
  disclosedIndexes: number[];
  /** Presentation header (contains nonce if provided) */
  presentationHeader: Uint8Array;
  /** Header from original signature */
  header: Uint8Array;
  /** Issuer's BBS public key */
  issuerPublicKey: Uint8Array;
  /** Total number of messages in the credential */
  messageCount: number;
  /** Optional schema identifier for schema-aware proofs */
  schemaId?: string;
  /** Field names that were revealed (for schema-aware proofs) */
  revealedFieldNames?: string[];
}

/**
 * Serializable form of BBSDisclosureProof for transport (JSON-safe).
 */
export interface SerializedBBSDisclosureProof {
  proof: string; // base64
  disclosedMessages: Record<string, string>; // label → decoded value
  disclosedIndexes: number[];
  presentationHeader: string; // base64
  header: string; // base64
  issuerPublicKey: string; // base64
  messageCount: number;
}

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/** Encode a value as a BBS message (Uint8Array). */
export function encodeBBSMessage(value: string | number | bigint): Uint8Array {
  return encoder.encode(String(value));
}

/** Decode a BBS message back to its string representation. */
export function decodeBBSMessage(message: Uint8Array): string {
  return decoder.decode(message);
}

// ---------------------------------------------------------------------------
// Key generation
// ---------------------------------------------------------------------------

/** Generate a BBS key pair for credential issuance. */
export async function generateBBSKeyPair(): Promise<BBSKeyPair> {
  const bbs = await loadBBS();
  const { secretKey, publicKey } = await bbs.generateKeyPair({
    ciphersuite: BBS_CIPHERSUITE,
  });
  return { secretKey, publicKey };
}

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

/**
 * Sign an ordered array of messages with BBS.
 * Returns the raw BBS signature.
 */
export async function signBBSMessages(
  secretKey: Uint8Array,
  publicKey: Uint8Array,
  messages: Uint8Array[],
  header: Uint8Array = new Uint8Array(),
): Promise<Uint8Array> {
  const bbs = await loadBBS();
  return bbs.sign({
    secretKey,
    publicKey,
    header,
    messages,
    ciphersuite: BBS_CIPHERSUITE,
  });
}

/**
 * Verify a BBS signature against all original messages.
 */
export async function verifyBBSSignature(
  publicKey: Uint8Array,
  signature: Uint8Array,
  messages: Uint8Array[],
  header: Uint8Array = new Uint8Array(),
): Promise<boolean> {
  const bbs = await loadBBS();
  return bbs.verifySignature({
    publicKey,
    signature,
    header,
    messages,
    ciphersuite: BBS_CIPHERSUITE,
  });
}

// ---------------------------------------------------------------------------
// Selective disclosure proof
// ---------------------------------------------------------------------------

/**
 * Derive a selective disclosure proof from a BBS credential.
 *
 * @param credential - Full BBS credential (held by the holder)
 * @param request    - Disclosure request specifying which fields to reveal
 * @returns A proof that reveals only the requested fields
 */
export async function deriveBBSDisclosureProof(
  credential: BBSCredential,
  request: BBSDisclosureRequest,
): Promise<BBSDisclosureProof> {
  const bbs = await loadBBS();

  // Map field names → indices (use credential labels for schema-aware credentials)
  const disclosedIndexes = request.disclose
    .map((name) => credential.labels.indexOf(name))
    .filter((i) => i >= 0)
    .sort((a, b) => a - b);

  if (disclosedIndexes.length === 0) {
    throw new ZkIdProofError('No valid fields specified for disclosure');
  }

  const presentationHeader = request.nonce ? encoder.encode(request.nonce) : new Uint8Array();

  const proof = await bbs.deriveProof({
    publicKey: credential.issuerPublicKey,
    signature: credential.signature,
    header: credential.header,
    messages: credential.messages,
    presentationHeader,
    disclosedMessageIndexes: disclosedIndexes,
    ciphersuite: BBS_CIPHERSUITE,
  });

  const disclosedMessages = new Map<number, Uint8Array>();
  const disclosedLabels = new Map<number, string>();
  for (const idx of disclosedIndexes) {
    disclosedMessages.set(idx, credential.messages[idx]);
    disclosedLabels.set(idx, credential.labels[idx]);
  }

  return {
    proof,
    disclosedMessages,
    disclosedLabels,
    disclosedIndexes,
    presentationHeader,
    header: credential.header,
    issuerPublicKey: credential.issuerPublicKey,
    messageCount: credential.messages.length,
  };
}

/**
 * Verify a BBS selective disclosure proof.
 *
 * @returns true if the proof is valid (disclosed fields match a valid signature)
 */
export async function verifyBBSDisclosureProof(
  disclosureProof: BBSDisclosureProof,
): Promise<boolean> {
  const bbs = await loadBBS();

  const disclosedMessages: Uint8Array[] = disclosureProof.disclosedIndexes.map(
    (idx) => disclosureProof.disclosedMessages.get(idx)!,
  );

  return bbs.verifyProof({
    publicKey: disclosureProof.issuerPublicKey,
    proof: disclosureProof.proof,
    header: disclosureProof.header,
    presentationHeader: disclosureProof.presentationHeader,
    disclosedMessages,
    disclosedMessageIndexes: disclosureProof.disclosedIndexes,
    ciphersuite: BBS_CIPHERSUITE,
  });
}

// ---------------------------------------------------------------------------
// Serialization helpers
// ---------------------------------------------------------------------------

/** Serialize a disclosure proof for JSON transport. */
export function serializeBBSProof(proof: BBSDisclosureProof): SerializedBBSDisclosureProof {
  const disclosedMessages: Record<string, string> = {};
  for (const idx of proof.disclosedIndexes) {
    const label = proof.disclosedLabels.get(idx)!;
    const value = decodeBBSMessage(proof.disclosedMessages.get(idx)!);
    disclosedMessages[label] = value;
  }

  return {
    proof: Buffer.from(proof.proof).toString('base64'),
    disclosedMessages,
    disclosedIndexes: proof.disclosedIndexes,
    presentationHeader: Buffer.from(proof.presentationHeader).toString('base64'),
    header: Buffer.from(proof.header).toString('base64'),
    issuerPublicKey: Buffer.from(proof.issuerPublicKey).toString('base64'),
    messageCount: proof.messageCount,
  };
}

/** Deserialize a disclosure proof from JSON transport. */
export function deserializeBBSProof(serialized: SerializedBBSDisclosureProof): BBSDisclosureProof {
  const disclosedMessages = new Map<number, Uint8Array>();
  const disclosedLabels = new Map<number, string>();

  for (const idx of serialized.disclosedIndexes) {
    const label = BBS_CREDENTIAL_FIELDS[idx];
    const value = serialized.disclosedMessages[label];
    disclosedLabels.set(idx, label);
    disclosedMessages.set(idx, encoder.encode(value));
  }

  return {
    proof: new Uint8Array(Buffer.from(serialized.proof, 'base64')),
    disclosedMessages,
    disclosedLabels,
    disclosedIndexes: serialized.disclosedIndexes,
    presentationHeader: new Uint8Array(Buffer.from(serialized.presentationHeader, 'base64')),
    header: new Uint8Array(Buffer.from(serialized.header, 'base64')),
    issuerPublicKey: new Uint8Array(Buffer.from(serialized.issuerPublicKey, 'base64')),
    messageCount: serialized.messageCount,
  };
}

// ---------------------------------------------------------------------------
// Credential field helpers
// ---------------------------------------------------------------------------

/**
 * Convert credential field values to an ordered array of BBS messages
 * following the canonical BBS_CREDENTIAL_FIELDS order.
 */
export function credentialFieldsToBBSMessages(fields: Record<string, string | number>): {
  messages: Uint8Array[];
  labels: readonly string[];
} {
  const messages = BBS_CREDENTIAL_FIELDS.map((name) => {
    const value = fields[name];
    if (value === undefined) {
      throw new ZkIdCredentialError(`Missing required credential field: ${name}`);
    }
    return encodeBBSMessage(value);
  });
  return { messages, labels: BBS_CREDENTIAL_FIELDS };
}

/**
 * Extract the revealed field values from a disclosure proof as a
 * human-readable record.
 */
export function getDisclosedFields(proof: BBSDisclosureProof): Record<string, string> {
  const result: Record<string, string> = {};
  for (const idx of proof.disclosedIndexes) {
    const label = proof.disclosedLabels.get(idx);
    const message = proof.disclosedMessages.get(idx);
    if (label && message) {
      result[label] = decodeBBSMessage(message);
    }
  }
  return result;
}

// ---------------------------------------------------------------------------
// Schema-aware BBS+ functions
// ---------------------------------------------------------------------------

/**
 * Convert arbitrary schema fields to BBS messages with deterministic ordering.
 * Fields are sorted alphabetically by name to ensure reproducible proofs.
 *
 * @param fields - Field values as key-value pairs
 * @param schema - Credential schema defining field structure
 * @returns Ordered array of BBS messages and corresponding labels
 */
export function schemaFieldsToBBSMessages(
  fields: Record<string, unknown>,
  schema: BBSCredentialSchema,
): {
  messages: Uint8Array[];
  labels: string[];
} {
  // Sort field names alphabetically for deterministic ordering
  const sortedFieldNames = schema.fields.map((f) => f.name).sort();

  const messages: Uint8Array[] = [];
  const labels: string[] = [];

  for (const fieldName of sortedFieldNames) {
    const value = fields[fieldName];
    if (value === undefined) {
      const fieldDef = schema.fields.find((f) => f.name === fieldName);
      if (fieldDef?.required) {
        throw new ZkIdCredentialError(`Missing required field: ${fieldName}`);
      }
      // Skip optional missing fields
      continue;
    }

    messages.push(encodeBBSMessage(value as string | number));
    labels.push(fieldName);
  }

  return { messages, labels };
}

/**
 * Sign a schema-aware BBS credential.
 *
 * @param fields - Field values matching the schema
 * @param schema - Credential schema
 * @param secretKey - Issuer's BBS secret key
 * @param publicKey - Issuer's BBS public key
 * @param header - Optional header bytes
 * @returns Signed BBS credential
 */
export async function signBBSSchemaCredential(
  fields: Record<string, unknown>,
  schema: BBSCredentialSchema,
  secretKey: Uint8Array,
  publicKey: Uint8Array,
  header: Uint8Array = new Uint8Array(),
): Promise<BBSCredential> {
  const { messages, labels } = schemaFieldsToBBSMessages(fields, schema);

  const signature = await signBBSMessages(secretKey, publicKey, messages, header);

  // Extract id field (required in all schemas)
  const id = String(fields.id || `cred-${Date.now()}`);

  return {
    id,
    messages,
    labels,
    signature,
    header,
    issuerPublicKey: publicKey,
    fieldValues: fields as Record<string, string | number>,
    schemaId: schema.id,
  };
}

/**
 * Derive a selective disclosure proof from a schema-aware BBS credential.
 *
 * @param credential - Full BBS credential
 * @param schema - Credential schema
 * @param revealedFieldNames - Field names to reveal
 * @param nonce - Optional nonce from verifier
 * @returns Selective disclosure proof
 */
export async function deriveBBSSchemaDisclosureProof(
  credential: BBSCredential,
  schema: BBSCredentialSchema,
  revealedFieldNames: string[],
  nonce?: string,
): Promise<BBSDisclosureProof> {
  const bbs = await loadBBS();

  // Map field names to indices based on credential labels
  const disclosedIndexes = revealedFieldNames
    .map((name) => credential.labels.indexOf(name))
    .filter((i) => i >= 0)
    .sort((a, b) => a - b);

  if (disclosedIndexes.length === 0) {
    throw new ZkIdProofError('No valid fields specified for disclosure');
  }

  const presentationHeader = nonce ? encoder.encode(nonce) : new Uint8Array();

  const proof = await bbs.deriveProof({
    publicKey: credential.issuerPublicKey,
    signature: credential.signature,
    header: credential.header,
    messages: credential.messages,
    presentationHeader,
    disclosedMessageIndexes: disclosedIndexes,
    ciphersuite: BBS_CIPHERSUITE,
  });

  const disclosedMessages = new Map<number, Uint8Array>();
  const disclosedLabels = new Map<number, string>();
  for (const idx of disclosedIndexes) {
    disclosedMessages.set(idx, credential.messages[idx]);
    disclosedLabels.set(idx, credential.labels[idx]);
  }

  return {
    proof,
    disclosedMessages,
    disclosedLabels,
    disclosedIndexes,
    presentationHeader,
    header: credential.header,
    issuerPublicKey: credential.issuerPublicKey,
    messageCount: credential.messages.length,
    schemaId: schema.id,
    revealedFieldNames,
  };
}

/**
 * Verify a schema-aware BBS selective disclosure proof.
 *
 * @param disclosureProof - Proof to verify
 * @param schema - Credential schema
 * @returns true if the proof is valid
 */
export async function verifyBBSSchemaDisclosureProof(
  disclosureProof: BBSDisclosureProof,
  schema: BBSCredentialSchema,
): Promise<boolean> {
  // Verify schema ID matches
  if (disclosureProof.schemaId && disclosureProof.schemaId !== schema.id) {
    throw new ZkIdProofError(
      `Schema mismatch: expected ${schema.id}, got ${disclosureProof.schemaId}`,
    );
  }

  // Use the standard BBS verification
  return verifyBBSDisclosureProof(disclosureProof);
}

/**
 * Serialize a BBS credential for storage or transmission.
 *
 * @param credential - BBS credential to serialize
 * @returns JSON-serializable credential
 */
export function serializeBBSCredential(credential: BBSCredential): SerializedBBSCredential {
  const schemaId = credential.schemaId || 'age-verification';

  // Determine issuer from fieldValues if available
  const issuer = String(credential.fieldValues.issuer || 'unknown');
  const issuedAt = String(credential.fieldValues.issuedAt || new Date().toISOString());
  const expiresAt = credential.fieldValues.expiresAt
    ? String(credential.fieldValues.expiresAt)
    : undefined;

  return {
    schemaId,
    fields: credential.fieldValues,
    signature: Buffer.from(credential.signature).toString('base64'),
    publicKey: Buffer.from(credential.issuerPublicKey).toString('base64'),
    issuer,
    issuedAt,
    expiresAt,
  };
}

/**
 * Deserialize a BBS credential from storage or transmission.
 *
 * @param serialized - Serialized credential
 * @param schema - Credential schema
 * @returns Reconstructed BBS credential
 */
export function deserializeBBSCredential(
  serialized: SerializedBBSCredential,
  schema: BBSCredentialSchema,
): BBSCredential {
  // Verify schema ID matches
  if (serialized.schemaId !== schema.id) {
    throw new ZkIdCredentialError(
      `Schema mismatch: expected ${schema.id}, got ${serialized.schemaId}`,
    );
  }

  const { messages, labels } = schemaFieldsToBBSMessages(serialized.fields, schema);

  const id = String(serialized.fields.id || `cred-${Date.now()}`);

  return {
    id,
    messages,
    labels,
    signature: new Uint8Array(Buffer.from(serialized.signature, 'base64')),
    header: new Uint8Array(), // Default empty header
    issuerPublicKey: new Uint8Array(Buffer.from(serialized.publicKey, 'base64')),
    fieldValues: serialized.fields as Record<string, string | number>,
    schemaId: serialized.schemaId,
  };
}
