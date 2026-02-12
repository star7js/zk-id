/**
 * BBS+ Credential Schema System
 *
 * Provides a flexible schema system for BBS+ credentials, allowing arbitrary field definitions
 * while maintaining deterministic proof generation and verification.
 */

/**
 * Field type definitions for BBS+ credentials
 */
export type BBSFieldType = 'string' | 'number' | 'boolean' | 'date';

/**
 * Definition of a single field in a BBS+ credential schema
 */
export interface BBSFieldDefinition {
  /** Field name (must be unique within schema) */
  name: string;
  /** Data type of the field */
  type: BBSFieldType;
  /** Whether this field is required */
  required: boolean;
  /** Human-readable description */
  description?: string;
}

/**
 * A BBS+ credential schema defining structure and fields
 */
export interface BBSCredentialSchema {
  /** Unique schema identifier (e.g., 'age-verification', 'kyc-basic') */
  id: string;
  /** Schema version (semantic versioning) */
  version: string;
  /** Field definitions */
  fields: BBSFieldDefinition[];
  /** Human-readable description */
  description?: string;
}

/**
 * Serialized BBS+ credential for storage and transmission
 */
export interface SerializedBBSCredential {
  /** Schema identifier */
  schemaId: string;
  /** Credential fields as key-value pairs */
  fields: Record<string, string | number | boolean>;
  /** BBS+ signature (base64 encoded) */
  signature: string;
  /** Issuer's BBS+ public key (base64 encoded) */
  publicKey: string;
  /** Issuer identifier */
  issuer: string;
  /** ISO 8601 issuance timestamp */
  issuedAt: string;
  /** Optional ISO 8601 expiration timestamp */
  expiresAt?: string;
}

/**
 * Schema-aware BBS+ disclosure proof metadata (extends the base proof from bbs.ts)
 */
export interface BBSDisclosureProofMetadata {
  /** Schema identifier */
  schemaId: string;
  /** Revealed field names */
  revealedFieldNames: string[];
  /** Revealed field values */
  revealedFields: Record<string, string | number | boolean>;
  /** Nonce used in proof generation */
  nonce: string;
}

/**
 * Age verification schema - backwards compatible with existing 6-field format
 */
export const AGE_VERIFICATION_SCHEMA: BBSCredentialSchema = {
  id: 'age-verification',
  version: '1.0.0',
  description: 'Age verification credential with birth year and nationality (6-field format)',
  fields: [
    {
      name: 'id',
      type: 'string',
      required: true,
      description: 'Unique credential identifier',
    },
    {
      name: 'birthYear',
      type: 'number',
      required: true,
      description: 'Year of birth',
    },
    {
      name: 'nationality',
      type: 'number',
      required: true,
      description: 'ISO 3166-1 numeric country code',
    },
    {
      name: 'salt',
      type: 'string',
      required: true,
      description: 'Random salt for credential uniqueness',
    },
    {
      name: 'issuedAt',
      type: 'string',
      required: true,
      description: 'ISO 8601 issuance timestamp',
    },
    {
      name: 'issuer',
      type: 'string',
      required: true,
      description: 'Issuer identifier',
    },
  ],
};

/**
 * Extended KYC schema with 9 fields for comprehensive identity verification
 */
export const KYC_BASIC_SCHEMA: BBSCredentialSchema = {
  id: 'kyc-basic',
  version: '1.0.0',
  description: 'Basic KYC credential with full date of birth and residence information',
  fields: [
    {
      name: 'id',
      type: 'string',
      required: true,
      description: 'Unique credential identifier',
    },
    {
      name: 'givenName',
      type: 'string',
      required: true,
      description: 'Given name(s) / first name(s)',
    },
    {
      name: 'familyName',
      type: 'string',
      required: true,
      description: 'Family name(s) / surname(s)',
    },
    {
      name: 'birthYear',
      type: 'number',
      required: true,
      description: 'Year of birth',
    },
    {
      name: 'birthMonth',
      type: 'number',
      required: true,
      description: 'Month of birth (1-12)',
    },
    {
      name: 'birthDay',
      type: 'number',
      required: true,
      description: 'Day of birth (1-31)',
    },
    {
      name: 'nationality',
      type: 'string',
      required: true,
      description: 'ISO 3166-1 alpha-2 country code of nationality',
    },
    {
      name: 'countryOfResidence',
      type: 'string',
      required: true,
      description: 'ISO 3166-1 alpha-2 country code of residence',
    },
    {
      name: 'salt',
      type: 'string',
      required: true,
      description: 'Random salt for credential uniqueness',
    },
  ],
};

/**
 * Capability delegation schema for authorization chains
 */
export const CAPABILITY_SCHEMA: BBSCredentialSchema = {
  id: 'capability',
  version: '1.0.0',
  description: 'Capability credential for delegated authorization',
  fields: [
    {
      name: 'id',
      type: 'string',
      required: true,
      description: 'Unique credential identifier',
    },
    {
      name: 'capability',
      type: 'string',
      required: true,
      description: 'Capability identifier (e.g., "read", "write", "admin")',
    },
    {
      name: 'scope',
      type: 'string',
      required: true,
      description: 'Resource scope (e.g., "api:documents", "service:payments")',
    },
    {
      name: 'delegator',
      type: 'string',
      required: true,
      description: 'Identity of the delegating party',
    },
    {
      name: 'delegatee',
      type: 'string',
      required: true,
      description: 'Identity of the receiving party',
    },
    {
      name: 'issuedAt',
      type: 'string',
      required: true,
      description: 'ISO 8601 issuance timestamp',
    },
    {
      name: 'expiresAt',
      type: 'string',
      required: false,
      description: 'ISO 8601 expiration timestamp',
    },
    {
      name: 'salt',
      type: 'string',
      required: true,
      description: 'Random salt for credential uniqueness',
    },
  ],
};

/**
 * AI agent identity schema for autonomous agent verification
 */
export const AGENT_IDENTITY_SCHEMA: BBSCredentialSchema = {
  id: 'agent-identity',
  version: '1.0.0',
  description: 'Identity credential for AI agents with capability attestation',
  fields: [
    {
      name: 'id',
      type: 'string',
      required: true,
      description: 'Unique credential identifier',
    },
    {
      name: 'agentId',
      type: 'string',
      required: true,
      description: 'Unique agent identifier',
    },
    {
      name: 'organizationId',
      type: 'string',
      required: true,
      description: 'Organization that deployed the agent',
    },
    {
      name: 'capabilities',
      type: 'string',
      required: true,
      description: 'JSON-encoded capability list',
    },
    {
      name: 'modelVersion',
      type: 'string',
      required: true,
      description: 'AI model version identifier',
    },
    {
      name: 'salt',
      type: 'string',
      required: true,
      description: 'Random salt for credential uniqueness',
    },
  ],
};

/**
 * Schema registry for managing available BBS+ credential schemas
 */
export class BBSSchemaRegistry {
  private schemas: Map<string, BBSCredentialSchema> = new Map();

  constructor() {
    // Register well-known schemas
    this.register(AGE_VERIFICATION_SCHEMA);
    this.register(KYC_BASIC_SCHEMA);
    this.register(CAPABILITY_SCHEMA);
    this.register(AGENT_IDENTITY_SCHEMA);
  }

  /**
   * Register a new schema
   */
  register(schema: BBSCredentialSchema): void {
    this.schemas.set(schema.id, schema);
  }

  /**
   * Get a schema by ID
   */
  get(id: string): BBSCredentialSchema | undefined {
    return this.schemas.get(id);
  }

  /**
   * List all registered schemas
   */
  list(): BBSCredentialSchema[] {
    return Array.from(this.schemas.values());
  }

  /**
   * Check if a schema exists
   */
  has(id: string): boolean {
    return this.schemas.has(id);
  }

  /**
   * Validate fields against a schema
   */
  validate(
    schemaId: string,
    fields: Record<string, unknown>,
  ): { valid: boolean; errors: string[] } {
    const schema = this.get(schemaId);
    if (!schema) {
      return { valid: false, errors: [`Schema '${schemaId}' not found`] };
    }

    const errors: string[] = [];

    // Check required fields
    for (const fieldDef of schema.fields) {
      if (fieldDef.required && !(fieldDef.name in fields)) {
        errors.push(`Required field '${fieldDef.name}' is missing`);
      }
    }

    // Check field types
    for (const [fieldName, value] of Object.entries(fields)) {
      const fieldDef = schema.fields.find((f) => f.name === fieldName);
      if (!fieldDef) {
        errors.push(`Unknown field '${fieldName}'`);
        continue;
      }

      const actualType = typeof value;
      let expectedType = fieldDef.type;

      // Date fields are stored as strings
      if (fieldDef.type === 'date') {
        expectedType = 'string';
      }

      if (actualType !== expectedType) {
        errors.push(`Field '${fieldName}' has type '${actualType}' but expected '${expectedType}'`);
      }
    }

    return { valid: errors.length === 0, errors };
  }
}

/**
 * Global schema registry instance
 */
export const SCHEMA_REGISTRY = new BBSSchemaRegistry();
