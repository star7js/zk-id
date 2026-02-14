/**
 * OpenID4VP adapter for mobile wallets
 *
 * Handles deep links, presentation generation, and submission
 * without any DOM/fetch dependencies (all I/O is injected).
 */

import type { MobileWallet } from './mobile-wallet.js';
import type { ProofResponse } from '@zk-id/core';

/**
 * HTTP adapter interface for platform-agnostic HTTP requests.
 *
 * Implementations:
 * - React Native: fetch (built-in)
 * - Node.js: node-fetch or undici
 * - Expo: fetch (built-in)
 */
export interface HttpAdapter {
  post(url: string, body: unknown, headers?: Record<string, string>): Promise<HttpResponse>;
  get(url: string, headers?: Record<string, string>): Promise<HttpResponse>;
}

export interface HttpResponse {
  ok: boolean;
  status: number;
  statusText: string;
  json(): Promise<unknown>;
  text(): Promise<string>;
}

/**
 * OpenID4VP Authorization Request
 */
export interface AuthorizationRequest {
  presentation_definition?: PresentationDefinition;
  dcql_query?: DCQLQuery;
  response_type?: string;
  response_mode?: string;
  response_uri: string;
  nonce: string;
  client_id: string;
  state?: string;
}

/**
 * Digital Credentials Query Language (DCQL) query
 */
export interface DCQLQuery {
  id: string;
  credentials: DCQLCredentialQuery[];
  name?: string;
  purpose?: string;
}

export interface DCQLCredentialQuery {
  id: string;
  type: string[];
  claims?: DCQLClaimsConstraint[];
  issuer?: string | string[];
  format?: string;
}

export interface DCQLClaimsConstraint {
  path: string;
  filter?: Record<string, unknown>;
  sd?: boolean;
}

export interface PresentationDefinition {
  id: string;
  name?: string;
  purpose?: string;
  input_descriptors: InputDescriptor[];
}

export interface InputDescriptor {
  id: string;
  name?: string;
  purpose?: string;
  constraints?: {
    fields?: Array<{
      path: string[];
      filter?: Record<string, unknown>;
    }>;
  };
}

/**
 * OpenID4VP Presentation Response
 */
export interface PresentationResponse {
  vp_token: string; // Base64-encoded W3C Verifiable Presentation
  presentation_submission: PresentationSubmission;
  state?: string;
}

export interface PresentationSubmission {
  id: string;
  definition_id: string;
  descriptor_map: DescriptorMapEntry[];
}

export interface DescriptorMapEntry {
  id: string;
  format: string;
  path: string;
}

/**
 * Parse an OpenID4VP authorization request from a deep link URL
 *
 * @param url - Deep link URL (e.g., openid4vp://?presentation_definition=...)
 * @returns Parsed authorization request
 */
export function parseAuthorizationRequest(url: string): AuthorizationRequest {
  try {
    // Handle both openid4vp:// and https:// schemes
    const urlObj = new URL(url.replace('openid4vp://', 'https://example.com/'));
    const params = urlObj.searchParams;

    // Check for request_uri (not yet supported)
    if (params.has('request_uri')) {
      throw new Error('request_uri (request by reference) is not yet supported');
    }

    // Check for JWT request (not yet supported)
    if (params.has('request')) {
      throw new Error('JWT-encoded requests are not yet supported');
    }

    // Parse presentation definition or DCQL query
    const presentationDefinitionParam = params.get('presentation_definition');
    const dcqlQueryParam = params.get('dcql_query');

    if (!presentationDefinitionParam && !dcqlQueryParam) {
      throw new Error('Missing presentation_definition or dcql_query parameter');
    }

    const authRequest: AuthorizationRequest = {
      response_type: params.get('response_type') || 'vp_token',
      response_mode: params.get('response_mode') || 'direct_post',
      response_uri: params.get('response_uri') || '',
      nonce: params.get('nonce') || '',
      client_id: params.get('client_id') || '',
      state: params.get('state') || undefined,
    };

    // Add presentation definition if present
    if (presentationDefinitionParam) {
      authRequest.presentation_definition = JSON.parse(presentationDefinitionParam);
    }

    // Add DCQL query if present
    if (dcqlQueryParam) {
      authRequest.dcql_query = JSON.parse(dcqlQueryParam);
    }

    return authRequest;
  } catch (error) {
    throw new Error(`Failed to parse authorization request: ${error}`);
  }
}

/**
 * Generate an OpenID4VP presentation response
 *
 * @param authRequest - Authorization request from verifier
 * @param wallet - Mobile wallet instance
 * @returns Presentation response ready to submit
 */
export async function generatePresentation(
  authRequest: AuthorizationRequest,
  wallet: MobileWallet,
): Promise<PresentationResponse> {
  // Analyze presentation definition or DCQL query to determine proof type
  let proofRequest: ProofRequest;
  let definitionId: string;

  if (authRequest.presentation_definition) {
    const inputDescriptor = authRequest.presentation_definition.input_descriptors[0];
    proofRequest = inputDescriptorToProofRequest(inputDescriptor, authRequest.nonce);
    definitionId = authRequest.presentation_definition.id;
  } else if (authRequest.dcql_query) {
    proofRequest = dcqlQueryToProofRequest(authRequest.dcql_query, authRequest.nonce);
    definitionId = authRequest.dcql_query.id;
  } else {
    throw new Error(
      'Authorization request must contain either presentation_definition or dcql_query',
    );
  }

  // Generate proof using wallet
  let proofResponse: ProofResponse;

  if (proofRequest.claimType === 'age' && proofRequest.minAge !== undefined) {
    proofResponse = await wallet.generateAgeProof(null, proofRequest.minAge, authRequest.nonce);
  } else if (proofRequest.claimType === 'nationality' && proofRequest.targetNationality) {
    proofResponse = await wallet.generateNationalityProof(
      null,
      proofRequest.targetNationality,
      authRequest.nonce,
    );
  } else {
    throw new Error(`Unsupported claim type: ${proofRequest.claimType}`);
  }

  // Wrap in W3C Verifiable Presentation
  const vp = {
    '@context': ['https://www.w3.org/2018/credentials/v1'],
    type: ['VerifiablePresentation'],
    verifiableCredential: [
      {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        type: ['VerifiableCredential', 'ZkIdCredential'],
        proof: proofResponse,
      },
    ],
  };

  // Build presentation submission metadata
  const presentationSubmission: PresentationSubmission = {
    id: `submission-${Date.now()}`,
    definition_id: definitionId,
    descriptor_map: [
      {
        id: authRequest.presentation_definition?.input_descriptors[0]?.id || 'credential-0',
        format: 'ldp_vp',
        path: '$.verifiableCredential[0]',
      },
    ],
  };

  return {
    vp_token: Buffer.from(JSON.stringify(vp)).toString('base64'),
    presentation_submission: presentationSubmission,
    state: authRequest.state,
  };
}

/**
 * Submit a presentation to the verifier's callback URL
 *
 * @param responseUri - Verifier callback URL from authorization request
 * @param presentation - Presentation response to submit
 * @param httpAdapter - HTTP client for making POST request
 * @returns Verifier response
 */
export async function submitPresentation(
  responseUri: string,
  presentation: PresentationResponse,
  httpAdapter: HttpAdapter,
): Promise<{ verified: boolean; message?: string }> {
  const response = await httpAdapter.post(responseUri, presentation, {
    'Content-Type': 'application/json',
  });

  if (!response.ok) {
    throw new Error(`Presentation submission failed: ${response.status} ${response.statusText}`);
  }

  return await response.json();
}

/**
 * Build a deep link URL for QR code scanning
 *
 * @param authRequest - Authorization request
 * @returns openid4vp:// deep link URL
 */
export function buildDeepLink(authRequest: AuthorizationRequest): string {
  const params = new URLSearchParams();

  // Add presentation definition or DCQL query
  if (authRequest.presentation_definition) {
    params.set('presentation_definition', JSON.stringify(authRequest.presentation_definition));
  } else if (authRequest.dcql_query) {
    params.set('dcql_query', JSON.stringify(authRequest.dcql_query));
  }

  // Add standard parameters
  params.set('response_uri', authRequest.response_uri);
  params.set('nonce', authRequest.nonce);
  params.set('client_id', authRequest.client_id);

  if (authRequest.state) {
    params.set('state', authRequest.state);
  }

  if (authRequest.response_mode) {
    params.set('response_mode', authRequest.response_mode);
  }

  if (authRequest.response_type) {
    params.set('response_type', authRequest.response_type);
  }

  return `openid4vp://?${params.toString()}`;
}

// ---------------------------------------------------------------------------
// Helper: Map InputDescriptor to ProofRequest
// ---------------------------------------------------------------------------

interface ProofRequest {
  claimType: 'age' | 'nationality';
  minAge?: number;
  targetNationality?: number;
  nonce: string;
  timestamp: string;
}

function toFiniteNumber(value: unknown): number | undefined {
  const n = Number(value);
  return Number.isFinite(n) ? n : undefined;
}

function getFirstEnumNumber(filter: Record<string, unknown> | undefined): number | undefined {
  if (!filter || !Array.isArray(filter.enum) || filter.enum.length === 0) {
    return undefined;
  }
  return toFiniteNumber(filter.enum[0]);
}

function inputDescriptorToProofRequest(descriptor: InputDescriptor, nonce: string): ProofRequest {
  const constraints = descriptor.constraints?.fields || [];

  // Detect age verification
  const ageField = constraints.find((f) => {
    const path = f.path.join('.');
    return path.includes('minAge') || path.includes('birthYear') || path.includes('age');
  });

  if (ageField) {
    const path = ageField.path.join('.');
    const filter = ageField.filter ?? {};
    const currentYear = new Date().getFullYear();

    const minAgeFromDirectConstraint =
      toFiniteNumber(filter.const) ??
      getFirstEnumNumber(filter) ??
      (path.includes('minAge') || (path.includes('age') && !path.includes('birthYear'))
        ? toFiniteNumber(filter.minimum)
        : undefined);

    if (minAgeFromDirectConstraint !== undefined) {
      return {
        claimType: 'age',
        minAge: minAgeFromDirectConstraint,
        nonce,
        timestamp: new Date().toISOString(),
      };
    }

    if (path.includes('birthYear')) {
      const maxBirthYear = toFiniteNumber(filter.maximum);
      if (maxBirthYear !== undefined) {
        return {
          claimType: 'age',
          minAge: currentYear - maxBirthYear,
          nonce,
          timestamp: new Date().toISOString(),
        };
      }
    }
  }

  // Detect nationality verification
  const nationalityField = constraints.find((f) =>
    f.path.some((p) => p.includes('nationality') || p.includes('targetNationality')),
  );

  if (nationalityField) {
    const filter = nationalityField.filter ?? {};
    const targetNationality = toFiniteNumber(filter.const) ?? getFirstEnumNumber(filter);

    if (targetNationality === undefined) {
      throw new Error('Unsupported nationality constraint in presentation definition');
    }

    return {
      claimType: 'nationality',
      targetNationality,
      nonce,
      timestamp: new Date().toISOString(),
    };
  }

  throw new Error('Unsupported presentation definition - cannot determine claim type');
}

/**
 * Convert a DCQL query to a ProofRequest
 *
 * @param dcqlQuery - DCQL query from authorization request
 * @param nonce - Nonce for proof
 * @returns ProofRequest for proof generation
 */
function dcqlQueryToProofRequest(dcqlQuery: DCQLQuery, nonce: string): ProofRequest {
  // Analyze DCQL query to determine claim type and parameters
  let claimType: 'age' | 'nationality' = 'age';
  let minAge: number | undefined;
  let targetNationality: number | undefined;

  // Check credential type and claims
  for (const credQuery of dcqlQuery.credentials) {
    // Check credential type
    if (credQuery.type.includes('AgeCredential')) {
      claimType = 'age';
    } else if (credQuery.type.includes('NationalityCredential')) {
      claimType = 'nationality';
    }

    // Extract constraints from claims
    if (credQuery.claims) {
      for (const claim of credQuery.claims) {
        // Age constraints
        if (claim.path.includes('birthYear') && claim.filter?.maximum) {
          // Convert maximum birth year to minimum age
          minAge = new Date().getFullYear() - claim.filter.maximum;
        }

        // Nationality constraints
        if (claim.path.includes('nationality') && claim.filter?.const) {
          targetNationality = Number(claim.filter.const);
        }
      }
    }
  }

  return {
    claimType,
    minAge,
    targetNationality,
    nonce,
    timestamp: new Date().toISOString(),
  };
}
