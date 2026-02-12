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
  post(url: string, body: any, headers?: Record<string, string>): Promise<HttpResponse>;
  get(url: string, headers?: Record<string, string>): Promise<HttpResponse>;
}

export interface HttpResponse {
  ok: boolean;
  status: number;
  statusText: string;
  json(): Promise<any>;
  text(): Promise<string>;
}

/**
 * OpenID4VP Authorization Request
 */
export interface AuthorizationRequest {
  presentation_definition: PresentationDefinition;
  response_mode?: string;
  response_uri: string;
  nonce: string;
  client_id: string;
  state?: string;
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
      filter?: any;
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

    // Direct parameters
    const presentationDefinitionParam = params.get('presentation_definition');
    if (!presentationDefinitionParam) {
      throw new Error('Missing presentation_definition parameter');
    }

    return {
      presentation_definition: JSON.parse(presentationDefinitionParam),
      response_mode: params.get('response_mode') || 'direct_post',
      response_uri: params.get('response_uri') || '',
      nonce: params.get('nonce') || '',
      client_id: params.get('client_id') || '',
      state: params.get('state') || undefined,
    };
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
  // Analyze presentation definition to determine proof type
  const inputDescriptor = authRequest.presentation_definition.input_descriptors[0];
  const proofRequest = inputDescriptorToProofRequest(inputDescriptor, authRequest.nonce);

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
    definition_id: authRequest.presentation_definition.id,
    descriptor_map: [
      {
        id: inputDescriptor.id,
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
): Promise<any> {
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
  const params = new URLSearchParams({
    presentation_definition: JSON.stringify(authRequest.presentation_definition),
    response_uri: authRequest.response_uri,
    nonce: authRequest.nonce,
    client_id: authRequest.client_id,
  });

  if (authRequest.state) {
    params.set('state', authRequest.state);
  }

  return `openid4vp://?${params.toString()}`;
}

// ---------------------------------------------------------------------------
// Helper: Map InputDescriptor to ProofRequest
// ---------------------------------------------------------------------------

interface ProofRequest {
  claimType: 'age' | 'nationality';
  minAge?: number;
  targetNationality?: string;
  nonce: string;
  timestamp: string;
}

function inputDescriptorToProofRequest(
  descriptor: InputDescriptor,
  nonce: string,
): ProofRequest {
  const constraints = descriptor.constraints?.fields || [];

  // Detect age verification
  const ageField = constraints.find((f) =>
    f.path.some((p) => p.includes('birthYear') || p.includes('age')),
  );

  if (ageField && ageField.filter?.minimum !== undefined) {
    const currentYear = new Date().getFullYear();
    const minBirthYear = ageField.filter.minimum;
    const minAge = currentYear - minBirthYear;

    return {
      claimType: 'age',
      minAge,
      nonce,
      timestamp: new Date().toISOString(),
    };
  }

  // Detect nationality verification
  const nationalityField = constraints.find((f) =>
    f.path.some((p) => p.includes('nationality')),
  );

  if (nationalityField && nationalityField.filter?.const) {
    return {
      claimType: 'nationality',
      targetNationality: nationalityField.filter.const,
      nonce,
      timestamp: new Date().toISOString(),
    };
  }

  throw new Error('Unsupported presentation definition - cannot determine claim type');
}
