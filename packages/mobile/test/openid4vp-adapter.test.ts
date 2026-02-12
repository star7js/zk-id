/**
 * Tests for OpenID4VP adapter
 */

import { describe, it, expect } from '@jest/globals';
import {
  parseAuthorizationRequest,
  buildDeepLink,
  generatePresentation,
  type AuthorizationRequest,
} from '../src/openid4vp-adapter.js';

const mockAuthRequest: AuthorizationRequest = {
  presentation_definition: {
    id: 'age-verification-123',
    name: 'Age Verification',
    purpose: 'Prove you are at least 18 years old',
    input_descriptors: [
      {
        id: 'age-descriptor',
        name: 'Age >= 18',
        constraints: {
          fields: [
            {
              path: ['$.credentialSubject.birthYear'],
              filter: {
                type: 'number',
                minimum: 2006,
              },
            },
          ],
        },
      },
    ],
  },
  response_mode: 'direct_post',
  response_uri: 'https://verifier.example.com/callback',
  nonce: 'challenge-nonce-123',
  client_id: 'demo-verifier',
  state: 'state-xyz',
};

describe('parseAuthorizationRequest', () => {
  it('should parse openid4vp:// deep link URL', () => {
    const deepLink = buildDeepLink(mockAuthRequest);
    const parsed = parseAuthorizationRequest(deepLink);

    expect(parsed.presentation_definition).toEqual(mockAuthRequest.presentation_definition);
    expect(parsed.response_uri).toBe(mockAuthRequest.response_uri);
    expect(parsed.nonce).toBe(mockAuthRequest.nonce);
    expect(parsed.client_id).toBe(mockAuthRequest.client_id);
    expect(parsed.state).toBe(mockAuthRequest.state);
  });

  it('should parse https:// URL with openid4vp parameters', () => {
    const params = new URLSearchParams({
      presentation_definition: JSON.stringify(mockAuthRequest.presentation_definition),
      response_uri: mockAuthRequest.response_uri,
      nonce: mockAuthRequest.nonce,
      client_id: mockAuthRequest.client_id,
      state: mockAuthRequest.state!,
    });

    const url = `https://verifier.example.com/auth?${params.toString()}`;
    const parsed = parseAuthorizationRequest(url);

    expect(parsed.presentation_definition).toEqual(mockAuthRequest.presentation_definition);
  });

  it('should throw error for request_uri (not yet supported)', () => {
    const url = 'openid4vp://?request_uri=https://example.com/request';

    expect(() => parseAuthorizationRequest(url)).toThrow('request_uri');
  });

  it('should throw error for JWT request (not yet supported)', () => {
    const url = 'openid4vp://?request=eyJhbGciOiJub25lIn0...';

    expect(() => parseAuthorizationRequest(url)).toThrow('JWT-encoded');
  });

  it('should throw error when presentation_definition is missing', () => {
    const url = 'openid4vp://?nonce=123&client_id=verifier';

    expect(() => parseAuthorizationRequest(url)).toThrow('Missing presentation_definition');
  });

  it('should default response_mode to direct_post', () => {
    const params = new URLSearchParams({
      presentation_definition: JSON.stringify(mockAuthRequest.presentation_definition),
      response_uri: mockAuthRequest.response_uri,
      nonce: mockAuthRequest.nonce,
      client_id: mockAuthRequest.client_id,
    });

    const url = `openid4vp://?${params.toString()}`;
    const parsed = parseAuthorizationRequest(url);

    expect(parsed.response_mode).toBe('direct_post');
  });
});

describe('buildDeepLink', () => {
  it('should build valid openid4vp:// deep link', () => {
    const deepLink = buildDeepLink(mockAuthRequest);

    expect(deepLink).toMatch(/^openid4vp:\/\//);
    expect(deepLink).toContain('presentation_definition=');
    expect(deepLink).toContain('response_uri=');
    expect(deepLink).toContain('nonce=');
    expect(deepLink).toContain('client_id=');
    expect(deepLink).toContain('state=');
  });

  it('should omit state if not provided', () => {
    const requestWithoutState = { ...mockAuthRequest, state: undefined };
    const deepLink = buildDeepLink(requestWithoutState);

    expect(deepLink).not.toContain('state=');
  });

  it('should URL-encode parameters correctly', () => {
    const deepLink = buildDeepLink(mockAuthRequest);
    const url = new URL(deepLink.replace('openid4vp://', 'https://example.com/'));

    const presentationDef = url.searchParams.get('presentation_definition');
    expect(presentationDef).toBeTruthy();

    const parsed = JSON.parse(presentationDef!);
    expect(parsed).toEqual(mockAuthRequest.presentation_definition);
  });

  it('should include response_type when provided', () => {
    const deepLink = buildDeepLink({
      ...mockAuthRequest,
      response_type: 'vp_token',
    });
    expect(deepLink).toContain('response_type=vp_token');
  });
});

describe('generatePresentation', () => {
  it('uses minAge directly from minAge constraints', async () => {
    let capturedMinAge: number | null = null;

    const wallet = {
      generateAgeProof: async (_id: string | null, minAge: number, nonce: string) => {
        capturedMinAge = minAge;
        return {
          credentialId: 'cred-1',
          claimType: 'age',
          proof: {
            proofType: 'age',
            proof: {
              pi_a: ['0'],
              pi_b: [['0'], ['0']],
              pi_c: ['0'],
              protocol: 'groth16',
              curve: 'bn128',
            },
            publicSignals: {
              currentYear: 2026,
              minAge,
              credentialHash: '1',
              nonce,
              requestTimestamp: Date.now(),
            },
          },
          nonce,
          requestTimestamp: new Date().toISOString(),
        };
      },
      generateNationalityProof: async () => {
        throw new Error('unexpected nationality proof');
      },
    } as any;

    const presentation = await generatePresentation(
      {
        presentation_definition: {
          id: 'age-minage',
          input_descriptors: [
            {
              id: 'age-proof',
              constraints: {
                fields: [
                  {
                    path: ['$.publicSignals.minAge'],
                    filter: { type: 'number', minimum: 18 },
                  },
                ],
              },
            },
          ],
        },
        response_uri: 'https://verifier.example.com/callback',
        nonce: 'n-1',
        client_id: 'demo-verifier',
        state: 's-1',
      },
      wallet,
    );

    expect(capturedMinAge).toBe(18);
    expect(presentation.state).toBe('s-1');
    expect(presentation.vp_token.length).toBeGreaterThan(0);
  });

  it('supports nationality enum constraints', async () => {
    let capturedNationality: number | null = null;

    const wallet = {
      generateAgeProof: async () => {
        throw new Error('unexpected age proof');
      },
      generateNationalityProof: async (_id: string | null, nationality: number, nonce: string) => {
        capturedNationality = nationality;
        return {
          credentialId: 'cred-2',
          claimType: 'nationality',
          proof: {
            proofType: 'nationality',
            proof: {
              pi_a: ['0'],
              pi_b: [['0'], ['0']],
              pi_c: ['0'],
              protocol: 'groth16',
              curve: 'bn128',
            },
            publicSignals: {
              targetNationality: nationality,
              credentialHash: '2',
              nonce,
              requestTimestamp: Date.now(),
            },
          },
          nonce,
          requestTimestamp: new Date().toISOString(),
        };
      },
    } as any;

    await generatePresentation(
      {
        presentation_definition: {
          id: 'nat-enum',
          input_descriptors: [
            {
              id: 'nat-proof',
              constraints: {
                fields: [
                  {
                    path: ['$.publicSignals.targetNationality'],
                    filter: { type: 'number', enum: [840] },
                  },
                ],
              },
            },
          ],
        },
        response_uri: 'https://verifier.example.com/callback',
        nonce: 'n-2',
        client_id: 'demo-verifier',
      },
      wallet,
    );

    expect(capturedNationality).toBe(840);
  });
});

describe('submitPresentation', () => {
  // Note: Submission tests require a mock HttpAdapter
  // These are integration tests

  it('should be tested in integration tests', () => {
    // Placeholder
    expect(true).toBe(true);
  });
});
