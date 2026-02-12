/**
 * Digital Credentials API adapter (placeholder)
 *
 * The Digital Credentials API is a W3C standard for browser-native
 * credential storage and presentation. Currently supported in Chrome
 * and Android (via EUDI Wallet).
 *
 * This module provides types and a stub implementation that can be
 * implemented when DC API support is added to zk-id.
 *
 * References:
 * - https://wicg.github.io/digital-credentials/
 * - https://developer.chrome.com/docs/privacy-security/digital-credentials
 */

/**
 * Digital Credentials API adapter interface
 */
export interface DCAPIAdapter {
  /**
   * Check if the Digital Credentials API is available on this platform
   */
  isAvailable(): Promise<boolean>;

  /**
   * Request a credential from the platform credential store
   *
   * @param request - Credential request (OpenID4VP format)
   * @returns Digital credential response
   */
  get(request: DigitalCredentialRequest): Promise<DigitalCredential>;

  /**
   * Store a credential in the platform credential store
   *
   * @param credential - Credential to store
   */
  store(credential: DigitalCredential): Promise<void>;
}

/**
 * Digital Credential Request (OpenID4VP format)
 */
export interface DigitalCredentialRequest {
  /** Protocol (currently only 'openid4vp' is supported) */
  protocol: 'openid4vp';
  /** OpenID4VP authorization request URL */
  data: string;
}

/**
 * Digital Credential (response from platform)
 */
export interface DigitalCredential {
  /** Protocol used */
  protocol: 'openid4vp';
  /** Presentation response (JSON string) */
  data: string;
}

/**
 * Not-implemented DC API adapter
 *
 * Throws descriptive errors explaining that DC API support
 * is not yet available in zk-id.
 */
export class NotImplementedDCAPIAdapter implements DCAPIAdapter {
  async isAvailable(): Promise<boolean> {
    return false;
  }

  async get(request: DigitalCredentialRequest): Promise<DigitalCredential> {
    throw new Error(
      'Digital Credentials API is not yet implemented in @zk-id/mobile. ' +
        'This feature is planned for Q3 2026. ' +
        'Use OpenID4VP with deep links instead (see openid4vp-adapter.ts).',
    );
  }

  async store(credential: DigitalCredential): Promise<void> {
    throw new Error(
      'Digital Credentials API is not yet implemented in @zk-id/mobile. ' +
        'Credentials are stored locally via SecureStorageAdapter instead.',
    );
  }
}

/**
 * Future: Browser/Android DC API adapter
 *
 * When implementing:
 * 1. Check for navigator.credentials.get({ identity: ... })
 * 2. Map OpenID4VP request to DC API format
 * 3. Handle Android EUDI Wallet integration
 * 4. Support iOS Wallet framework (when available)
 */
export class BrowserDCAPIAdapter implements DCAPIAdapter {
  async isAvailable(): Promise<boolean> {
    // Check for navigator.credentials.get support
    if (typeof navigator === 'undefined' || !navigator.credentials) {
      return false;
    }

    // Digital Credentials API is available if navigator.credentials exists
    // Full feature detection would require browser capability checks
    return true;
  }

  async get(request: DigitalCredentialRequest): Promise<DigitalCredential> {
    throw new Error('BrowserDCAPIAdapter.get() not yet implemented');

    // Future implementation:
    /*
    const credential = await navigator.credentials.get({
      identity: {
        providers: [{
          protocol: 'openid4vp',
          request: request.data,
        }],
      },
    });

    return {
      protocol: 'openid4vp',
      data: credential.token,
    };
    */
  }

  async store(credential: DigitalCredential): Promise<void> {
    throw new Error('BrowserDCAPIAdapter.store() not yet implemented');

    // Future implementation:
    /*
    await navigator.credentials.store({
      identity: {
        protocol: credential.protocol,
        data: credential.data,
      },
    });
    */
  }
}

/**
 * Roadmap for DC API support:
 *
 * Q2 2026:
 * - Research EUDI Wallet DC API integration
 * - Prototype Android native module for React Native
 * - Test with Chrome Canary DC API
 *
 * Q3 2026:
 * - Implement BrowserDCAPIAdapter for web
 * - Implement AndroidDCAPIAdapter for React Native
 * - Add iOS Wallet framework support (if available)
 * - Integration tests with real EUDI Wallet
 *
 * Q4 2026:
 * - Production release with DC API support
 * - Documentation and examples
 * - Backward compatibility with deep link flow
 */
