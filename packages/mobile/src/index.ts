/**
 * @zk-id/mobile
 *
 * Zero-knowledge identity SDK for React Native and mobile platforms.
 *
 * This package provides credential management and proof generation
 * for mobile apps without any DOM/browser dependencies.
 */

// Credential storage
export {
  type SecureStorageAdapter,
  MobileCredentialStore,
  MobileBBSCredentialStore,
  InMemoryCredentialStore,
  InMemoryBBSCredentialStore,
} from './credential-store.js';

// Wallet
export { MobileWallet, type MobileWalletConfig } from './mobile-wallet.js';

// OpenID4VP adapter
export {
  type HttpAdapter,
  type HttpResponse,
  type AuthorizationRequest,
  type PresentationDefinition,
  type InputDescriptor,
  type PresentationResponse,
  type PresentationSubmission,
  type DescriptorMapEntry,
  parseAuthorizationRequest,
  generatePresentation,
  submitPresentation,
  buildDeepLink,
} from './openid4vp-adapter.js';

// Digital Credentials API (placeholder)
export {
  type DCAPIAdapter,
  type DigitalCredentialRequest,
  type DigitalCredential,
  NotImplementedDCAPIAdapter,
  BrowserDCAPIAdapter,
} from './dc-api-types.js';

// Re-export core types for convenience
export type {
  Credential,
  SignedCredential,
  ProofRequest,
  ProofResponse,
  BBSProofResponse,
  SerializedBBSCredential,
} from '@zk-id/core';
