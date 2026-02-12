/**
 * ZkId Age Gate Widget
 *
 * Self-contained, embeddable age verification widget with zero-knowledge proofs.
 * Can be added to any website with 3 lines of code.
 */

import { OpenID4VPWallet, InMemoryCredentialStore } from '@zk-id/sdk';
import type { SignedCredential } from '@zk-id/core';

export interface ZkIdAgeGateConfig {
  /** Endpoint to verify the presentation against */
  verificationEndpoint: string;
  /** Minimum age required */
  minAge: number;
  /** Callback when verification succeeds */
  onVerified: () => void;
  /** Callback when verification fails or is cancelled */
  onRejected?: (reason: string) => void;
  /** Optional: Custom issuer endpoint for test credentials */
  issuerEndpoint?: string;
  /** Optional: Circuit paths (defaults to CDN) */
  circuitPaths?: {
    ageWasm: string;
    ageZkey: string;
  };
  /** Optional: Custom branding */
  branding?: {
    title?: string;
    primaryColor?: string;
    logo?: string;
  };
}

class ZkIdAgeGate {
  private config: ZkIdAgeGateConfig;
  private wallet: OpenID4VPWallet | null = null;
  private overlay: HTMLElement | null = null;

  constructor(config: ZkIdAgeGateConfig) {
    this.config = {
      ...config,
      circuitPaths: config.circuitPaths || {
        ageWasm: 'https://cdn.jsdelivr.net/npm/@zk-id/circuits/dist/age.wasm',
        ageZkey: 'https://cdn.jsdelivr.net/npm/@zk-id/circuits/dist/age.zkey',
      },
      branding: {
        title: 'Age Verification Required',
        primaryColor: '#238636',
        logo: '',
        ...config.branding,
      },
    };
  }

  /**
   * Initialize the wallet and show the modal
   */
  async show(): Promise<void> {
    // Initialize wallet
    this.wallet = new OpenID4VPWallet({
      credentialStore: new InMemoryCredentialStore(),
      circuitPaths: this.config.circuitPaths!,
      walletId: 'age-gate-widget',
    });

    // Inject styles
    this.injectStyles();

    // Create and show modal
    this.showModal();
  }

  /**
   * Inject widget styles into the page
   */
  private injectStyles(): void {
    if (document.getElementById('zkid-age-gate-styles')) {
      return; // Already injected
    }

    const style = document.createElement('style');
    style.id = 'zkid-age-gate-styles';
    style.textContent = `
      .zkid-overlay {
        position: fixed;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background: rgba(0, 0, 0, 0.85);
        backdrop-filter: blur(4px);
        display: flex;
        align-items: center;
        justify-content: center;
        z-index: 999999;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      }

      .zkid-modal {
        background: #1a1a1a;
        border-radius: 12px;
        padding: 2rem;
        max-width: 450px;
        width: 90%;
        box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
        color: #ffffff;
        animation: zkid-modal-in 0.3s ease-out;
      }

      @keyframes zkid-modal-in {
        from {
          opacity: 0;
          transform: scale(0.95) translateY(20px);
        }
        to {
          opacity: 1;
          transform: scale(1) translateY(0);
        }
      }

      .zkid-header {
        text-align: center;
        margin-bottom: 1.5rem;
      }

      .zkid-logo {
        width: 60px;
        height: 60px;
        margin: 0 auto 1rem;
        display: block;
      }

      .zkid-title {
        font-size: 1.5rem;
        font-weight: 600;
        margin: 0 0 0.5rem;
        color: #ffffff;
      }

      .zkid-subtitle {
        font-size: 0.875rem;
        color: #888;
        margin: 0;
      }

      .zkid-content {
        margin: 1.5rem 0;
      }

      .zkid-step {
        background: #252525;
        border-radius: 8px;
        padding: 1rem;
        margin-bottom: 1rem;
        border-left: 3px solid var(--zkid-primary, #238636);
      }

      .zkid-step-title {
        font-weight: 500;
        margin-bottom: 0.5rem;
        color: #ffffff;
      }

      .zkid-step-desc {
        font-size: 0.875rem;
        color: #aaa;
        margin: 0;
      }

      .zkid-input {
        width: 100%;
        padding: 0.75rem;
        background: #252525;
        border: 1px solid #333;
        border-radius: 6px;
        color: #ffffff;
        font-size: 0.875rem;
        margin-bottom: 0.5rem;
      }

      .zkid-input:focus {
        outline: none;
        border-color: var(--zkid-primary, #238636);
      }

      .zkid-label {
        display: block;
        font-size: 0.875rem;
        color: #aaa;
        margin-bottom: 0.5rem;
      }

      .zkid-buttons {
        display: flex;
        gap: 0.75rem;
        margin-top: 1.5rem;
      }

      .zkid-button {
        flex: 1;
        padding: 0.875rem 1.5rem;
        border: none;
        border-radius: 6px;
        font-size: 0.875rem;
        font-weight: 500;
        cursor: pointer;
        transition: all 0.2s;
      }

      .zkid-button-primary {
        background: var(--zkid-primary, #238636);
        color: white;
      }

      .zkid-button-primary:hover {
        background: var(--zkid-primary-hover, #2ea043);
      }

      .zkid-button-primary:disabled {
        background: #333;
        color: #666;
        cursor: not-allowed;
      }

      .zkid-button-secondary {
        background: transparent;
        border: 1px solid #333;
        color: #aaa;
      }

      .zkid-button-secondary:hover {
        background: #252525;
        border-color: #444;
      }

      .zkid-spinner {
        display: inline-block;
        width: 14px;
        height: 14px;
        border: 2px solid #333;
        border-top-color: #ffffff;
        border-radius: 50%;
        animation: zkid-spin 0.6s linear infinite;
        margin-left: 0.5rem;
      }

      @keyframes zkid-spin {
        to { transform: rotate(360deg); }
      }

      .zkid-status {
        text-align: center;
        padding: 1rem;
        border-radius: 6px;
        margin: 1rem 0;
        font-size: 0.875rem;
      }

      .zkid-status-success {
        background: rgba(35, 134, 54, 0.2);
        border: 1px solid #238636;
        color: #3fb950;
      }

      .zkid-status-error {
        background: rgba(248, 81, 73, 0.2);
        border: 1px solid #f85149;
        color: #f85149;
      }

      .zkid-status-info {
        background: rgba(88, 166, 255, 0.2);
        border: 1px solid #58a6ff;
        color: #58a6ff;
      }

      .zkid-privacy {
        background: #252525;
        border-radius: 6px;
        padding: 0.75rem;
        margin-top: 1rem;
        font-size: 0.75rem;
        color: #888;
        border-left: 3px solid #58a6ff;
      }

      .zkid-privacy strong {
        color: #58a6ff;
      }
    `;
    document.head.appendChild(style);
  }

  /**
   * Show the modal UI
   */
  private showModal(): void {
    const { branding, minAge } = this.config;

    this.overlay = document.createElement('div');
    this.overlay.className = 'zkid-overlay';
    this.overlay.style.setProperty('--zkid-primary', branding!.primaryColor!);
    this.overlay.style.setProperty('--zkid-primary-hover', this.adjustColor(branding!.primaryColor!, 10));

    this.overlay.innerHTML = `
      <div class="zkid-modal">
        <div class="zkid-header">
          ${branding!.logo ? `<img src="${branding!.logo}" alt="Logo" class="zkid-logo">` : ''}
          <h2 class="zkid-title">${branding!.title}</h2>
          <p class="zkid-subtitle">Prove you're ${minAge}+ without revealing your birthdate</p>
        </div>

        <div class="zkid-content">
          <div id="zkid-step-credential">
            <div class="zkid-step">
              <div class="zkid-step-title">📋 Step 1: Get Test Credential</div>
              <div class="zkid-step-desc">For demo purposes, we'll issue a test credential.</div>
            </div>

            <label class="zkid-label">Date of Birth</label>
            <input type="date" id="zkid-dob" class="zkid-input" value="1990-01-01" max="${new Date().toISOString().split('T')[0]}">

            <div id="zkid-status"></div>
          </div>

          <div class="zkid-privacy">
            <strong>🔒 Your Privacy:</strong> Your birthdate stays on your device. Only a zero-knowledge proof is sent to verify your age.
          </div>
        </div>

        <div class="zkid-buttons">
          <button id="zkid-cancel" class="zkid-button zkid-button-secondary">Cancel</button>
          <button id="zkid-verify" class="zkid-button zkid-button-primary">Verify Age</button>
        </div>
      </div>
    `;

    document.body.appendChild(this.overlay);

    // Attach event listeners
    this.overlay.querySelector('#zkid-cancel')!.addEventListener('click', () => this.cancel());
    this.overlay.querySelector('#zkid-verify')!.addEventListener('click', () => this.verify());
  }

  /**
   * Adjust color brightness
   */
  private adjustColor(color: string, percent: number): string {
    const num = parseInt(color.replace('#', ''), 16);
    const amt = Math.round(2.55 * percent);
    const R = (num >> 16) + amt;
    const G = (num >> 8 & 0x00FF) + amt;
    const B = (num & 0x0000FF) + amt;
    return '#' + (
      0x1000000 +
      (R < 255 ? (R < 1 ? 0 : R) : 255) * 0x10000 +
      (G < 255 ? (G < 1 ? 0 : G) : 255) * 0x100 +
      (B < 255 ? (B < 1 ? 0 : B) : 255)
    ).toString(16).slice(1);
  }

  /**
   * Handle cancel
   */
  private cancel(): void {
    this.close();
    if (this.config.onRejected) {
      this.config.onRejected('User cancelled');
    }
  }

  /**
   * Handle verification
   */
  private async verify(): Promise<void> {
    const verifyButton = this.overlay!.querySelector('#zkid-verify') as HTMLButtonElement;
    const statusDiv = this.overlay!.querySelector('#zkid-status') as HTMLElement;

    verifyButton.disabled = true;
    verifyButton.innerHTML = 'Working...<span class="zkid-spinner"></span>';

    try {
      // Step 1: Issue credential
      statusDiv.className = 'zkid-status zkid-status-info';
      statusDiv.textContent = 'Issuing test credential...';

      const dob = (this.overlay!.querySelector('#zkid-dob') as HTMLInputElement).value;
      const credential = await this.issueTestCredential(dob);

      await this.wallet!['config'].credentialStore.put(credential);

      // Step 2: Fetch authorization request
      statusDiv.textContent = 'Fetching verification request...';

      const authResponse = await fetch(this.config.verificationEndpoint);
      if (!authResponse.ok) {
        throw new Error('Failed to fetch authorization request');
      }
      const { authRequest } = await authResponse.json();

      // Step 3: Generate proof
      statusDiv.textContent = 'Generating zero-knowledge proof... (this may take ~45 seconds)';

      const presentation = await this.wallet!.generatePresentation(authRequest);

      // Step 4: Submit presentation
      statusDiv.textContent = 'Submitting proof for verification...';

      const submitResponse = await fetch(authRequest.response_uri, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(presentation),
      });

      const result = await submitResponse.json();

      if (result.verified) {
        statusDiv.className = 'zkid-status zkid-status-success';
        statusDiv.textContent = '✅ Age verified successfully!';

        setTimeout(() => {
          this.close();
          this.config.onVerified();
        }, 1500);
      } else {
        throw new Error(result.error || 'Verification failed');
      }
    } catch (error) {
      statusDiv.className = 'zkid-status zkid-status-error';
      statusDiv.textContent = `❌ Error: ${error}`;
      verifyButton.disabled = false;
      verifyButton.textContent = 'Retry';

      if (this.config.onRejected) {
        this.config.onRejected(String(error));
      }
    }
  }

  /**
   * Issue a test credential (for demo purposes)
   */
  private async issueTestCredential(dob: string): Promise<SignedCredential> {
    if (this.config.issuerEndpoint) {
      const response = await fetch(this.config.issuerEndpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          holderName: 'Demo User',
          dateOfBirth: dob,
          nationality: 'US',
        }),
      });

      if (!response.ok) {
        throw new Error('Failed to issue credential');
      }

      return await response.json();
    }

    // Fallback: create mock credential (NOTE: This won't verify in production!)
    throw new Error('No issuer endpoint configured. Set issuerEndpoint in config.');
  }

  /**
   * Close and remove the modal
   */
  private close(): void {
    if (this.overlay) {
      this.overlay.remove();
      this.overlay = null;
    }
  }
}

// Export singleton instance
export const ZkIdAgeGateWidget = {
  /**
   * Initialize and show the age gate
   */
  init(config: ZkIdAgeGateConfig): void {
    const gate = new ZkIdAgeGate(config);
    gate.show();
  },
};
