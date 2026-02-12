/**
 * OpenID4VP Demo - Browser Wallet Client
 *
 * Implements the browser wallet UI for credential issuance,
 * storage, and OpenID4VP presentation generation.
 */

import { OpenID4VPWallet, InMemoryCredentialStore } from '@zk-id/sdk';
import type { SignedCredential, Credential } from '@zk-id/core';

// Configuration
const ISSUER_URL = 'http://localhost:3001';
const VERIFIER_URL = 'http://localhost:3002';

// Circuit paths (served from the circuits package via issuer server)
const CIRCUIT_PATHS = {
  ageWasm: `${ISSUER_URL}/circuits/age.wasm`,
  ageZkey: `${ISSUER_URL}/circuits/age.zkey`,
  nationalityWasm: `${ISSUER_URL}/circuits/nationality.wasm`,
  nationalityZkey: `${ISSUER_URL}/circuits/nationality.zkey`,
};

// Initialize wallet
const wallet = new OpenID4VPWallet({
  credentialStore: new InMemoryCredentialStore(),
  circuitPaths: CIRCUIT_PATHS,
  walletId: 'demo-browser-wallet',
});

// Current authorization request
let currentAuthRequest: any = null;

// ---------------------------------------------------------------------------
// Logging helpers
// ---------------------------------------------------------------------------

function logVerifier(message: string, type: 'info' | 'success' | 'error' = 'info') {
  const log = document.getElementById('verifier-log')!;
  const entry = document.createElement('div');
  entry.className = `log-entry ${type}`;
  entry.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
  log.appendChild(entry);
  log.scrollTop = log.scrollHeight;
}

function logWallet(message: string, type: 'info' | 'success' | 'error' = 'info') {
  const log = document.getElementById('wallet-log')!;
  const entry = document.createElement('div');
  entry.className = `log-entry ${type}`;
  entry.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
  log.appendChild(entry);
  log.scrollTop = log.scrollHeight;
}

// ---------------------------------------------------------------------------
// Health checks
// ---------------------------------------------------------------------------

async function checkServerHealth() {
  const issuerStatus = document.getElementById('issuer-status')!;
  const verifierStatus = document.getElementById('verifier-status')!;
  const statusText = document.getElementById('status-text')!;

  try {
    const [issuerRes, verifierRes] = await Promise.allSettled([
      fetch(`${ISSUER_URL}/health`),
      fetch(`${VERIFIER_URL}/health`),
    ]);

    const issuerOk = issuerRes.status === 'fulfilled' && issuerRes.value.ok;
    const verifierOk = verifierRes.status === 'fulfilled' && verifierRes.value.ok;

    issuerStatus.className = `status-dot ${issuerOk ? '' : 'disconnected'}`;
    verifierStatus.className = `status-dot ${verifierOk ? '' : 'disconnected'}`;

    if (issuerOk && verifierOk) {
      statusText.textContent = 'All servers online';
    } else if (!issuerOk && !verifierOk) {
      statusText.textContent = 'Servers offline - run npm start';
    } else if (!issuerOk) {
      statusText.textContent = 'Issuer offline';
    } else {
      statusText.textContent = 'Verifier offline';
    }

    return issuerOk && verifierOk;
  } catch (error) {
    issuerStatus.className = 'status-dot disconnected';
    verifierStatus.className = 'status-dot disconnected';
    statusText.textContent = 'Servers offline';
    return false;
  }
}

// ---------------------------------------------------------------------------
// Verifier: Create Authorization Request
// ---------------------------------------------------------------------------

document.getElementById('create-request')!.addEventListener('click', async () => {
  const minAge = parseInt((document.getElementById('min-age') as HTMLInputElement).value);
  const button = document.getElementById('create-request') as HTMLButtonElement;

  button.disabled = true;
  button.innerHTML = 'Creating...<span class="spinner"></span>';
  logVerifier(`Creating authorization request for age ${minAge}+`);

  try {
    const response = await fetch(`${VERIFIER_URL}/auth/request?minAge=${minAge}`);
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    const data = await response.json();
    currentAuthRequest = data.authRequest;

    // Display QR code
    const qrSection = document.getElementById('qr-section')!;
    const qrCode = document.getElementById('qr-code') as HTMLImageElement;
    const requestDetails = document.getElementById('request-details')!;

    qrCode.src = data.qrCode;
    requestDetails.textContent = JSON.stringify(data.authRequest, null, 2);
    qrSection.classList.remove('hidden');

    logVerifier('Authorization request created', 'success');

    // Enable presentation button if wallet has credentials
    const credentials = await wallet['config'].credentialStore.getAll();
    if (credentials.length > 0) {
      (document.getElementById('generate-presentation') as HTMLButtonElement).disabled = false;
    }
  } catch (error) {
    logVerifier(`Error: ${error}`, 'error');
    alert(`Failed to create request: ${error}`);
  } finally {
    button.disabled = false;
    button.innerHTML = 'Create Authorization Request';
  }
});

// ---------------------------------------------------------------------------
// Wallet: Issue Credential
// ---------------------------------------------------------------------------

document.getElementById('issue-credential')!.addEventListener('click', async () => {
  const name = (document.getElementById('holder-name') as HTMLInputElement).value;
  const dob = (document.getElementById('holder-dob') as HTMLInputElement).value;
  const nationality = (document.getElementById('holder-nationality') as HTMLInputElement).value.toUpperCase();
  const button = document.getElementById('issue-credential') as HTMLButtonElement;

  if (!name || !dob || !nationality) {
    alert('Please fill in all fields');
    return;
  }

  button.disabled = true;
  button.innerHTML = 'Issuing...<span class="spinner"></span>';
  logWallet('Requesting credential from issuer...');

  try {
    const response = await fetch(`${ISSUER_URL}/issue`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        holderName: name,
        dateOfBirth: dob,
        nationality,
      }),
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    const signedCredential: SignedCredential = await response.json();

    // Store in wallet
    await wallet['config'].credentialStore.put(signedCredential);

    logWallet('Credential issued and stored', 'success');
    renderCredentials();

    // Enable presentation button if there's a pending request
    if (currentAuthRequest) {
      (document.getElementById('generate-presentation') as HTMLButtonElement).disabled = false;
    }
  } catch (error) {
    logWallet(`Error: ${error}`, 'error');
    alert(`Failed to issue credential: ${error}`);
  } finally {
    button.disabled = false;
    button.innerHTML = 'Issue Credential from Issuer';
  }
});

// ---------------------------------------------------------------------------
// Wallet: Render Credentials
// ---------------------------------------------------------------------------

async function renderCredentials() {
  const container = document.getElementById('credential-list')!;
  const credentials = await wallet['config'].credentialStore.getAll();

  if (credentials.length === 0) {
    container.innerHTML = '<p style="color: #8b949e; font-size: 0.875rem;">No credentials yet. Issue one above.</p>';
    return;
  }

  container.innerHTML = credentials.map(signedCred => {
    const cred = signedCred.credential;
    const age = calculateAge(cred.dateOfBirth);

    return `
      <div class="credential-card">
        <div class="field">
          <span class="label">ID</span>
          <span class="value">${cred.id.slice(0, 8)}...</span>
        </div>
        <div class="field">
          <span class="label">Name</span>
          <span class="value">${cred.holderName}</span>
        </div>
        <div class="field">
          <span class="label">Date of Birth</span>
          <span class="value">${cred.dateOfBirth} (age ${age})</span>
        </div>
        <div class="field">
          <span class="label">Nationality</span>
          <span class="value">${cred.nationality}</span>
        </div>
        <div class="field">
          <span class="label">Issued At</span>
          <span class="value">${new Date(signedCred.issuedAt).toLocaleString()}</span>
        </div>
      </div>
    `;
  }).join('');
}

function calculateAge(dob: string): number {
  const birthDate = new Date(dob);
  const today = new Date();
  let age = today.getFullYear() - birthDate.getFullYear();
  const monthDiff = today.getMonth() - birthDate.getMonth();
  if (monthDiff < 0 || (monthDiff === 0 && today.getDate() < birthDate.getDate())) {
    age--;
  }
  return age;
}

// ---------------------------------------------------------------------------
// Wallet: Generate and Submit Presentation
// ---------------------------------------------------------------------------

document.getElementById('generate-presentation')!.addEventListener('click', async () => {
  if (!currentAuthRequest) {
    alert('No authorization request available. Create one in the Verifier panel first.');
    return;
  }

  const button = document.getElementById('generate-presentation') as HTMLButtonElement;
  button.disabled = true;
  button.innerHTML = 'Generating proof...<span class="spinner"></span>';
  logWallet('Generating ZK proof...');

  try {
    // Generate presentation
    const presentation = await wallet.generatePresentation(currentAuthRequest);

    logWallet('Proof generated, submitting to verifier...', 'success');
    button.innerHTML = 'Submitting...<span class="spinner"></span>';

    // Submit to verifier callback
    const response = await fetch(currentAuthRequest.response_uri, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(presentation),
    });

    const result = await response.json();

    if (result.verified) {
      logWallet('Presentation verified successfully!', 'success');
      displayVerificationResult(result, 'success');
      logVerifier('Presentation verified successfully', 'success');
    } else {
      logWallet('Presentation verification failed', 'error');
      displayVerificationResult(result, 'error');
      logVerifier(`Verification failed: ${result.error}`, 'error');
    }
  } catch (error) {
    logWallet(`Error: ${error}`, 'error');
    alert(`Failed to generate or submit presentation: ${error}`);
  } finally {
    button.disabled = false;
    button.innerHTML = 'Generate & Submit Proof';
  }
});

function displayVerificationResult(result: any, type: 'success' | 'error') {
  const container = document.getElementById('verification-result')!;
  container.innerHTML = `
    <div class="result ${type}">
      <div class="field">
        <span class="label">Status</span>
        <span class="value">${result.verified ? '✅ Verified' : '❌ Failed'}</span>
      </div>
      ${result.message ? `
        <div class="field">
          <span class="label">Message</span>
          <span class="value">${result.message}</span>
        </div>
      ` : ''}
      ${result.error ? `
        <div class="field">
          <span class="label">Error</span>
          <span class="value">${result.error}</span>
        </div>
      ` : ''}
    </div>
  `;
}

// ---------------------------------------------------------------------------
// Initialize
// ---------------------------------------------------------------------------

(async () => {
  logWallet('Wallet initialized');
  logVerifier('Verifier ready');

  // Check server health
  const healthy = await checkServerHealth();
  if (!healthy) {
    logVerifier('Servers not available - run npm start', 'error');
    logWallet('Servers not available - run npm start', 'error');
  }

  // Check for existing credentials
  renderCredentials();

  // Poll server health every 5 seconds
  setInterval(checkServerHealth, 5000);
})();
