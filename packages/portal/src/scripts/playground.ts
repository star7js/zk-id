// @ts-nocheck
// Playground script for browser-based ZK proof generation

// API base URL (from environment)
const API_BASE_URL = import.meta.env.PUBLIC_API_URL || 'https://zk-id-1.onrender.com';

// Application state
const state = {
  credential: null,
  credentialId: null,
};

// Detect network/CORS errors from API cold starts
function formatApiError(error: any): string {
  const msg = error?.message || String(error);
  if (msg === 'Load failed' || msg === 'Failed to fetch' || msg === 'NetworkError when attempting to fetch resource.') {
    return 'Could not reach the API server. It may be starting up — please wait a moment and try again.';
  }
  return msg;
}

// Utility functions
function showResult(elementId: string, type: string, content: string) {
  const el = document.getElementById(elementId);
  if (!el) return;
  el.className = `result ${type}`;
  el.innerHTML = content;
}

function getNationalityName(code: number): string {
  const names: Record<number, string> = {
    840: 'United States',
    826: 'United Kingdom',
    124: 'Canada',
    276: 'Germany',
    250: 'France',
    392: 'Japan',
  };
  return names[code] || `Country ${code}`;
}

// Issue credential
async function issueCredential() {
  const birthYear = parseInt((document.getElementById('birthYear') as HTMLInputElement).value);
  const nationality = parseInt((document.getElementById('nationality') as HTMLSelectElement).value);

  if (isNaN(birthYear) || birthYear < 1900 || birthYear > 2026) {
    showResult('issueResult', 'error', '<strong>Invalid birth year</strong>');
    return;
  }

  showResult('issueResult', 'loading', '<strong>⏳ Requesting credential...</strong>');

  try {
    const response = await fetch(`${API_BASE_URL}/api/issue-credential`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ birthYear, nationality, userId: 'playground-user' }),
    });

    const data = await response.json();

    if (data.success) {
      state.credential = data.credential;
      state.credentialId = data.credential.credential.id;

      showResult(
        'issueResult',
        'success',
        `
          <strong>✓ Credential Issued</strong>
          <div style="margin-top: 12px; font-family: var(--font-mono); font-size: 12px;">
            <div>ID: ${state.credentialId}</div>
            <div>Birth Year: ${birthYear}</div>
            <div>Nationality: ${getNationalityName(nationality)} (${nationality})</div>
          </div>
        `,
      );

      // Enable proof generation
      (document.getElementById('verifyAgeBtn') as HTMLButtonElement).disabled = false;
      (document.getElementById('verifyNationalityBtn') as HTMLButtonElement).disabled = false;
    } else {
      showResult('issueResult', 'error', `<strong>✗ ${data.error}</strong>`);
    }
  } catch (error: any) {
    showResult('issueResult', 'error', `<strong>✗ ${formatApiError(error)}</strong>`);
  }
}

// Generate age proof
async function verifyAge() {
  if (!state.credential) {
    showResult('proofResult', 'error', '<strong>Please issue a credential first</strong>');
    return;
  }

  const minAge = parseInt((document.getElementById('minAge') as HTMLInputElement).value);

  showResult('proofResult', 'loading', '<strong>⏳ Generating ZK proof in browser...</strong>');
  showResult('verifyResult', 'loading', '<strong>Waiting for proof...</strong>');

  try {
    // Fetch challenge
    const challengeResponse = await fetch(`${API_BASE_URL}/api/challenge`);
    const challenge = await challengeResponse.json();

    // Prepare circuit inputs
    const currentYear = new Date().getFullYear();
    const requestTimestampMs = Date.parse(challenge.requestTimestamp);
    const saltDecimal = BigInt('0x' + state.credential.credential.salt).toString();

    const inputs = {
      birthYear: state.credential.credential.birthYear.toString(),
      nationality: state.credential.credential.nationality.toString(),
      salt: saltDecimal,
      currentYear: currentYear.toString(),
      minAge: minAge.toString(),
      credentialHash: state.credential.credential.commitment,
      nonce: challenge.nonce.toString(),
      requestTimestamp: requestTimestampMs.toString(),
    };

    // Generate proof (circuit files are served from the API server)
    const proofStart = Date.now();
    const { proof, publicSignals } = await (window as any).snarkjs.groth16.fullProve(
      inputs,
      `${API_BASE_URL}/circuits/age-verify_js/age-verify.wasm`,
      `${API_BASE_URL}/circuits/age-verify.zkey`,
    );
    const proofTime = Date.now() - proofStart;

    showResult('proofResult', 'success', `<strong>✓ Proof generated in ${proofTime}ms</strong>`);

    // Format and send proof
    const formattedProof = {
      proof: {
        pi_a: proof.pi_a.slice(0, 2),
        pi_b: proof.pi_b.slice(0, 2),
        pi_c: proof.pi_c.slice(0, 2),
        protocol: proof.protocol,
        curve: proof.curve,
      },
      publicSignals: {
        currentYear: parseInt(publicSignals[0]),
        minAge: parseInt(publicSignals[1]),
        credentialHash: publicSignals[2],
        nonce: publicSignals[3],
        requestTimestamp: parseInt(publicSignals[4]),
      },
    };

    const verifyResponse = await fetch(`${API_BASE_URL}/api/verify-age`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        proof: formattedProof,
        nonce: challenge.nonce,
        requestTimestamp: challenge.requestTimestamp,
        claimType: 'age',
        credentialId: state.credentialId,
        signedCredential: state.credential,
      }),
    });

    const result = await verifyResponse.json();

    if (result.verified) {
      showResult(
        'verifyResult',
        'success',
        `
          <strong>✓ Age Verification Successful</strong>
          <p style="margin: 12px 0 0;">User is at least ${minAge} years old.</p>
          <div style="margin-top: 16px; padding: 12px; background: var(--bg-elevated); border-radius: 6px;">
            <div style="font-size: 12px; color: var(--text-muted); margin-bottom: 8px;">PRIVACY ANALYSIS</div>
            <div style="font-size: 13px;">
              <div style="color: var(--accent-client);">✓ Birth year kept private (${state.credential.credential.birthYear})</div>
              <div style="color: var(--accent-client);">✓ Nationality kept private (${state.credential.credential.nationality})</div>
              <div style="color: var(--accent-server);">📤 Revealed: Age ≥ ${minAge}</div>
            </div>
          </div>
        `,
      );
    } else {
      showResult(
        'verifyResult',
        'error',
        `<strong>✗ ${result.error || 'Verification failed'}</strong>`,
      );
    }
  } catch (error: any) {
    let errorMsg = formatApiError(error);
    if (error.message?.includes('Assert Failed')) {
      const actualAge = new Date().getFullYear() - state.credential.credential.birthYear;
      errorMsg = `Cannot generate proof: Your age (${actualAge}) does not meet the requirement (${minAge}). ZK proofs can only prove true statements.`;
    }
    showResult('proofResult', 'error', `<strong>✗ ${errorMsg}</strong>`);
    showResult('verifyResult', 'error', '<strong>Proof generation failed</strong>');
  }
}

// Generate nationality proof
async function verifyNationality() {
  if (!state.credential) {
    showResult('proofResult', 'error', '<strong>Please issue a credential first</strong>');
    return;
  }

  const targetNationality = parseInt(
    (document.getElementById('targetNationality') as HTMLSelectElement).value,
  );

  showResult('proofResult', 'loading', '<strong>⏳ Generating ZK proof in browser...</strong>');
  showResult('verifyResult', 'loading', '<strong>Waiting for proof...</strong>');

  try {
    // Fetch challenge
    const challengeResponse = await fetch(`${API_BASE_URL}/api/challenge`);
    const challenge = await challengeResponse.json();

    // Prepare circuit inputs
    const requestTimestampMs = Date.parse(challenge.requestTimestamp);
    const saltDecimal = BigInt('0x' + state.credential.credential.salt).toString();

    const inputs = {
      birthYear: state.credential.credential.birthYear.toString(),
      nationality: state.credential.credential.nationality.toString(),
      salt: saltDecimal,
      targetNationality: targetNationality.toString(),
      credentialHash: state.credential.credential.commitment,
      nonce: challenge.nonce.toString(),
      requestTimestamp: requestTimestampMs.toString(),
    };

    // Generate proof (circuit files are served from the API server)
    const proofStart = Date.now();
    const { proof, publicSignals } = await (window as any).snarkjs.groth16.fullProve(
      inputs,
      `${API_BASE_URL}/circuits/nationality-verify_js/nationality-verify.wasm`,
      `${API_BASE_URL}/circuits/nationality-verify.zkey`,
    );
    const proofTime = Date.now() - proofStart;

    showResult('proofResult', 'success', `<strong>✓ Proof generated in ${proofTime}ms</strong>`);

    // Format and send proof
    const formattedProof = {
      proof: {
        pi_a: proof.pi_a.slice(0, 2),
        pi_b: proof.pi_b.slice(0, 2),
        pi_c: proof.pi_c.slice(0, 2),
        protocol: proof.protocol,
        curve: proof.curve,
      },
      publicSignals: {
        targetNationality: parseInt(publicSignals[0]),
        credentialHash: publicSignals[1],
        nonce: publicSignals[2],
        requestTimestamp: parseInt(publicSignals[3]),
      },
    };

    const verifyResponse = await fetch(`${API_BASE_URL}/api/verify-nationality`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        proof: formattedProof,
        nonce: challenge.nonce,
        requestTimestamp: challenge.requestTimestamp,
        claimType: 'nationality',
        credentialId: state.credentialId,
        signedCredential: state.credential,
      }),
    });

    const result = await verifyResponse.json();

    if (result.verified) {
      const nationalityName = getNationalityName(targetNationality);
      showResult(
        'verifyResult',
        'success',
        `
          <strong>✓ Nationality Verification Successful</strong>
          <p style="margin: 12px 0 0;">User has nationality: ${nationalityName}</p>
          <div style="margin-top: 16px; padding: 12px; background: var(--bg-elevated); border-radius: 6px;">
            <div style="font-size: 12px; color: var(--text-muted); margin-bottom: 8px;">PRIVACY ANALYSIS</div>
            <div style="font-size: 13px;">
              <div style="color: var(--accent-client);">✓ Birth year kept private (${state.credential.credential.birthYear})</div>
              <div style="color: var(--accent-client);">✓ Age kept private</div>
              <div style="color: var(--accent-server);">📤 Revealed: Nationality = ${nationalityName}</div>
            </div>
          </div>
        `,
      );
    } else {
      showResult(
        'verifyResult',
        'error',
        `<strong>✗ ${result.error || 'Verification failed'}</strong>`,
      );
    }
  } catch (error: any) {
    let errorMsg = formatApiError(error);
    if (error.message?.includes('Assert Failed')) {
      errorMsg = `Cannot generate proof: Your nationality (${state.credential.credential.nationality}) does not match target (${targetNationality}). ZK proofs can only prove true statements.`;
    }
    showResult('proofResult', 'error', `<strong>✗ ${errorMsg}</strong>`);
    showResult('verifyResult', 'error', '<strong>Proof generation failed</strong>');
  }
}

// Event listeners
document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('issueBtn')?.addEventListener('click', issueCredential);
  document.getElementById('verifyAgeBtn')?.addEventListener('click', verifyAge);
  document.getElementById('verifyNationalityBtn')?.addEventListener('click', verifyNationality);

  // Proof type tab switching
  const proofTabs = document.querySelectorAll('.proof-tab');
  proofTabs.forEach((tab) => {
    tab.addEventListener('click', () => {
      const type = tab.getAttribute('data-type');

      proofTabs.forEach((t) => t.classList.remove('active'));
      tab.classList.add('active');

      document.querySelectorAll('.proof-form').forEach((form) => {
        (form as HTMLElement).style.display = 'none';
      });

      const targetForm = document.querySelector(`.${type}-form`) as HTMLElement;
      if (targetForm) {
        targetForm.style.display = 'block';
      }
    });
  });
});
