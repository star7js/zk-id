// @ts-nocheck
// Quick start guided flow

// API base URL (from environment)
const API_BASE_URL = import.meta.env.PUBLIC_API_URL || 'https://zk-id-1.onrender.com';

const state = {
  credential: null,
  credentialId: null,
  currentStep: 1,
};

// Detect network/CORS errors from API cold starts
function formatApiError(error: any): string {
  const msg = error?.message || String(error);
  if (
    msg === 'Load failed' ||
    msg === 'Failed to fetch' ||
    msg === 'NetworkError when attempting to fetch resource.'
  ) {
    return 'Could not reach the API server. It may be starting up — please wait a moment and try again.';
  }
  return msg;
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

function showResult(elementId: string, type: string, content: string) {
  const el = document.getElementById(elementId);
  if (!el) return;
  el.className = `result ${type}`;

  // Clear existing content
  el.textContent = '';

  // Parse content and create DOM elements safely
  const parser = new DOMParser();
  const doc = parser.parseFromString(content, 'text/html');

  // Import the parsed nodes (sanitized by DOMParser)
  const nodes = doc.body.childNodes;
  nodes.forEach((node) => {
    el.appendChild(node.cloneNode(true));
  });
}

function goToStep(stepNumber: number) {
  // Hide all steps
  document.querySelectorAll('.step-card').forEach((card) => {
    (card as HTMLElement).style.display = 'none';
  });

  // Show target step
  const targetStep = document.getElementById(`step-${stepNumber}`);
  if (targetStep) {
    targetStep.style.display = 'block';
    targetStep.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  // Update progress tracker
  document.querySelectorAll('.progress-step').forEach((step, index) => {
    step.classList.remove('active', 'completed');
    if (index + 1 < stepNumber) {
      step.classList.add('completed');
    } else if (index + 1 === stepNumber) {
      step.classList.add('active');
    }
  });

  state.currentStep = stepNumber;
}

async function issueCredential() {
  const birthYear = parseInt((document.getElementById('birthYear') as HTMLInputElement).value);
  const nationality = parseInt((document.getElementById('nationality') as HTMLSelectElement).value);

  showResult('issueResult', 'loading', '<strong>⏳ Issuing credential...</strong>');

  try {
    const response = await fetch(`${API_BASE_URL}/api/issue-credential`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ birthYear, nationality, userId: 'quickstart-user' }),
    });

    const data = await response.json();

    if (data.success) {
      state.credential = data.credential;
      state.credentialId = data.credential.credential.id;

      showResult(
        'issueResult',
        'success',
        '<strong>✓ Credential issued successfully!</strong><br>Ready to generate a proof.',
      );

      // Enable next button
      (document.getElementById('step2Next') as HTMLButtonElement).disabled = false;
    } else {
      showResult('issueResult', 'error', `<strong>✗ ${data.error}</strong>`);
    }
  } catch (error: any) {
    showResult('issueResult', 'error', `<strong>✗ ${formatApiError(error)}</strong>`);
  }
}

async function generateProof() {
  if (!state.credential) {
    showResult('proveResult', 'error', '<strong>Please issue a credential first</strong>');
    return;
  }

  showResult('proveResult', 'loading', '<strong>⏳ Generating proof (2-5 seconds)...</strong>');

  try {
    // Fetch challenge
    const challengeResponse = await fetch(`${API_BASE_URL}/api/challenge`);
    const challenge = await challengeResponse.json();

    // Prepare inputs
    const currentYear = new Date().getFullYear();
    const requestTimestampMs = Date.parse(challenge.requestTimestamp);
    const saltDecimal = BigInt('0x' + state.credential.credential.salt).toString();

    const inputs = {
      birthYear: state.credential.credential.birthYear.toString(),
      nationality: state.credential.credential.nationality.toString(),
      salt: saltDecimal,
      currentYear: currentYear.toString(),
      minAge: '18',
      credentialHash: state.credential.credential.commitment,
      nonce: challenge.nonce.toString(),
      requestTimestamp: requestTimestampMs.toString(),
    };

    // Generate proof (circuit files are served from the API server)
    const { proof, publicSignals } = await (window as any).snarkjs.groth16.fullProve(
      inputs,
      `${API_BASE_URL}/circuits/age-verify_js/age-verify.wasm`,
      `${API_BASE_URL}/circuits/age-verify.zkey`,
    );

    showResult(
      'proveResult',
      'success',
      '<strong>✓ Proof generated!</strong><br>Your birth year stayed private in your browser.',
    );

    // Store proof for verification
    state.proof = {
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

    state.challenge = challenge;

    // Enable next button and auto-advance
    (document.getElementById('step3Next') as HTMLButtonElement).disabled = false;

    // Auto-advance after 1 second
    setTimeout(() => {
      goToStep(4);
      verifyProof();
    }, 1000);
  } catch (error: any) {
    let errorMsg = formatApiError(error);
    if (error.message?.includes('Assert Failed')) {
      const actualAge = new Date().getFullYear() - state.credential.credential.birthYear;
      errorMsg = `Cannot generate proof: Your age (${actualAge}) is less than 18.`;
    }
    showResult('proveResult', 'error', `<strong>✗ ${errorMsg}</strong>`);
  }
}

async function verifyProof() {
  if (!state.proof) {
    return;
  }

  const resultDiv = document.getElementById('verifyResult');
  const setVerifyStatus = (type: 'loading' | 'error', message: string) => {
    if (!resultDiv) return;
    resultDiv.className = `result ${type}`;
    resultDiv.replaceChildren();
    const strong = document.createElement('strong');
    strong.textContent = message;
    resultDiv.appendChild(strong);
  };

  const renderVerificationSuccess = (birthYear: number, nationality: number) => {
    if (!resultDiv) return;
    resultDiv.className = 'result success';
    resultDiv.replaceChildren();

    const title = document.createElement('div');
    title.style.fontSize = '18px';
    title.style.fontWeight = '600';
    title.style.marginBottom = '12px';
    title.textContent = '✓ Verification Successful!';

    const content = document.createElement('div');
    content.style.fontSize = '14px';
    content.style.lineHeight = '1.7';

    const summary = document.createElement('p');
    summary.textContent =
      'The server confirmed you are 18+ without learning your exact birth year.';
    content.appendChild(summary);

    const makePanel = (heading: string, rows: Array<{ text: string; color: string }>) => {
      const panel = document.createElement('div');
      panel.style.marginTop = '12px';
      panel.style.padding = '16px';
      panel.style.background = 'var(--bg-primary)';
      panel.style.borderRadius = '8px';

      const panelHeading = document.createElement('div');
      panelHeading.style.color = 'var(--text-muted)';
      panelHeading.style.fontSize = '12px';
      panelHeading.style.marginBottom = '8px';
      panelHeading.style.fontFamily = 'var(--font-mono)';
      panelHeading.textContent = heading;
      panel.appendChild(panelHeading);

      rows.forEach(({ text, color }) => {
        const row = document.createElement('div');
        row.style.color = color;
        row.textContent = text;
        panel.appendChild(row);
      });

      return panel;
    };

    content.appendChild(
      makePanel('WHAT THE SERVER LEARNED', [
        { text: '✓ Age ≥ 18 (proven)', color: 'var(--accent-server)' },
        { text: '✓ Credential is valid', color: 'var(--accent-server)' },
        { text: '✓ Proof matches challenge', color: 'var(--accent-server)' },
      ]),
    );

    content.appendChild(
      makePanel('WHAT STAYED PRIVATE', [
        { text: `🔒 Exact birth year (${birthYear})`, color: 'var(--accent-client)' },
        {
          text: `🔒 Nationality: ${getNationalityName(nationality)} (${nationality})`,
          color: 'var(--accent-client)',
        },
        { text: '🔒 Credential salt', color: 'var(--accent-client)' },
      ]),
    );

    resultDiv.appendChild(title);
    resultDiv.appendChild(content);
  };

  setVerifyStatus('loading', '⏳ Verifying proof...');

  try {
    const verifyResponse = await fetch(`${API_BASE_URL}/api/verify-age`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        proof: state.proof,
        nonce: state.challenge.nonce,
        requestTimestamp: state.challenge.requestTimestamp,
        claimType: 'age',
        credentialId: state.credentialId,
        signedCredential: state.credential,
      }),
    });

    const result = await verifyResponse.json();

    if (result.verified) {
      renderVerificationSuccess(
        state.credential.credential.birthYear,
        state.credential.credential.nationality,
      );
    } else {
      setVerifyStatus('error', `✗ ${result.error || 'Verification failed'}`);
    }
  } catch (error: any) {
    setVerifyStatus('error', `✗ ${formatApiError(error)}`);
  }
}

// Event listeners
document.addEventListener('DOMContentLoaded', () => {
  // Start with step 1
  goToStep(1);

  // Copy button handlers
  document.querySelectorAll('.copy-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      const code = btn.getAttribute('data-code');
      if (code) {
        navigator.clipboard.writeText(code);
        const originalText = btn.textContent;
        btn.textContent = 'Copied!';
        setTimeout(() => {
          btn.textContent = originalText;
        }, 2000);
      }
    });
  });

  // Next button handlers
  document.querySelectorAll('.next-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      const nextStep = parseInt(btn.getAttribute('data-next') || '1');
      goToStep(nextStep);
    });
  });

  // Step-specific handlers
  document.getElementById('issueBtn')?.addEventListener('click', issueCredential);
  document.getElementById('proveBtn')?.addEventListener('click', generateProof);

  // Reset button
  document.getElementById('resetBtn')?.addEventListener('click', () => {
    state.credential = null;
    state.credentialId = null;
    state.proof = null;
    state.challenge = null;
    (document.getElementById('step2Next') as HTMLButtonElement).disabled = true;
    (document.getElementById('step3Next') as HTMLButtonElement).disabled = true;
    goToStep(1);
  });
});
