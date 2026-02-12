---
title: 'ZK + OpenID4VP for EU Compliance: Privacy-First Age Verification'
description: 'How zero-knowledge proofs and OpenID4VP enable GDPR-compliant age verification without collecting personal data'
date: 2026-02-11
author: 'zk-id Team'
tags: ['Privacy', 'Compliance', 'OpenID4VP', 'GDPR', 'eIDAS', 'DSA']
draft: false
---

## The Problem: Age Verification vs. Privacy

Age verification on the internet has always been a privacy nightmare. Current solutions force users to choose between:

1. **Manual birthdate entry**: Zero security, easily bypassed, creates data liability
2. **ID document upload**: Massive privacy violation, expensive ($0.50-2 per verification), creates honeypots for identity theft
3. **Third-party KYC services**: Tracking, data sharing, regulatory complexity

**The fundamental tension**: You need to verify someone is 18+ without actually knowing their birthdate.

This is especially critical in the EU, where:
- **GDPR** requires data minimization and purpose limitation
- **DSA (Digital Services Act)** mandates age verification for platforms
- **eIDAS 2.0** is rolling out digital identity wallets across member states

Traditional age verification solutions violate GDPR's data minimization principle by collecting unnecessary personal data.

## Why Zero-Knowledge Proofs Solve This

Zero-knowledge (ZK) proofs are a cryptographic primitive that lets you prove a statement is true without revealing _why_ it's true.

**Applied to age verification**:
- **Traditional**: "Here's my birthdate: 1990-06-15" → Verifier learns exact age
- **Zero-knowledge**: "I'm >= 18" → Verifier learns only the binary fact, nothing else

**How it works technically**:

1. **Credential issuance**: A trusted issuer (government ID provider, bank) signs your birthdate with EdDSA
2. **Proof generation**: Your device generates a ZK-SNARK proving `currentYear - birthYear >= 18` without revealing `birthYear`
3. **Verification**: The verifier checks the cryptographic proof without learning your birthdate

**Key properties**:
- ✅ **Zero knowledge**: Birth year never leaves your device
- ✅ **Sound**: Cryptographically impossible to fake (128-bit security)
- ✅ **Binding**: Proof is tied to a specific credential signed by a trusted issuer
- ✅ **Non-interactive**: No back-and-forth protocol, just submit proof once

## OpenID4VP for Interoperability

Zero-knowledge is powerful, but proprietary ZK systems create vendor lock-in. Enter **OpenID4VP** (OpenID for Verifiable Presentations).

OpenID4VP is a W3C/OIDF standard that defines how:
- **Verifiers** request credentials
- **Wallets** present credentials
- **Issuers** provide credentials

**Why this matters**:
- Any OpenID4VP-compliant wallet works with any verifier
- Follows OAuth 2.0 patterns familiar to developers
- Integrates with existing SSO infrastructure
- Aligns with EU Digital Identity Wallet (EUDI Wallet) roadmap

**zk-id** is the first OpenID4VP implementation with true zero-knowledge proofs. Other implementations use:
- **Selective Disclosure JWT (SD-JWT)**: Reveals birthdate, not zero-knowledge
- **Anonymous Credentials**: Complex setup, limited adoption

## Demo Walkthrough

We've built a fully functional demo that runs locally in 3 minutes:

### Step 1: Issue a Credential (30 seconds)

```bash
cd examples/openid4vp-demo
npm start
```

Visit http://localhost:3000. On the right panel (Browser Wallet):
1. Enter a test birthdate
2. Click "Issue Credential from Issuer"
3. Credential appears in wallet

**What happened**: The issuer server signed your credential using EdDSA (same crypto as Signal, Telegram).

### Step 2: Create Verification Request (15 seconds)

On the left panel (Verifier):
1. Set minimum age (default: 18)
2. Click "Create Authorization Request"
3. QR code appears

**What happened**: The verifier created an OpenID4VP authorization request following DIF Presentation Exchange v2.0.

### Step 3: Generate & Verify Proof (60 seconds)

On the right panel:
1. Click "Generate & Submit Proof"
2. Wait ~45 seconds (first proof loads circuit)
3. Result appears: ✅ Verified

**What happened**:
1. Your browser loaded a ZK circuit (5MB WASM + zkey)
2. Generated a ZK-SNARK proving `age >= 18`
3. Packaged it as a W3C Verifiable Presentation
4. Submitted to verifier via OpenID4VP callback
5. Verifier verified the proof cryptographically

**Key insight**: The verifier confirmed you're 18+ without learning your birthdate.

## EU Regulatory Alignment

### GDPR Compliance

zk-id satisfies multiple GDPR requirements:

**Article 5(1)(c) - Data Minimization**:
> "Personal data shall be adequate, relevant and limited to what is necessary."

✅ Only the binary fact (age >= 18) is transmitted. Birthdate never leaves the device.

**Article 25 - Privacy by Design**:
> "The controller shall implement appropriate technical and organisational measures... designed to implement data-protection principles."

✅ ZK proofs are privacy by design at the cryptographic layer.

**Article 9 - Special Categories**:
> "Processing of personal data revealing... health, sex life or sexual orientation... shall be prohibited."

✅ Age-gating adult content without collecting "special category" data.

### DSA (Digital Services Act)

**Article 28 - Protection of Minors**:
> "Providers of online platforms accessible to minors shall put in place appropriate and proportionate measures to ensure a high level of privacy, safety, and security of minors."

Traditional solutions:
- Upload ID → Creates data breach risk, violates Article 28's "high level of privacy"
- Manual birthdate entry → Easily bypassed, fails "appropriate measures"

**zk-id**:
- ✅ High privacy (ZK proof)
- ✅ Strong security (128-bit soundness)
- ✅ Proportionate (no data collection)

### eIDAS 2.0 & EU Digital Identity Wallet

eIDAS 2.0 (effective 2026) mandates EU member states provide digital identity wallets. These wallets will:
- Store government-issued credentials (passport, driver's license)
- Support selective disclosure and privacy-preserving proofs
- Use OpenID4VP and ISO mDOC standards

**zk-id's positioning**:
- ✅ OpenID4VP-compliant (interoperable with EUDI Wallets)
- ✅ Supports selective disclosure (BBS+ credentials)
- ✅ Zero-knowledge proofs (next-gen privacy)

When EUDI Wallets roll out, zk-id-powered verifiers will work out-of-the-box.

## Try It Yourself

### 1. Run the Demo

```bash
git clone https://github.com/star7js/zk-id.git
cd zk-id
npm install
npm run compile:circuits
npm run --workspace=@zk-id/circuits setup
cd examples/openid4vp-demo
npm start
```

Visit http://localhost:3000 and walk through the 3-step flow.

### 2. Embed in Your Site (3 Lines)

For a quick integration, use our age-gate widget:

```typescript
import { ZkIdAgeGateWidget } from '@zk-id/age-gate-widget';

ZkIdAgeGateWidget.init({
  verificationEndpoint: 'https://your-verifier.com/auth/request',
  minAge: 18,
  onVerified: () => showRestrictedContent(),
});
```

See [age-gate widget demo](https://zk-id.io/examples/age-gate-widget).

### 3. Deploy Your Own Verifier

```bash
npm install @zk-id/sdk

# See examples/openid4vp-demo/src/verifier.ts for a full example
```

## Technical Deep Dive

*To be expanded with human-written content:*

- Circuit architecture (Groth16, Circom)
- Signature verification (EdDSA in ZK)
- Commitment schemes (Poseidon hash)
- Presentation Exchange mappings
- BBS+ for selective disclosure
- Range proofs and predicate logic

## Roadmap

- **Q1 2026**: Mobile SDK (React Native, Flutter)
- **Q2 2026**: EUDI Wallet integration
- **Q3 2026**: Custom predicate circuits (nationality, income ranges)
- **Q4 2026**: Recursive proofs for multi-credential composition

## Get Involved

- **Try it**: [Live Demo](https://zk-id.io/playground)
- **Build it**: [Integration Guide](https://zk-id.io/docs/integration-guide)
- **Contribute**: [GitHub](https://github.com/star7js/zk-id)
- **Discuss**: [GitHub Discussions](https://github.com/star7js/zk-id/discussions)

---

*Questions? Open an [issue on GitHub](https://github.com/star7js/zk-id/issues) or join the discussion.*
