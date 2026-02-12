# AI Agent Credentials

**Status:** Research / Prototype Concept
**Last Updated:** 2026-02-11

## Abstract

AI agents increasingly operate autonomously in digital environments, making decisions and taking actions on behalf of organizations and users. However, there is currently no standardized, cryptographically-secure method for verifying agent identity, proving capabilities, or establishing delegation chains. This document explores how BBS+ credentials with schema flexibility can provide verifiable identity for AI agents.

---

## 1. Problem Statement

### 1.1 The Challenge

AI agents face unique identity challenges:

1. **Identity Verification**: How can a verifier confirm that an agent is authentic and deployed by a trusted organization?
2. **Capability Attestation**: How can an agent prove what it is authorized to do without over-sharing?
3. **Delegation Chains**: How can we track when org → agent → sub-agent delegations occur?
4. **Model Binding**: How do we tie agent identity to a specific model version or deployment?
5. **Revocation**: How do we revoke agent credentials when models are deprecated or compromised?

### 1.2 Current Approaches and Limitations

| Approach                            | Strengths                      | Weaknesses                                                             |
| ----------------------------------- | ------------------------------ | ---------------------------------------------------------------------- |
| **API Keys**                        | Simple, widely supported       | No cryptographic binding, easily leaked, no capability attestation     |
| **OAuth 2.0 / Client Credentials**  | Industry standard, token-based | Not designed for agent-specific metadata (model version, capabilities) |
| **mTLS**                            | Strong cryptographic binding   | Certificate management overhead, no selective disclosure               |
| **JSON Web Tokens (JWT)**           | Self-contained, stateless      | No privacy-preserving selective disclosure                             |
| **W3C Verifiable Credentials (VC)** | Standard format, flexible      | Limited privacy features without ZK integration                        |

**Key Gap:** None of these provide:

- Privacy-preserving selective disclosure of capabilities
- Cryptographic binding to model version
- Delegation chain tracking with minimal information leakage

---

## 2. Proposed Solution: Agent Identity Schema

### 2.1 Schema Definition

zk-id Phase 2 introduces an `AGENT_IDENTITY_SCHEMA` (defined in `packages/core/src/bbs-schema.ts`):

```typescript
export const AGENT_IDENTITY_SCHEMA: BBSCredentialSchema = {
  id: 'agent-identity',
  version: '1.0.0',
  description: 'Identity credential for AI agents with capability attestation',
  fields: [
    {
      name: 'id',
      type: 'string',
      required: true,
      description: 'Unique credential identifier',
    },
    {
      name: 'agentId',
      type: 'string',
      required: true,
      description: 'Unique agent identifier (e.g., DID or deployment ID)',
    },
    {
      name: 'organizationId',
      type: 'string',
      required: true,
      description: 'Organization that deployed the agent',
    },
    {
      name: 'capabilities',
      type: 'string',
      required: true,
      description: 'JSON-encoded capability list',
    },
    {
      name: 'modelVersion',
      type: 'string',
      required: true,
      description: 'AI model version identifier (e.g., "gpt-4-0125", "claude-sonnet-4.5")',
    },
    {
      name: 'salt',
      type: 'string',
      required: true,
      description: 'Random salt for credential uniqueness',
    },
  ],
};
```

### 2.2 Example Credential

```json
{
  "schemaId": "agent-identity",
  "fields": {
    "id": "agent-cred-12345",
    "agentId": "did:example:ai-agent-finance-001",
    "organizationId": "acme-corp",
    "capabilities": "[\"read:transactions\",\"write:invoices\"]",
    "modelVersion": "gpt-4-0125-preview",
    "salt": "0x..."
  },
  "signature": "...",
  "publicKey": "...",
  "issuer": "acme-corp-issuer",
  "issuedAt": "2026-02-11T10:00:00Z",
  "expiresAt": "2026-03-11T10:00:00Z"
}
```

### 2.3 BBS+ Selective Disclosure Flow

1. **Issuance**: Organization issues BBS+ agent credential binding identity, capabilities, and model version
2. **Presentation Request**: API gateway requests proof of specific capability (e.g., "read:transactions")
3. **Selective Disclosure**: Agent reveals only `organizationId`, `capabilities`, and proves the credential is signed by a trusted issuer
4. **Verification**: Gateway verifies BBS+ proof without learning `agentId` or `modelVersion`

---

## 3. Capability Attestation

### 3.1 Capability Format

Capabilities are JSON-encoded strings following OAuth 2.0 scope conventions:

```json
["read:documents", "write:invoices", "delete:temp-files", "admin:user-management"]
```

### 3.2 Fine-Grained Disclosure

Using BBS+ selective disclosure:

| Scenario          | Revealed Fields                                             | Hidden Fields                     |
| ----------------- | ----------------------------------------------------------- | --------------------------------- |
| Public API access | `organizationId`, `capabilities`                            | `agentId`, `modelVersion`, `salt` |
| Internal audit    | `agentId`, `organizationId`, `modelVersion`, `capabilities` | `salt`                            |
| Capability check  | `capabilities` only                                         | All others                        |

This minimizes information leakage while proving authorization.

---

## 4. Delegation Chains

### 4.1 Delegation Credential Schema

For agent-to-agent delegation, use the `CAPABILITY_SCHEMA`:

```typescript
export const CAPABILITY_SCHEMA: BBSCredentialSchema = {
  id: 'capability',
  version: '1.0.0',
  description: 'Capability credential for delegated authorization',
  fields: [
    {
      name: 'id',
      type: 'string',
      required: true,
      description: 'Unique credential identifier',
    },
    {
      name: 'capability',
      type: 'string',
      required: true,
      description: 'Capability identifier (e.g., "read", "write", "admin")',
    },
    {
      name: 'scope',
      type: 'string',
      required: true,
      description: 'Resource scope (e.g., "api:documents", "service:payments")',
    },
    {
      name: 'delegator',
      type: 'string',
      required: true,
      description: 'Identity of the delegating party (agent or org)',
    },
    {
      name: 'delegatee',
      type: 'string',
      required: true,
      description: 'Identity of the receiving party (sub-agent)',
    },
    {
      name: 'issuedAt',
      type: 'string',
      required: true,
      description: 'ISO 8601 issuance timestamp',
    },
    {
      name: 'expiresAt',
      type: 'string',
      required: false,
      description: 'ISO 8601 expiration timestamp',
    },
    {
      name: 'salt',
      type: 'string',
      required: true,
      description: 'Random salt for credential uniqueness',
    },
  ],
};
```

### 4.2 Delegation Chain Example

```
Acme Corp (Issuer)
  ↓ issues AGENT_IDENTITY_SCHEMA
Agent A (Orchestrator)
  ↓ issues CAPABILITY_SCHEMA
Agent B (Worker)
```

Agent B can selectively disclose:

- That it was delegated by Agent A
- The specific capability it has
- Proof it's authorized by Acme Corp (via Agent A's credential)

Without revealing:

- Agent B's full identity
- Agent A's model version
- Timestamps unless required

---

## 5. Credential Binding to Model/Deployment

### 5.1 Model Version Field

The `modelVersion` field binds credentials to a specific AI model:

```json
{
  "modelVersion": "claude-sonnet-4.5-20250929"
}
```

This enables:

- **Revocation on model deprecation**: When a model is sunset, all credentials for that version can be revoked
- **Audit trails**: Track which model version made which decisions
- **Policy enforcement**: "Only allow GPT-4 or newer for financial operations"

### 5.2 Deployment Binding

For ephemeral agents (e.g., serverless functions), bind to deployment ID:

```json
{
  "agentId": "lambda-fn-invoice-processor-v3-abc123",
  "modelVersion": "gpt-4-0125-preview"
}
```

---

## 6. Standards Tracking

### 6.1 Relevant Standards

| Standard                            | Status                | Relevance to Agent Credentials                                      |
| ----------------------------------- | --------------------- | ------------------------------------------------------------------- |
| **NIST AI 100-4**                   | Draft (2024)          | AI Risk Management Framework — recommends verifiable agent identity |
| **IETF draft-ietf-oauth-sd-jwt-vc** | Active                | Selective Disclosure JWT for VCs — alternative to BBS+              |
| **W3C Verifiable Credentials 2.0**  | Recommendation (2024) | Standard VC format — can embed BBS+ proofs                          |
| **OpenID4VP**                       | Draft                 | Presentation protocol — already integrated in zk-id                 |
| **DID Core 1.0**                    | Recommendation (2022) | Decentralized identifiers — can be used for `agentId`               |

### 6.2 Integration Path

zk-id agent credentials are compatible with:

- **W3C VC 2.0**: Wrap BBS+ credentials in VC envelope
- **OpenID4VP**: Use `createBBSDisclosureRequest()` for agent verification
- **DID**: Use DIDs as `agentId` and `organizationId`

---

## 7. Comparison with Existing Approaches

### 7.1 Agent Credentials vs. API Keys

| Feature               | API Keys                   | BBS+ Agent Credentials          |
| --------------------- | -------------------------- | ------------------------------- |
| Privacy               | None (key is the identity) | Selective disclosure            |
| Capability Expression | Implicit in key            | Explicit, provable              |
| Delegation            | Not supported              | Built-in with CAPABILITY_SCHEMA |
| Model Binding         | Not possible               | Cryptographically bound         |
| Revocation            | Delete key (stateful)      | Revocation store or expiry      |

### 7.2 Agent Credentials vs. OAuth 2.0 Client Credentials

| Feature              | OAuth 2.0                    | BBS+ Agent Credentials        |
| -------------------- | ---------------------------- | ----------------------------- |
| Standard Adoption    | Very high                    | Emerging                      |
| Token Privacy        | Low (JWT readable)           | High (BBS+ ZK disclosure)     |
| Model Metadata       | Not standard                 | First-class field             |
| Delegation           | OAuth delegation grants      | Native with CAPABILITY_SCHEMA |
| Offline Verification | Requires token introspection | BBS+ proofs verify offline    |

### 7.3 Agent Credentials vs. mTLS

| Feature               | mTLS                       | BBS+ Agent Credentials            |
| --------------------- | -------------------------- | --------------------------------- |
| Authentication        | Strong (X.509 certs)       | Strong (BBS+ signatures)          |
| Selective Disclosure  | None (full cert exposed)   | Fine-grained field disclosure     |
| Capability Expression | X.509 extensions (limited) | Structured JSON capabilities      |
| Management Overhead   | High (cert rotation, CRLs) | Lower (revocation stores, expiry) |

---

## 8. Prototype Implementation Path

### 8.1 Phase 1: Schema-Aware Issuance (✓ Complete)

- [x] Define `AGENT_IDENTITY_SCHEMA` and `CAPABILITY_SCHEMA`
- [x] Implement schema-aware BBS+ issuance (`BBSCredentialIssuer.issueSchemaCredential`)
- [x] Add BBS issuer endpoint (`POST /issue/bbs`) to issuer server

### 8.2 Phase 2: Verification Integration (✓ Complete)

- [x] Add agent-specific verification policies to `ZkIdServer`
- [x] Implement capability matching logic (scope-based authorization)
- [x] Create OpenID4VP flows for agent presentation requests

**Implemented:**

- `verifyCapabilityChain()` in `bbs-schema.ts` - validates delegation chains
- `matchCapability()` in `bbs-schema.ts` - checks capability grants with wildcard support
- `createAgentVerificationRequest()` in OpenID4VPVerifier - creates presentation requests for agent credentials

### 8.3 Phase 3: Delegation Support

- [ ] Implement CAPABILITY_SCHEMA credential issuance for delegation
- [ ] Add chain-of-trust verification (Agent B proves Agent A delegated, Agent A proves Org issued)
- [ ] Create delegation visualization tools (audit logs)

### 8.4 Phase 4: Production Hardening

- [ ] Add revocation mechanism for model version sunset
- [ ] Implement key rotation for long-lived agents
- [ ] Create developer SDKs (Python, Go) for agent integration
- [ ] Write comprehensive security audit documentation

---

## 9. End-to-End Usage Example

### 9.1 Issuance: Organization Issues Agent Credential

```typescript
import { BBSCredentialIssuer } from '@zk-id/issuer';

// Organization issues agent-identity credential
const issuer = new BBSCredentialIssuer();
await issuer.initialize();

const agentCredential = await issuer.issueSchemaCredential('agent-identity', {
  id: 'cred-001',
  agentId: 'agent-gpt4-prod-001',
  organizationId: 'org-acme-corp',
  capabilities: JSON.stringify(['api:read', 'api:write', 'database:read']),
  modelVersion: 'gpt-4-turbo-2024-04-09',
  salt: crypto.randomBytes(32).toString('hex'),
});

// Issuer endpoint: POST /issue/bbs
// Body: { schemaId: 'agent-identity', fields: {...} }
```

### 9.2 Delegation: Agent A Delegates to Agent B

```typescript
// Agent A delegates 'api:read' capability to Agent B
const delegationCredential = await issuer.issueSchemaCredential('capability', {
  id: 'cap-delegation-001',
  capability: 'api:read',
  scope: 'api:documents/*',
  delegator: 'agent-gpt4-prod-001', // Agent A
  delegatee: 'agent-claude-assistant-002', // Agent B
  issuedAt: new Date().toISOString(),
  expiresAt: new Date(Date.now() + 3600000).toISOString(), // 1 hour
  salt: crypto.randomBytes(32).toString('hex'),
});
```

### 9.3 Selective Disclosure: Agent Reveals Only Necessary Fields

```typescript
import { createBBSDisclosureProof } from '@zk-id/core';

// Agent B creates a disclosure proof revealing only agentId and organizationId
const disclosureProof = await createBBSDisclosureProof(
  agentCredential,
  ['agentId', 'organizationId'], // Only reveal these fields
  issuer.getPublicKey(),
  'nonce-12345',
);

// Result: Cryptographic proof + revealed fields
// Hidden: capabilities, modelVersion, salt
```

### 9.4 Verification: Service Verifies Agent Credential

```typescript
import { OpenID4VPVerifier, verifyCapabilityChain, matchCapability } from '@zk-id/sdk';

// Create verification request for agent credentials
const verifier = new OpenID4VPVerifier({
  verifierId: 'document-service',
  verifierUrl: 'https://docs.example.com',
});

// Request agent-identity credential
const authRequest = verifier.createAgentVerificationRequest(
  'agent-identity',
  undefined,
  undefined,
  'state-xyz',
);

// Or request specific capability
const capabilityRequest = verifier.createAgentVerificationRequest(
  'capability',
  'api:read',
  'api:documents',
  'state-abc',
);

// Verify capability chain (multi-hop delegation)
const credentials = [rootCredential, delegationCredential]; // Agent B's chain
const result = verifyCapabilityChain(credentials, 'api:read', 'api:documents/report-2024');

if (result.valid) {
  console.log('✓ Agent authorized to access api:documents/report-2024');
} else {
  console.error('✗ Authorization failed:', result.errors);
}

// Single credential capability check
if (matchCapability(delegationCredential, 'api:read', 'api:documents/report-2024')) {
  console.log('✓ Capability granted');
}
```

### 9.5 Complete Flow: Agent-to-Service Authentication

```typescript
// 1. Service creates verification request
const { authRequest, deepLink } = verifier.createAgentVerificationRequest(
  'capability',
  'api:write',
  'api:documents',
);

// 2. Agent receives request and creates disclosure proof
const proof = await createBBSDisclosureProof(
  agentCredential,
  ['capability', 'scope', 'delegatee'], // Reveal required fields
  issuerPublicKey,
  authRequest.nonce,
);

// 3. Agent submits proof to service
const response = await fetch(authRequest.response_uri, {
  method: 'POST',
  body: JSON.stringify({ proof, state: authRequest.state }),
});

// 4. Service validates proof and grants access
const verified = await verifier.verifyPresentation(response);
if (verified.valid && matchCapability(verified.credential, 'api:write', 'api:documents')) {
  // Grant API access
  return { authorized: true, agentId: verified.credential.fields.delegatee };
}
```

---

## 10. Security Considerations

### 10.1 Threats

| Threat                  | Mitigation                                                                            |
| ----------------------- | ------------------------------------------------------------------------------------- |
| **Credential Theft**    | Short-lived credentials (1-hour expiry), credential binding to deployment environment |
| **Replay Attacks**      | Nonce-based proof generation, timestamp validation                                    |
| **Delegation Abuse**    | Capability scoping, delegation depth limits, audit logging                            |
| **Model Impersonation** | Bind credentials to specific model version, verify signatures                         |

### 10.2 Best Practices

1. **Short Expiry**: Agent credentials should expire within hours, not days
2. **Minimal Disclosure**: Only reveal fields necessary for the specific verification
3. **Audit Logging**: Log all credential issuances and verifications for compliance
4. **Model Version Updates**: Re-issue credentials when model versions change
5. **Revocation Monitoring**: Regularly check revocation stores for compromised credentials

---

## 11. Future Research Directions

### 11.1 On-Chain Agent Registries

Explore Ethereum smart contracts or Hyperledger for:

- Immutable agent deployment logs
- Public revocation lists
- Delegation chain transparency

### 11.2 Multi-Agent Coordination Protocols

How do multiple agents with BBS+ credentials coordinate?

- Secure multi-party computation with credential-based ACLs
- Agent swarms with shared capability pools

### 11.3 Human-in-the-Loop Attestation

Combine agent credentials with human approval:

- Agent proposes action, human issues time-limited capability credential
- Audit trail shows both agent identity and human approval

---

## 12. Conclusion

BBS+ credentials with schema flexibility provide a privacy-preserving, cryptographically-secure foundation for AI agent identity. By combining agent-specific metadata (model version, capabilities) with selective disclosure, organizations can:

1. **Verify agent authenticity** without over-sharing deployment details
2. **Prove capabilities** without revealing full permission sets
3. **Track delegation chains** with minimal information leakage
4. **Bind credentials to model versions** for lifecycle management

As AI agents become more autonomous, standardized credential systems like this will be critical for trust, compliance, and security.

---

## References

- **BBS+ Signatures**: [IETF Draft - BBS Signatures](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-signatures/)
- **W3C Verifiable Credentials**: [W3C VC Data Model 2.0](https://www.w3.org/TR/vc-data-model-2.0/)
- **OpenID4VP**: [OpenID for Verifiable Presentations](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
- **NIST AI 100-4**: [AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework)
- **zk-id Documentation**: [BBS+ Integration](./BBS.md), [OpenID4VP](./OPENID4VP.md)
