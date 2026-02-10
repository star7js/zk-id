# Standards Alignment

This document describes how zk-id maps to existing identity verification standards, particularly ISO 18013-5 (mobile Driving License) and ISO 18013-7 (online age verification).

## ISO 18013-5 (mDL)

ISO 18013-5 defines the data model and security mechanisms for mobile driving licenses (mDL). While zk-id is not an mDL implementation, it provides functional overlap for age and nationality verification.

### Data Element Mapping

| zk-id Attribute | mDL Element         | Identifier                            | Fidelity | Notes                                           |
| --------------- | ------------------- | ------------------------------------- | -------- | ----------------------------------------------- |
| `birthYear`     | `birth_date`        | `org.iso.18013.5.1.birth_date`        | Partial  | zk-id stores year only; mDL uses full date      |
| `nationality`   | `nationality`       | `org.iso.18013.5.1.nationality`       | Partial  | zk-id uses ISO 3166-1 numeric; mDL uses alpha-2 |
| `credential.id` | `document_number`   | `org.iso.18013.5.1.document_number`   | Partial  | Different identifier formats                    |
| `issuer`        | `issuing_authority` | `org.iso.18013.5.1.issuing_authority` | Partial  | String identifier vs. X.509 subject             |
| `issuedAt`      | `issue_date`        | `org.iso.18013.5.1.issue_date`        | Exact    | Both use ISO 8601                               |

### Country Code Conversion

zk-id uses ISO 3166-1 numeric codes (e.g., 840 for USA); mDL uses alpha-2 codes (e.g., "US"). The `@zk-id/issuer` package provides bidirectional conversion tables:

```typescript
import { ISO_3166_NUMERIC_TO_ALPHA2, ISO_3166_ALPHA2_TO_NUMERIC } from '@zk-id/issuer';

ISO_3166_NUMERIC_TO_ALPHA2[840]; // "US"
ISO_3166_ALPHA2_TO_NUMERIC['GB']; // 826
```

### mDL Element Export

Convert a zk-id credential to mDL-aligned data elements:

```typescript
import { toMdlElements } from '@zk-id/issuer';

const elements = toMdlElements(signedCredential, 'US');
// Returns: [
//   { identifier: "org.iso.18013.5.1.birth_date", value: "1990-01-01" },
//   { identifier: "org.iso.18013.5.1.nationality", value: "US" },
//   { identifier: "org.iso.18013.5.1.issuing_authority", value: "Gov-ID" },
//   ...
// ]
```

## ISO 18013-7 (Online Age Verification)

ISO 18013-7 defines the online presentation protocol for mDL, including `age_over_NN` attestation. This maps directly to zk-id's age proof system.

### Age-Over Attestation

When a zk-id age proof verifies successfully, the result can be expressed as an ISO 18013-7 `age_over_NN` attestation:

```typescript
import { createAgeOverAttestation } from '@zk-id/issuer';

// After successful verification of minAge=18:
const attestation = createAgeOverAttestation(18);
// {
//   ageThreshold: 18,
//   elementId: "org.iso.18013.5.1.age_over_18",
//   value: true
// }
```

### Privacy Comparison

| Feature                  | zk-id                         | ISO 18013-7                   |
| ------------------------ | ----------------------------- | ----------------------------- |
| Proves age >= threshold  | Yes (ZK proof)                | Yes (age_over_NN)             |
| Reveals exact birth date | No                            | No (for age_over)             |
| Reveals issuer identity  | Yes (in signed credential)    | Yes (in mDL)                  |
| Proof mechanism          | Groth16 ZK-SNARK              | Selective disclosure via MDOC |
| Offline support          | No (requires verifier server) | Yes (proximity via NFC/BLE)   |
| Replay protection        | Nonce + timestamp binding     | Session transcript hash       |

## Architectural Differences

| Concept            | zk-id                              | ISO 18013-5/7                    |
| ------------------ | ---------------------------------- | -------------------------------- |
| Credential binding | Poseidon commitment                | MSO (Mobile Security Object)     |
| Signature scheme   | Ed25519                            | ECDSA or EdDSA via COSE          |
| Issuer trust       | Registry with key rotation         | X.509 certificate chains (VICAL) |
| Revocation         | Merkle inclusion proof (valid-set) | Status lists (future extension)  |
| Proof system       | Groth16 on BN128                   | MDOC selective disclosure        |
| Transport          | HTTPS + JSON                       | MDOC + CBOR                      |

## Multi-Claim Proofs

zk-id supports proving multiple claims in a single verification session via the multi-claim API:

```typescript
import { createMultiClaimRequest, expandMultiClaimRequest } from '@zk-id/core';

const request = createMultiClaimRequest(
  [
    { label: 'drinking-age', claimType: 'age', minAge: 21 },
    { label: 'citizenship', claimType: 'nationality', targetNationality: 840 },
  ],
  nonce,
);

// Expand to individual proof requests (same nonce binding)
const proofRequests = expandMultiClaimRequest(request);
```

This parallels ISO 18013-7's capability to request multiple data elements in a single session, though the underlying mechanisms differ (ZK proofs vs. selective disclosure).

## Full Mapping Table

The complete programmatic mapping is available via `STANDARDS_MAPPINGS` in `@zk-id/issuer`:

```typescript
import { STANDARDS_MAPPINGS } from '@zk-id/issuer';

for (const m of STANDARDS_MAPPINGS) {
  console.log(`${m.zkIdConcept} → ${m.standard} ${m.standardConcept} (${m.fidelity})`);
}
```

## Roadmap

Future standards alignment work:

- W3C Verifiable Credentials Data Model 2.0 full compliance
- ISO 18013-5 CBOR/COSE encoding option
- IETF SD-JWT interoperability

---

Last updated: 2026-02-09
