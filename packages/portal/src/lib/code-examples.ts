// Code examples for the API reference page, keyed by "METHOD /path"

export interface CodeExample {
  typescript: string;
  python: string;
  go: string;
}

const BASE = 'http://localhost:3000';
const HEADER = 'X-ZkId-Protocol-Version: zk-id/1.0-draft';

export const codeExamples: Record<string, CodeExample> = {
  'GET /api/health': {
    typescript: `const res = await fetch('${BASE}/api/health', {
  headers: { 'X-ZkId-Protocol-Version': 'zk-id/1.0-draft' }
});
const data = await res.json();
// { status: "ok", issuer: "...", protocolVersion: "zk-id/1.0-draft" }`,

    python: `import requests

res = requests.get("${BASE}/api/health",
    headers={"X-ZkId-Protocol-Version": "zk-id/1.0-draft"})
data = res.json()
print(data["status"])  # "ok"`,

    go: `req, _ := http.NewRequest("GET", "${BASE}/api/health", nil)
req.Header.Set("X-ZkId-Protocol-Version", "zk-id/1.0-draft")

resp, err := http.DefaultClient.Do(req)
if err != nil {
    log.Fatal(err)
}
defer resp.Body.Close()

var result struct {
    Status          string \`json:"status"\`
    Issuer          string \`json:"issuer"\`
    ProtocolVersion string \`json:"protocolVersion"\`
}
json.NewDecoder(resp.Body).Decode(&result)
fmt.Println(result.Status) // "ok"`,
  },

  'GET /api/challenge': {
    typescript: `const res = await fetch('${BASE}/api/challenge', {
  headers: { 'X-ZkId-Protocol-Version': 'zk-id/1.0-draft' }
});
const challenge = await res.json();
// Use challenge.nonce and challenge.requestTimestamp
// when generating proofs
console.log(challenge.nonce);            // "a1b2c3..."
console.log(challenge.requestTimestamp); // "2026-01-15T12:00:00.000Z"`,

    python: `import requests

res = requests.get("${BASE}/api/challenge",
    headers={"X-ZkId-Protocol-Version": "zk-id/1.0-draft"})
challenge = res.json()
nonce = challenge["nonce"]
timestamp = challenge["requestTimestamp"]`,

    go: `req, _ := http.NewRequest("GET", "${BASE}/api/challenge", nil)
req.Header.Set("X-ZkId-Protocol-Version", "zk-id/1.0-draft")

resp, err := http.DefaultClient.Do(req)
if err != nil {
    log.Fatal(err)
}
defer resp.Body.Close()

var challenge struct {
    Nonce            string \`json:"nonce"\`
    RequestTimestamp string \`json:"requestTimestamp"\`
}
json.NewDecoder(resp.Body).Decode(&challenge)`,
  },

  'POST /api/issue-credential': {
    typescript: `const res = await fetch('${BASE}/api/issue-credential', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'X-ZkId-Protocol-Version': 'zk-id/1.0-draft'
  },
  body: JSON.stringify({
    birthYear: 1990,
    nationality: 840,  // ISO 3166-1: US
    userId: 'user-123'
  })
});
const data = await res.json();
// data.credential contains the SignedCredential
const credential = data.credential;
console.log(credential.credential.id);         // hex credential ID
console.log(credential.credential.commitment); // Poseidon hash`,

    python: `import requests

res = requests.post("${BASE}/api/issue-credential",
    headers={
        "Content-Type": "application/json",
        "X-ZkId-Protocol-Version": "zk-id/1.0-draft"
    },
    json={
        "birthYear": 1990,
        "nationality": 840,  # ISO 3166-1: US
        "userId": "user-123"
    })
data = res.json()
credential = data["credential"]
print(credential["credential"]["id"])`,

    go: `body, _ := json.Marshal(map[string]interface{}{
    "birthYear":   1990,
    "nationality": 840, // ISO 3166-1: US
    "userId":      "user-123",
})

req, _ := http.NewRequest("POST", "${BASE}/api/issue-credential",
    bytes.NewReader(body))
req.Header.Set("Content-Type", "application/json")
req.Header.Set("X-ZkId-Protocol-Version", "zk-id/1.0-draft")

resp, err := http.DefaultClient.Do(req)
if err != nil {
    log.Fatal(err)
}
defer resp.Body.Close()

var result struct {
    Success    bool            \`json:"success"\`
    Credential json.RawMessage \`json:"credential"\`
}
json.NewDecoder(resp.Body).Decode(&result)`,
  },

  'POST /api/verify-age': {
    typescript: `// 1. Get a challenge from the server
const challengeRes = await fetch('${BASE}/api/challenge');
const challenge = await challengeRes.json();

// 2. Generate proof client-side with snarkjs (browser)
const { proof, publicSignals } = await snarkjs.groth16.fullProve(
  circuitInputs, wasmPath, zkeyPath
);

// 3. Submit proof for verification
const res = await fetch('${BASE}/api/verify-age', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'X-ZkId-Protocol-Version': 'zk-id/1.0-draft'
  },
  body: JSON.stringify({
    claimType: 'age',
    proof: { proof, publicSignals },
    nonce: challenge.nonce,
    requestTimestamp: challenge.requestTimestamp,
    credentialId: credential.credential.id,
    signedCredential: credential
  })
});
const result = await res.json();
console.log(result.verified); // true
console.log(result.minAge);   // 18`,

    python: `import requests

# Proof must be generated client-side (browser/WASM).
# This shows how to submit a pre-generated proof.
res = requests.post("${BASE}/api/verify-age",
    headers={
        "Content-Type": "application/json",
        "X-ZkId-Protocol-Version": "zk-id/1.0-draft"
    },
    json={
        "claimType": "age",
        "proof": {
            "proof": proof_data,        # from snarkjs
            "publicSignals": signals     # from snarkjs
        },
        "nonce": challenge["nonce"],
        "requestTimestamp": challenge["requestTimestamp"],
        "credentialId": credential_id,
        "signedCredential": signed_credential
    })
result = res.json()
print(result["verified"])  # True`,

    go: `// Proof must be generated client-side (browser/WASM).
// This shows how to submit a pre-generated proof to the server.
body, _ := json.Marshal(map[string]interface{}{
    "claimType": "age",
    "proof": map[string]interface{}{
        "proof":         proofData,
        "publicSignals": publicSignals,
    },
    "nonce":            challenge.Nonce,
    "requestTimestamp": challenge.RequestTimestamp,
    "credentialId":     credentialID,
    "signedCredential": signedCredential,
})

req, _ := http.NewRequest("POST", "${BASE}/api/verify-age",
    bytes.NewReader(body))
req.Header.Set("Content-Type", "application/json")
req.Header.Set("X-ZkId-Protocol-Version", "zk-id/1.0-draft")

resp, err := http.DefaultClient.Do(req)
if err != nil {
    log.Fatal(err)
}
defer resp.Body.Close()

var result struct {
    Verified bool   \`json:"verified"\`
    MinAge   int    \`json:"minAge"\`
    Error    string \`json:"error"\`
}
json.NewDecoder(resp.Body).Decode(&result)`,
  },

  'POST /api/verify-nationality': {
    typescript: `// 1. Get a challenge from the server
const challengeRes = await fetch('${BASE}/api/challenge');
const challenge = await challengeRes.json();

// 2. Generate nationality proof client-side with snarkjs
const { proof, publicSignals } = await snarkjs.groth16.fullProve(
  circuitInputs, nationalityWasmPath, nationalityZkeyPath
);

// 3. Submit proof for verification
const res = await fetch('${BASE}/api/verify-nationality', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'X-ZkId-Protocol-Version': 'zk-id/1.0-draft'
  },
  body: JSON.stringify({
    claimType: 'nationality',
    proof: { proof, publicSignals },
    nonce: challenge.nonce,
    requestTimestamp: challenge.requestTimestamp,
    credentialId: credential.credential.id,
    signedCredential: credential
  })
});
const result = await res.json();
console.log(result.verified);    // true
console.log(result.nationality); // 840`,

    python: `import requests

res = requests.post("${BASE}/api/verify-nationality",
    headers={
        "Content-Type": "application/json",
        "X-ZkId-Protocol-Version": "zk-id/1.0-draft"
    },
    json={
        "claimType": "nationality",
        "proof": {
            "proof": proof_data,
            "publicSignals": signals
        },
        "nonce": challenge["nonce"],
        "requestTimestamp": challenge["requestTimestamp"],
        "credentialId": credential_id,
        "signedCredential": signed_credential
    })
result = res.json()
print(result["verified"])     # True
print(result["nationality"])  # 840`,

    go: `body, _ := json.Marshal(map[string]interface{}{
    "claimType": "nationality",
    "proof": map[string]interface{}{
        "proof":         proofData,
        "publicSignals": publicSignals,
    },
    "nonce":            challenge.Nonce,
    "requestTimestamp": challenge.RequestTimestamp,
    "credentialId":     credentialID,
    "signedCredential": signedCredential,
})

req, _ := http.NewRequest("POST", "${BASE}/api/verify-nationality",
    bytes.NewReader(body))
req.Header.Set("Content-Type", "application/json")
req.Header.Set("X-ZkId-Protocol-Version", "zk-id/1.0-draft")

resp, err := http.DefaultClient.Do(req)
if err != nil {
    log.Fatal(err)
}
defer resp.Body.Close()

var result struct {
    Verified    bool   \`json:"verified"\`
    Nationality int    \`json:"nationality"\`
    Error       string \`json:"error"\`
}
json.NewDecoder(resp.Body).Decode(&result)`,
  },

  'POST /api/verify-voting-eligibility': {
    typescript: `// Voting eligibility requires two proofs: age >= 18 AND nationality = USA (840)
// Generate both proofs client-side, then submit together
const res = await fetch('${BASE}/api/verify-voting-eligibility', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'X-ZkId-Protocol-Version': 'zk-id/1.0-draft'
  },
  body: JSON.stringify({
    proofs: [
      {
        claimType: 'age',
        proof: { proof: ageProof, publicSignals: ageSignals },
        nonce: challenge.nonce,
        requestTimestamp: challenge.requestTimestamp,
        signedCredential: credential
      },
      {
        claimType: 'nationality',
        proof: { proof: natProof, publicSignals: natSignals },
        nonce: challenge.nonce,
        requestTimestamp: challenge.requestTimestamp,
        signedCredential: credential
      }
    ]
  })
});
const result = await res.json();
console.log(result.verified); // true
console.log(result.scenario); // "US Voting Eligibility"`,

    python: `import requests

# Submit both age and nationality proofs together
res = requests.post("${BASE}/api/verify-voting-eligibility",
    headers={
        "Content-Type": "application/json",
        "X-ZkId-Protocol-Version": "zk-id/1.0-draft"
    },
    json={
        "proofs": [
            {
                "claimType": "age",
                "proof": age_proof,
                "nonce": challenge["nonce"],
                "requestTimestamp": challenge["requestTimestamp"],
                "signedCredential": signed_credential
            },
            {
                "claimType": "nationality",
                "proof": nationality_proof,
                "nonce": challenge["nonce"],
                "requestTimestamp": challenge["requestTimestamp"],
                "signedCredential": signed_credential
            }
        ]
    })
result = res.json()
print(result["verified"])  # True
print(result["scenario"])  # "US Voting Eligibility"`,

    go: `body, _ := json.Marshal(map[string]interface{}{
    "proofs": []map[string]interface{}{
        {
            "claimType":         "age",
            "proof":             ageProof,
            "nonce":             challenge.Nonce,
            "requestTimestamp":  challenge.RequestTimestamp,
            "signedCredential":  signedCredential,
        },
        {
            "claimType":         "nationality",
            "proof":             nationalityProof,
            "nonce":             challenge.Nonce,
            "requestTimestamp":  challenge.RequestTimestamp,
            "signedCredential":  signedCredential,
        },
    },
})

req, _ := http.NewRequest("POST",
    "${BASE}/api/verify-voting-eligibility", bytes.NewReader(body))
req.Header.Set("Content-Type", "application/json")
req.Header.Set("X-ZkId-Protocol-Version", "zk-id/1.0-draft")

resp, err := http.DefaultClient.Do(req)
if err != nil {
    log.Fatal(err)
}
defer resp.Body.Close()

var result struct {
    Verified bool   \`json:"verified"\`
    Scenario string \`json:"scenario"\`
    Message  string \`json:"message"\`
}
json.NewDecoder(resp.Body).Decode(&result)`,
  },

  'POST /api/verify-senior-discount': {
    typescript: `// Senior discount requires a single age proof with minAge >= 65
const res = await fetch('${BASE}/api/verify-senior-discount', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'X-ZkId-Protocol-Version': 'zk-id/1.0-draft'
  },
  body: JSON.stringify({
    proofs: [
      {
        claimType: 'age',
        proof: { proof: ageProof, publicSignals: ageSignals },
        nonce: challenge.nonce,
        requestTimestamp: challenge.requestTimestamp,
        signedCredential: credential
      }
    ]
  })
});
const result = await res.json();
console.log(result.verified); // true
console.log(result.scenario); // "Senior Discount"`,

    python: `import requests

res = requests.post("${BASE}/api/verify-senior-discount",
    headers={
        "Content-Type": "application/json",
        "X-ZkId-Protocol-Version": "zk-id/1.0-draft"
    },
    json={
        "proofs": [
            {
                "claimType": "age",
                "proof": age_proof,
                "nonce": challenge["nonce"],
                "requestTimestamp": challenge["requestTimestamp"],
                "signedCredential": signed_credential
            }
        ]
    })
result = res.json()
print(result["verified"])  # True
print(result["scenario"])  # "Senior Discount"`,

    go: `body, _ := json.Marshal(map[string]interface{}{
    "proofs": []map[string]interface{}{
        {
            "claimType":        "age",
            "proof":            ageProof,
            "nonce":            challenge.Nonce,
            "requestTimestamp": challenge.RequestTimestamp,
            "signedCredential": signedCredential,
        },
    },
})

req, _ := http.NewRequest("POST",
    "${BASE}/api/verify-senior-discount", bytes.NewReader(body))
req.Header.Set("Content-Type", "application/json")
req.Header.Set("X-ZkId-Protocol-Version", "zk-id/1.0-draft")

resp, err := http.DefaultClient.Do(req)
if err != nil {
    log.Fatal(err)
}
defer resp.Body.Close()

var result struct {
    Verified bool   \`json:"verified"\`
    Scenario string \`json:"scenario"\`
    Message  string \`json:"message"\`
}
json.NewDecoder(resp.Body).Decode(&result)`,
  },

  'POST /api/verify-signed': {
    typescript: `// NOTE: This endpoint is not implemented in the demo server.
// It verifies proofs with in-circuit BabyJub EdDSA signature checks.
const res = await fetch('${BASE}/api/verify-signed', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'X-ZkId-Protocol-Version': 'zk-id/1.0-draft'
  },
  body: JSON.stringify({
    claimType: 'age',
    proof: { proof: signedProof, publicSignals: signedSignals },
    nonce: challenge.nonce,
    requestTimestamp: challenge.requestTimestamp,
    signedCredential: circuitSignedCredential // includes issuerPublicKey
  })
});
const result = await res.json();
console.log(result.verified);`,

    python: `import requests

# NOTE: This endpoint is not implemented in the demo server.
res = requests.post("${BASE}/api/verify-signed",
    headers={
        "Content-Type": "application/json",
        "X-ZkId-Protocol-Version": "zk-id/1.0-draft"
    },
    json={
        "claimType": "age",
        "proof": {
            "proof": signed_proof,
            "publicSignals": signed_signals
        },
        "nonce": challenge["nonce"],
        "requestTimestamp": challenge["requestTimestamp"],
        "signedCredential": circuit_signed_credential
    })
result = res.json()
print(result["verified"])`,

    go: `// NOTE: This endpoint is not implemented in the demo server.
body, _ := json.Marshal(map[string]interface{}{
    "claimType": "age",
    "proof": map[string]interface{}{
        "proof":         signedProof,
        "publicSignals": signedSignals,
    },
    "nonce":            challenge.Nonce,
    "requestTimestamp": challenge.RequestTimestamp,
    "signedCredential": circuitSignedCredential,
})

req, _ := http.NewRequest("POST", "${BASE}/api/verify-signed",
    bytes.NewReader(body))
req.Header.Set("Content-Type", "application/json")
req.Header.Set("X-ZkId-Protocol-Version", "zk-id/1.0-draft")

resp, err := http.DefaultClient.Do(req)
if err != nil {
    log.Fatal(err)
}
defer resp.Body.Close()

var result struct {
    Verified bool   \`json:"verified"\`
    Error    string \`json:"error"\`
}
json.NewDecoder(resp.Body).Decode(&result)`,
  },

  'POST /api/verify-scenario': {
    typescript: `// Verify a named scenario bundle with multiple proofs
const res = await fetch('${BASE}/api/verify-scenario', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'X-ZkId-Protocol-Version': 'zk-id/1.0-draft'
  },
  body: JSON.stringify({
    scenarioId: 'voting-eligibility-us',
    response: {
      nonce: challenge.nonce,
      requestTimestamp: challenge.requestTimestamp,
      credentialId: credential.credential.id,
      proofs: [
        { label: 'age', claimType: 'age', proof: ageProofData },
        { label: 'nationality', claimType: 'nationality', proof: natProofData }
      ]
    }
  })
});
const result = await res.json();
console.log(result.verified); // true
console.log(result.scenario); // "US Voting Eligibility"`,

    python: `import requests

res = requests.post("${BASE}/api/verify-scenario",
    headers={
        "Content-Type": "application/json",
        "X-ZkId-Protocol-Version": "zk-id/1.0-draft"
    },
    json={
        "scenarioId": "voting-eligibility-us",
        "response": {
            "nonce": challenge["nonce"],
            "requestTimestamp": challenge["requestTimestamp"],
            "credentialId": credential_id,
            "proofs": [
                {"label": "age", "claimType": "age", "proof": age_proof},
                {"label": "nationality", "claimType": "nationality",
                 "proof": nationality_proof}
            ]
        }
    })
result = res.json()
print(result["verified"])  # True
print(result["scenario"])  # "US Voting Eligibility"`,

    go: `body, _ := json.Marshal(map[string]interface{}{
    "scenarioId": "voting-eligibility-us",
    "response": map[string]interface{}{
        "nonce":            challenge.Nonce,
        "requestTimestamp": challenge.RequestTimestamp,
        "credentialId":     credentialID,
        "proofs": []map[string]interface{}{
            {"label": "age", "claimType": "age", "proof": ageProof},
            {"label": "nationality", "claimType": "nationality",
                "proof": nationalityProof},
        },
    },
})

req, _ := http.NewRequest("POST", "${BASE}/api/verify-scenario",
    bytes.NewReader(body))
req.Header.Set("Content-Type", "application/json")
req.Header.Set("X-ZkId-Protocol-Version", "zk-id/1.0-draft")

resp, err := http.DefaultClient.Do(req)
if err != nil {
    log.Fatal(err)
}
defer resp.Body.Close()

var result struct {
    Verified bool   \`json:"verified"\`
    Scenario string \`json:"scenario"\`
}
json.NewDecoder(resp.Body).Decode(&result)`,
  },

  'POST /api/revoke-credential': {
    typescript: `const res = await fetch('${BASE}/api/revoke-credential', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'X-ZkId-Protocol-Version': 'zk-id/1.0-draft'
  },
  body: JSON.stringify({
    credentialId: credential.credential.id
  })
});
const result = await res.json();
console.log(result.success); // true
console.log(result.message); // "Credential revoked successfully"`,

    python: `import requests

res = requests.post("${BASE}/api/revoke-credential",
    headers={
        "Content-Type": "application/json",
        "X-ZkId-Protocol-Version": "zk-id/1.0-draft"
    },
    json={"credentialId": credential_id})
result = res.json()
print(result["success"])  # True
print(result["message"])  # "Credential revoked successfully"`,

    go: `body, _ := json.Marshal(map[string]interface{}{
    "credentialId": credentialID,
})

req, _ := http.NewRequest("POST", "${BASE}/api/revoke-credential",
    bytes.NewReader(body))
req.Header.Set("Content-Type", "application/json")
req.Header.Set("X-ZkId-Protocol-Version", "zk-id/1.0-draft")

resp, err := http.DefaultClient.Do(req)
if err != nil {
    log.Fatal(err)
}
defer resp.Body.Close()

var result struct {
    Success bool   \`json:"success"\`
    Message string \`json:"message"\`
}
json.NewDecoder(resp.Body).Decode(&result)`,
  },

  'GET /api/revocation/root': {
    typescript: `const res = await fetch('${BASE}/api/revocation/root', {
  headers: { 'X-ZkId-Protocol-Version': 'zk-id/1.0-draft' }
});
const rootInfo = await res.json();
console.log(rootInfo.root);       // Merkle root (decimal string)
console.log(rootInfo.version);    // monotonic version number
console.log(rootInfo.ttlSeconds); // cache TTL (e.g. 300)
console.log(rootInfo.expiresAt);  // re-fetch after this time`,

    python: `import requests

res = requests.get("${BASE}/api/revocation/root",
    headers={"X-ZkId-Protocol-Version": "zk-id/1.0-draft"})
root_info = res.json()
print(root_info["root"])        # Merkle root
print(root_info["version"])     # monotonic version
print(root_info["ttlSeconds"])  # cache TTL`,

    go: `req, _ := http.NewRequest("GET", "${BASE}/api/revocation/root", nil)
req.Header.Set("X-ZkId-Protocol-Version", "zk-id/1.0-draft")

resp, err := http.DefaultClient.Do(req)
if err != nil {
    log.Fatal(err)
}
defer resp.Body.Close()

var rootInfo struct {
    Root       string \`json:"root"\`
    Version    int    \`json:"version"\`
    UpdatedAt  string \`json:"updatedAt"\`
    ExpiresAt  string \`json:"expiresAt"\`
    TTLSeconds int    \`json:"ttlSeconds"\`
}
json.NewDecoder(resp.Body).Decode(&rootInfo)`,
  },
};

export function getExample(method: string, path: string): CodeExample | undefined {
  return codeExamples[`${method} ${path}`];
}
