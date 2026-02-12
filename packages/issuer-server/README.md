# @zk-id/issuer-server

Reference credential issuer server for zk-id. This is a production-ready Express server that wraps `ManagedCredentialIssuer` to provide a REST API for issuing, revoking, and checking the status of zk-id credentials.

## Features

- ✅ **REST API**: Issue credentials, revoke credentials, check status
- ✅ **Authentication**: API key-based authentication
- ✅ **Rate Limiting**: Built-in rate limiting to prevent abuse
- ✅ **CORS Support**: Configurable cross-origin resource sharing
- ✅ **Security Headers**: Helmet.js for security best practices
- ✅ **Audit Logging**: Request logging for monitoring
- ✅ **Credential Expiration**: Support for time-limited credentials
- ✅ **Revocation**: Built-in credential revocation support
- ✅ **Health Checks**: Liveness endpoint for monitoring
- ✅ **Docker Ready**: Easy deployment with Docker

## Quick Start

### Development

```bash
# Install dependencies
npm install

# Create .env file
cp .env.example .env

# Edit .env with your configuration
# On first run, keys will be generated if not provided

# Start development server
npm run dev
```

The server will start on http://localhost:3001

### Production

```bash
# Build
npm run build

# Start
npm start
```

### Docker

```bash
# Build image
docker build -t zk-id-issuer .

# Run container
docker run -p 3001:3001 \
  -e API_KEY=your-secure-key \
  -e ISSUER_NAME="Your Identity Service" \
  zk-id-issuer
```

## API Reference

### Health Check

Check server health and status.

**Request:**

```bash
GET /health
```

**Response:**

```json
{
  "status": "healthy",
  "timestamp": "2026-02-11T12:00:00.000Z",
  "issuer": "Your Identity Service"
}
```

### Get Public Key

Retrieve the issuer's public key for credential verification.

**Request:**

```bash
GET /public-key
```

**Response:**

```json
{
  "issuer": "Your Identity Service",
  "publicKey": "MCowBQYDK2VwAyEA...",
  "format": "Ed25519-SPKI-DER"
}
```

### Issue Credential

Issue a new signed credential.

**Request:**

```bash
POST /issue
X-Api-Key: your-api-key

{
  "birthYear": 1990,
  "nationality": 840,
  "userId": "user-123",
  "expiresAt": "2027-02-11T00:00:00.000Z"
}
```

**Response:**

```json
{
  "success": true,
  "credential": {
    "credential": {
      "id": "...",
      "birthYear": 1990,
      "nationality": 840,
      "salt": "...",
      "commitment": "...",
      "createdAt": "2026-02-11T12:00:00.000Z"
    },
    "issuer": "Your Identity Service",
    "signature": "...",
    "issuedAt": "2026-02-11T12:00:00.000Z",
    "expiresAt": "2027-02-11T00:00:00.000Z"
  }
}
```

**Parameters:**

- `birthYear` (number, required): Birth year of credential holder
- `nationality` (number, required): ISO 3166-1 numeric nationality code
- `userId` (string, required): Unique identifier for the user
- `expiresAt` (string, optional): ISO 8601 expiration timestamp

### Revoke Credential

Revoke a previously issued credential.

**Request:**

```bash
POST /revoke
X-Api-Key: your-api-key

{
  "commitment": "12345..."
}
```

**Response:**

```json
{
  "success": true,
  "message": "Credential revoked",
  "commitment": "12345..."
}
```

### Check Credential Status

Check if a credential has been revoked.

**Request:**

```bash
GET /status/:commitment
```

**Response:**

```json
{
  "commitment": "12345...",
  "revoked": false,
  "status": "active"
}
```

## Configuration

### Environment Variables

| Variable             | Required | Default                          | Description                                     |
| -------------------- | -------- | -------------------------------- | ----------------------------------------------- |
| `PORT`               | No       | 3001                             | Server port                                     |
| `NODE_ENV`           | No       | development                      | Environment (development/production)            |
| `API_KEY`            | Yes      | dev-api-key-change-in-production | API key for authentication                      |
| `ISSUER_NAME`        | Yes      | zk-id Reference Issuer           | Issuer identifier                               |
| `ISSUER_PRIVATE_KEY` | No\*     | (generated)                      | Base64-encoded Ed25519 private key (DER format) |
| `ISSUER_PUBLIC_KEY`  | No\*     | (generated)                      | Base64-encoded Ed25519 public key (DER format)  |
| `CORS_ORIGIN`        | No       | \*                               | Allowed CORS origins                            |

\* Keys will be generated on first run if not provided (not recommended for production)

### Key Generation

The server can generate Ed25519 keys automatically on first run:

```bash
npm run dev
```

Copy the output keys to your `.env` file:

```
ISSUER_PRIVATE_KEY=MC4CAQAwBQYDK2VwBCIEI...
ISSUER_PUBLIC_KEY=MCowBQYDK2VwAyEA...
```

For production, use a KMS/HSM:

- AWS KMS
- Google Cloud KMS
- Azure Key Vault
- HashiCorp Vault

## Security Considerations

### Production Checklist

- [ ] **Change API_KEY**: Use a strong, randomly generated API key
- [ ] **Use HTTPS**: Always run behind a reverse proxy with TLS
- [ ] **KMS/HSM**: Use a hardware security module for key management
- [ ] **Rate Limiting**: Adjust rate limits based on your usage patterns
- [ ] **CORS**: Restrict CORS to your specific domains
- [ ] **Monitoring**: Set up logging and alerting
- [ ] **Backups**: Back up revocation state if using persistent storage
- [ ] **Key Rotation**: Implement key rotation policy

### API Key Management

The API key authenticates credential issuance requests. Protect it like a password:

- Generate with `openssl rand -hex 32`
- Store securely (environment variables, secrets manager)
- Rotate regularly
- Use different keys for different environments

### Key Management

For production:

1. **Never commit private keys** to version control
2. Use environment variables or secrets managers
3. Consider KMS/HSM for key storage
4. Implement key rotation
5. Monitor key usage

## Integration Example

### Issue a Credential

```typescript
import fetch from 'node-fetch';

async function issueCredential(birthYear: number, nationality: number, userId: string) {
  const response = await fetch('http://localhost:3001/issue', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Api-Key': process.env.API_KEY!,
    },
    body: JSON.stringify({
      birthYear,
      nationality,
      userId,
      expiresAt: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(), // 1 year
    }),
  });

  const result = await response.json();
  return result.credential;
}
```

### Verify with Public Key

```typescript
import { ZkIdServer, InMemoryIssuerRegistry } from '@zk-id/sdk';
import { createPublicKey } from 'crypto';

async function setupVerifier() {
  // Fetch issuer public key
  const response = await fetch('http://localhost:3001/public-key');
  const { issuer, publicKey } = await response.json();

  // Convert to KeyObject
  const publicKeyObj = createPublicKey({
    key: Buffer.from(publicKey, 'base64'),
    format: 'der',
    type: 'spki',
  });

  // Create verifier
  const issuerRegistry = new InMemoryIssuerRegistry([{ issuer, publicKey: publicKeyObj }]);

  return new ZkIdServer({
    verificationKeyPath: './verification_key.json',
    issuerRegistry,
  });
}
```

## Deployment

### Docker Compose

See [docker-compose.yml](./docker-compose.yml) for a complete deployment example with:

- Issuer server
- PostgreSQL database (for persistent revocation storage)
- Redis (for distributed caching)

```bash
docker-compose up -d
```

### Kubernetes

Example deployment:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: zk-id-issuer
spec:
  replicas: 3
  selector:
    matchLabels:
      app: zk-id-issuer
  template:
    metadata:
      labels:
        app: zk-id-issuer
    spec:
      containers:
        - name: issuer
          image: zk-id-issuer:latest
          ports:
            - containerPort: 3001
          env:
            - name: API_KEY
              valueFrom:
                secretKeyRef:
                  name: zk-id-secrets
                  key: api-key
            - name: ISSUER_PRIVATE_KEY
              valueFrom:
                secretKeyRef:
                  name: zk-id-secrets
                  key: private-key
            - name: ISSUER_PUBLIC_KEY
              valueFrom:
                secretKeyRef:
                  name: zk-id-secrets
                  key: public-key
          livenessProbe:
            httpGet:
              path: /health
              port: 3001
            initialDelaySeconds: 10
            periodSeconds: 30
```

## Monitoring

### Health Checks

The `/health` endpoint provides server status:

```bash
curl http://localhost:3001/health
```

### Logs

All requests are logged to stdout:

```
[2026-02-11T12:00:00.000Z] POST /issue
[2026-02-11T12:00:01.000Z] GET /status/abc123
```

### Metrics

Consider adding:

- Prometheus metrics for request rates, latencies
- Error tracking (Sentry, Rollbar)
- APM (New Relic, Datadog)

## Development

### Project Structure

```
issuer-server/
├── src/
│   └── index.ts          # Main server file
├── .env.example          # Example environment configuration
├── package.json          # Dependencies and scripts
├── tsconfig.json         # TypeScript configuration
├── Dockerfile            # Docker image definition
├── docker-compose.yml    # Docker Compose setup
└── README.md            # This file
```

### Testing

```bash
# Run tests
npm test

# Test issuance
curl -X POST http://localhost:3001/issue \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: dev-api-key-change-in-production" \
  -d '{
    "birthYear": 1990,
    "nationality": 840,
    "userId": "test-user"
  }'
```

## License

Apache-2.0
