import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { spawn, ChildProcessWithoutNullStreams } from 'child_process';
import { dirname, resolve } from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const packageDir = resolve(__dirname, '..');
const port = 33000 + Math.floor(Math.random() * 1000);
const baseUrl = `http://127.0.0.1:${port}`;
const apiKey = 'test-api-key';

let serverProcess: ChildProcessWithoutNullStreams | null = null;
let lastIssuedCommitment: string | null = null;

const sleep = (ms: number) => new Promise((resolvePromise) => setTimeout(resolvePromise, ms));

async function waitForHealth(timeoutMs = 20000): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const res = await fetch(`${baseUrl}/health`);
      if (res.ok) return;
    } catch {
      // Server not ready yet.
    }
    await sleep(200);
  }
  throw new Error(`Issuer server did not become healthy within ${timeoutMs}ms`);
}

beforeAll(async () => {
  serverProcess = spawn(process.execPath, ['--import', 'tsx', 'src/index.ts'], {
    cwd: packageDir,
    env: {
      ...process.env,
      PORT: String(port),
      API_KEY: apiKey,
      ISSUER_NAME: 'zk-id Test Issuer',
      NODE_ENV: 'test',
      CORS_ORIGIN: '*',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  // Drain output buffers to avoid child-process blocking.
  serverProcess.stdout.on('data', () => undefined);
  serverProcess.stderr.on('data', () => undefined);

  await waitForHealth();
});

afterAll(async () => {
  if (!serverProcess) return;
  if (!serverProcess.killed) {
    serverProcess.kill('SIGTERM');
    await new Promise<void>((resolvePromise) => {
      serverProcess?.once('exit', () => resolvePromise());
      setTimeout(() => resolvePromise(), 5000);
    });
  }
});

describe('issuer-server', () => {
  it('returns health status', async () => {
    const res = await fetch(`${baseUrl}/health`);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { status: string; issuer: string };
    expect(body.status).toBe('healthy');
    expect(body.issuer).toBe('zk-id Test Issuer');
  });

  it('rejects credential issuance without API key', async () => {
    const res = await fetch(`${baseUrl}/issue`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        birthYear: 1990,
        nationality: 840,
        userId: 'user-no-auth',
      }),
    });

    expect(res.status).toBe(401);
  });

  it('issues a credential with valid API key', async () => {
    const res = await fetch(`${baseUrl}/issue`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Api-Key': apiKey,
      },
      body: JSON.stringify({
        birthYear: 1990,
        nationality: 840,
        userId: 'user-1',
      }),
    });

    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      success: boolean;
      credential: { credential: { id: string; commitment: string } };
    };

    expect(body.success).toBe(true);
    expect(body.credential.credential.id).toBeTypeOf('string');
    expect(body.credential.credential.commitment).toBeTypeOf('string');
    lastIssuedCommitment = body.credential.credential.commitment;
  });

  it('returns active status for a newly issued credential', async () => {
    expect(lastIssuedCommitment).toBeTruthy();
    const res = await fetch(`${baseUrl}/status/${lastIssuedCommitment}`);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { revoked: boolean; status: string };
    expect(body.revoked).toBe(false);
    expect(body.status).toBe('active');
  });

  it('exposes built-in schema registry including agent schema', async () => {
    const res = await fetch(`${baseUrl}/schemas`);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { schemas: Array<{ id: string }> };
    const ids = body.schemas.map((s) => s.id);
    expect(ids).toContain('age-verification');
    expect(ids).toContain('agent-identity');
    expect(ids).toContain('capability');
  });

  it('serves circuit artifacts using compatibility aliases', async () => {
    const res = await fetch(`${baseUrl}/circuits/age-vkey.json`);
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body).toHaveProperty('protocol');
  });
});
