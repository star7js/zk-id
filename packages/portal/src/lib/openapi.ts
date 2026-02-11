import { readFileSync } from 'fs';
import { load } from 'js-yaml';
import { join } from 'path';

export interface Endpoint {
  path: string;
  method: string;
  summary: string;
  description?: string;
  parameters?: any[];
  requestBody?: any;
  responses?: Record<string, any>;
}

export function parseOpenAPI(): Endpoint[] {
  const yamlPath = join(process.cwd(), '../../docs/openapi.yaml');
  const yamlContent = readFileSync(yamlPath, 'utf-8');
  const spec = load(yamlContent) as any;

  const endpoints: Endpoint[] = [];

  for (const [path, pathItem] of Object.entries(spec.paths || {})) {
    for (const [method, operation] of Object.entries(pathItem as any)) {
      if (['get', 'post', 'put', 'delete', 'patch'].includes(method)) {
        const op = operation as any;
        endpoints.push({
          path,
          method: method.toUpperCase(),
          summary: op.summary || '',
          description: op.description || '',
          parameters: op.parameters || [],
          requestBody: op.requestBody,
          responses: op.responses || {},
        });
      }
    }
  }

  return endpoints;
}

export function getMethodColor(method: string): string {
  const colors: Record<string, string> = {
    GET: 'var(--accent-client)',
    POST: 'var(--accent-server)',
    PUT: 'var(--warning)',
    DELETE: 'var(--error)',
    PATCH: 'var(--accent-proof)',
  };
  return colors[method] || 'var(--text-secondary)';
}
