import { readFileSync, writeFileSync } from 'fs';
import { join } from 'path';

const docs = [
  // Getting Started
  {
    src: '../../GETTING-STARTED.md',
    dest: 'getting-started.md',
    title: 'Getting Started',
    category: 'Getting Started',
    order: 1,
  },
  {
    src: '../../CONTRIBUTING.md',
    dest: 'contributing.md',
    title: 'Contributing Guide',
    category: 'Getting Started',
    order: 2,
  },
  {
    src: '../../CHANGELOG.md',
    dest: 'changelog.md',
    title: 'Changelog',
    category: 'Getting Started',
    order: 3,
  },

  // Architecture
  {
    src: '../../docs/ARCHITECTURE.md',
    dest: 'architecture.md',
    title: 'Architecture',
    category: 'Architecture',
    order: 10,
  },
  {
    src: '../../docs/PROTOCOL.md',
    dest: 'protocol.md',
    title: 'Protocol Specification',
    category: 'Architecture',
    order: 11,
  },
  {
    src: '../../docs/CIRCUIT-DIAGRAMS.md',
    dest: 'circuit-diagrams.md',
    title: 'Circuit Diagrams',
    category: 'Architecture',
    order: 12,
  },
  {
    src: '../../docs/CIRCUIT-COMPLEXITY.md',
    dest: 'circuit-complexity.md',
    title: 'Circuit Complexity',
    category: 'Architecture',
    order: 13,
  },
  {
    src: '../../docs/SCHEMA-EXTENSIBILITY.md',
    dest: 'schema-extensibility.md',
    title: 'Schema Extensibility',
    category: 'Architecture',
    order: 14,
  },

  // Security
  {
    src: '../../SECURITY.md',
    dest: 'security.md',
    title: 'Security Policy',
    category: 'Security',
    order: 20,
  },
  {
    src: '../../docs/THREAT-MODEL.md',
    dest: 'threat-model.md',
    title: 'Threat Model',
    category: 'Security',
    order: 21,
  },
  {
    src: '../../docs/AUDIT.md',
    dest: 'audit.md',
    title: 'Security Audit',
    category: 'Security',
    order: 22,
  },
  {
    src: '../../docs/CRYPTOGRAPHIC-PARAMETERS.md',
    dest: 'cryptographic-parameters.md',
    title: 'Cryptographic Parameters',
    category: 'Security',
    order: 23,
  },
  {
    src: '../../docs/SIGNED-CIRCUITS.md',
    dest: 'signed-circuits.md',
    title: 'Signed Circuits',
    category: 'Security',
    order: 24,
  },
  {
    src: '../../docs/SECURITY-HARDENING.md',
    dest: 'security-hardening.md',
    title: 'Security Hardening',
    category: 'Security',
    order: 25,
  },

  // Operations
  {
    src: '../../docs/DEPLOYMENT.md',
    dest: 'deployment.md',
    title: 'Deployment Guide',
    category: 'Operations',
    order: 30,
  },
  {
    src: '../../docs/REPRODUCIBLE-BUILDS.md',
    dest: 'reproducible-builds.md',
    title: 'Reproducible Builds',
    category: 'Operations',
    order: 31,
  },
  {
    src: '../../docs/MIGRATION.md',
    dest: 'migration.md',
    title: 'Migration Guide',
    category: 'Operations',
    order: 32,
  },

  // Development
  {
    src: '../../docs/BENCHMARKS.md',
    dest: 'benchmarks.md',
    title: 'Performance Benchmarks',
    category: 'Development',
    order: 40,
  },
  {
    src: '../../COVERAGE-REPORT.md',
    dest: 'coverage-report.md',
    title: 'Code Coverage Report',
    category: 'Development',
    order: 41,
  },
  {
    src: '../../docs/KNOWN-LIMITATIONS.md',
    dest: 'known-limitations.md',
    title: 'Known Limitations',
    category: 'Development',
    order: 42,
  },

  // Reference
  {
    src: '../../docs/STANDARDS.md',
    dest: 'standards.md',
    title: 'Standards & Compliance',
    category: 'Reference',
    order: 50,
  },
  {
    src: '../../docs/COMPLIANCE.md',
    dest: 'compliance.md',
    title: 'Compliance Documentation',
    category: 'Reference',
    order: 51,
  },
  {
    src: '../../docs/ROADMAP.md',
    dest: 'roadmap.md',
    title: 'Roadmap',
    category: 'Reference',
    order: 52,
  },
  {
    src: '../../docs/TICKETS.md',
    dest: 'tickets.md',
    title: 'Project Tickets',
    category: 'Reference',
    order: 53,
  },
];

const basePath = new URL('.', import.meta.url).pathname;

docs.forEach(({ src, dest, title, category, order }) => {
  try {
    const content = readFileSync(join(basePath, src), 'utf-8');

    // Extract description from first paragraph (skip heading)
    const lines = content.split('\n');
    let description = '';
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      if (line && !line.startsWith('#') && !line.startsWith('```')) {
        description = line.substring(0, 150);
        break;
      }
    }

    const frontmatter = `---
title: "${title}"
description: "${description}"
category: "${category}"
order: ${order}
---

`;

    writeFileSync(join(basePath, 'src/content/docs', dest), frontmatter + content);
    console.log(`✓ Copied ${dest}`);
  } catch (error) {
    console.error(`✗ Failed to copy ${src}:`, error.message);
  }
});

console.log(`\nCopied ${docs.length} documentation files`);
