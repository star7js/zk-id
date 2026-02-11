# ZK-ID Developer Portal

Interactive developer portal and playground for ZK-ID, built with Astro.

## Features

- **Landing Page** - Overview and quick links
- **Quick Start** - Interactive 4-step guide (< 5 minutes)
- **Playground** - Live sandbox for ZK proof generation
- **API Reference** - Complete API documentation
- **Documentation** - All 24 project docs organized by category

## Development Workflow

### Prerequisites

- Node.js 18+
- Running demo server for backend API (see below)

### Install Dependencies

From the repository root:

```bash
npm install
```

### Start Development Server

From the repository root:

```bash
# Start the portal (default: http://localhost:4321)
npm run portal:dev
```

The portal will be available at http://localhost:4321.

### Start Demo Server (Required for Interactive Features)

The playground and quick start require the demo API server to be running:

```bash
# In a separate terminal
npm run dev
```

This starts the demo server on http://localhost:3000. The portal proxies `/api` and `/circuits` requests to this server.

### Build for Production

```bash
npm run portal:build
```

Outputs static site to `dist/`.

### Preview Production Build

```bash
npm run portal:preview
```

## Project Structure

```
packages/portal/
├── src/
│   ├── layouts/
│   │   ├── BaseLayout.astro      # Main shell (nav, footer)
│   │   └── DocsLayout.astro       # Docs pages (adds sidebar)
│   ├── pages/
│   │   ├── index.astro            # Landing page
│   │   ├── quick-start.astro      # Interactive quick start
│   │   ├── playground.astro       # Live ZK proof sandbox
│   │   ├── api-reference.astro    # API documentation
│   │   └── docs/
│   │       ├── index.astro        # Docs overview
│   │       └── [...slug].astro    # Dynamic doc pages
│   ├── scripts/
│   │   ├── playground.ts          # Playground client logic
│   │   └── quick-start.ts         # Quick start flow
│   ├── content/
│   │   ├── config.ts              # Content collection schema
│   │   └── docs/                  # 24 markdown docs with frontmatter
│   ├── styles/
│   │   └── global.css             # Global styles (dark theme)
│   └── lib/
│       └── openapi.ts             # OpenAPI parser
├── astro.config.mjs               # Astro config + Vite proxy
└── copy-docs.mjs                  # Script to copy docs with frontmatter
```

## Proxy Configuration

The Astro dev server proxies these routes to the demo server:

- `/api/*` → `http://localhost:3000/api/*`
- `/circuits/*` → `http://localhost:3000/circuits/*`

This allows the playground and quick start to call API endpoints and fetch circuit files.

## Browser-Based ZK Proofs

The playground and quick start use snarkjs loaded from CDN to generate ZK proofs entirely in the browser. This requires:

1. **snarkjs library** - Loaded via CDN script tag
2. **Circuit artifacts** - WASM and zkey files served from demo server
3. **User credential** - Issued by server, stored in browser memory

All proof generation happens client-side. Only the proof is sent to the server for verification.

## Deployment

The portal is a static site that can be deployed to:

- **GitHub Pages** - Pre-configured in astro.config.mjs
- **Netlify / Vercel** - Zero-config deployment
- **Any static host** - Upload `dist/` directory

Note: Interactive features (playground, quick start) require a running backend API.

## License

Apache-2.0
