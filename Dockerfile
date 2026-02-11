# Multi-stage build for zk-id demo web app
# Suitable for running the demo server with all dependencies

# --- Stage 1: Install and build ---
FROM node:20-slim AS builder

WORKDIR /app

# Copy workspace root files
COPY package.json package-lock.json* ./
COPY tsconfig.base.json ./

# Copy all package manifests (for dependency resolution)
COPY packages/circuits/package.json packages/circuits/
COPY packages/core/package.json packages/core/
COPY packages/sdk/package.json packages/sdk/
COPY packages/issuer/package.json packages/issuer/
COPY packages/redis/package.json packages/redis/
COPY packages/contracts/package.json packages/contracts/
COPY examples/web-app/package.json examples/web-app/

# Install dependencies
RUN npm ci --ignore-scripts

# Copy source code
COPY packages/ packages/
COPY examples/ examples/

# Copy pre-compiled circuit artifacts (required for verification)
COPY packages/circuits/build/ packages/circuits/build/

# Build all packages in dependency order
RUN npm run build --workspace=@zk-id/core && \
    npm run build --workspace=@zk-id/sdk && \
    npm run build --workspace=@zk-id/issuer && \
    npm run build --workspace=@zk-id/redis && \
    npm run build --workspace=@zk-id/example-web-app

# --- Stage 2: Production runtime ---
FROM node:20-slim AS runtime

WORKDIR /app

# Copy workspace root
COPY package.json package-lock.json* ./
COPY tsconfig.base.json ./

# Copy all package manifests
COPY packages/circuits/package.json packages/circuits/
COPY packages/core/package.json packages/core/
COPY packages/sdk/package.json packages/sdk/
COPY packages/issuer/package.json packages/issuer/
COPY packages/redis/package.json packages/redis/
COPY packages/contracts/package.json packages/contracts/
COPY examples/web-app/package.json examples/web-app/

# Install production dependencies only
RUN npm ci --omit=dev --ignore-scripts 2>/dev/null || npm install --omit=dev --ignore-scripts

# Copy built artifacts from builder
COPY --from=builder /app/packages/core/dist/ packages/core/dist/
COPY --from=builder /app/packages/sdk/dist/ packages/sdk/dist/
COPY --from=builder /app/packages/issuer/dist/ packages/issuer/dist/
COPY --from=builder /app/packages/redis/dist/ packages/redis/dist/
COPY --from=builder /app/examples/web-app/dist/ examples/web-app/dist/

# Copy source files needed at runtime (ts-node for demo server)
COPY packages/core/ packages/core/
COPY packages/sdk/ packages/sdk/
COPY packages/issuer/ packages/issuer/
COPY packages/redis/ packages/redis/
COPY examples/web-app/ examples/web-app/

# Copy circuit build artifacts (verification keys, WASM)
COPY packages/circuits/build/ packages/circuits/build/

ENV NODE_ENV=production
ENV PORT=3000

EXPOSE 3000

# Run the demo web app
CMD ["npm", "start", "--workspace=@zk-id/example-web-app"]
