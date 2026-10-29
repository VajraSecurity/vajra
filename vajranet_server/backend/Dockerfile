# backend image -- Express/TypeScript API (see src/consts/server.ts:
# DEFAULT_PORT=4000).
#
# Build context is the WHOLE repo root, not backend/. Every COPY below is
# written relative to that root, not to this directory.
#
# Two stages: `canvas` (pulled in via chartjs-node-canvas) is a native
# addon needing cairo/pango/jpeg/gif/rsvg at both compile and run time, so
# the build stage gets the -dev headers + a toolchain and the runtime
# stage gets just the matching shared libraries -- smaller final image,
# without re-triggering a native rebuild in a stage that has no compiler.
# node_modules (not just dist) is carried over from build rather than
# reinstalled with --omit=dev, specifically so that already-built canvas
# binary is reused as-is instead of being rebuilt a second time. devDependencies
# are instead stripped in-place afterward via `npm prune --omit=dev`, which
# only removes packages -- it does not touch or rebuild existing binaries.
FROM node:22-bookworm-slim AS build
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential python3 pkg-config \
    libcairo2-dev libpango1.0-dev libjpeg-dev libgif-dev librsvg2-dev \
 && rm -rf /var/lib/apt/lists/*

# The build only needs puppeteer's API surface at compile time, not its bundled
# Chromium.
ENV PUPPETEER_SKIP_DOWNLOAD=true

COPY backend/package*.json ./
RUN npm ci

COPY backend/ .
RUN npm run build

# Drop devDependencies (e.g. Vitest) now that the build is done. This runs
# after the compile step, not via `npm ci --omit=dev`, so the already-built
# canvas native addon binary is kept as-is rather than triggering a rebuild.
RUN npm prune --omit=dev

FROM node:22-bookworm-slim
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    libcairo2 libpango-1.0-0 libjpeg62-turbo libgif7 librsvg2-2 \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --create-home --uid 1001 backend \
 && mkdir -p /app/keys /app/storage \
 && chown backend:backend /app /app/keys /app/storage
USER backend

ENV NODE_ENV=production
COPY --from=build --chown=backend:backend /app/node_modules ./node_modules
COPY --from=build --chown=backend:backend /app/dist ./dist
COPY --from=build --chown=backend:backend /app/package*.json ./

EXPOSE 4000
CMD ["node", "dist/index.js"]
