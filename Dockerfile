FROM node:22-alpine AS base
RUN corepack enable

# --- Build stage ---
FROM base AS builder
WORKDIR /app

COPY package.json package-lock.json turbo.json tsconfig.base.json ./
COPY packages/shared/package.json packages/shared/
COPY apps/api/package.json apps/api/

RUN npm ci

COPY packages/shared/ packages/shared/
COPY apps/api/ apps/api/

RUN npx turbo build --filter=@clawvet/api

# --- Production stage ---
FROM base AS runner
WORKDIR /app

ENV NODE_ENV=production

COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/packages/shared ./packages/shared
COPY --from=builder /app/apps/api/dist ./apps/api/dist
COPY --from=builder /app/apps/api/package.json ./apps/api/
COPY --from=builder /app/apps/api/node_modules ./apps/api/node_modules
COPY --from=builder /app/package.json ./

EXPOSE 3001

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://localhost:3001/healthz || exit 1

CMD ["node", "apps/api/dist/server.js"]
