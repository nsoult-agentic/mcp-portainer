# mcp-portainer — READ-ONLY Portainer monitoring MCP server
# Multi-stage build: install deps → production image

# ── Build stage ──────────────────────────────────────
FROM oven/bun:1.1.45-alpine AS build

WORKDIR /app
COPY package.json bun.lock* ./
RUN bun install --production

# ── Production stage ─────────────────────────────────
FROM oven/bun:1.1.45-alpine

WORKDIR /app

# Copy only production artifacts
COPY --from=build /app/node_modules ./node_modules
COPY package.json ./
COPY src/ ./src/

# Non-root user for defense-in-depth
USER bun

EXPOSE 8900

CMD ["bun", "run", "src/http.ts"]
