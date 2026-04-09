/**
 * MCP server for Portainer — READ-ONLY monitoring and restart.
 * Deployed via GitHub Actions → ghcr.io → Portainer CE GitOps polling.
 *
 * Tools:
 *   portainer-list-stacks  — List all stacks with status
 *   portainer-restart      — Restart a container by name
 *   portainer-debug        — Test API connectivity
 *   portainer-logs         — Fetch container logs (sanitized)
 *   portainer-stack-file   — Get docker-compose.yml for a stack
 *
 * SECURITY: Portainer API key = root access via Docker socket.
 * Only list, restart, debug, logs (tail, read-only), and stack-file (read-only) are exposed.
 * No create, inspect, exec, delete, or shell capability.
 * Stack file content is sanitized — passwords/secrets are redacted.
 *
 * Usage: PORT=8900 SECRETS_DIR=/secrets bun run src/http.ts
 */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import { z } from "zod";

// ── Configuration ──────────────────────────────────────────

const PORT = Number(process.env["PORT"]) || 8900;
const SECRETS_DIR = process.env["SECRETS_DIR"] || "/secrets";
const PORTAINER_URL = process.env["PORTAINER_URL"] || "http://host.docker.internal:9000";
const ENVIRONMENT_ID = process.env["PORTAINER_ENV_ID"] || "2";

// Optional allowlist — restricts which containers can be restarted.
// Comma-separated names. Empty = all containers allowed (backwards compatible).
const RESTART_ALLOWLIST = (process.env["RESTART_ALLOWLIST"] || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

// Read API key from file (NEVER from env var)
function loadApiKey(): string {
  const keyPath = resolve(SECRETS_DIR, "api-key");
  try {
    const key = readFileSync(keyPath, "utf-8").trim();
    if (key.length === 0) {
      throw new Error("API key file is empty");
    }
    return key;
  } catch (err) {
    // Generic error — never expose file paths or reasons in output
    throw new Error("Failed to load Portainer API key. Check secrets mount.");
  }
}

const API_KEY = loadApiKey();

// ── Rate Limiter ──────────────────────────────────────────

const RATE_LIMIT = 30; // max requests per window
const RATE_WINDOW_MS = 60_000; // 1 minute
const requestTimestamps: number[] = [];

function isRateLimited(): boolean {
  const now = Date.now();
  // Remove timestamps outside the window
  while (requestTimestamps.length > 0 && requestTimestamps[0] < now - RATE_WINDOW_MS) {
    requestTimestamps.shift();
  }
  if (requestTimestamps.length >= RATE_LIMIT) return true;
  requestTimestamps.push(now);
  return false;
}

// ── Portainer API Client ───────────────────────────────────

// API key is used in fetch() headers only — NEVER appears in MCP tool output.
// Tool responses return formatted text strings, not raw HTTP responses.

async function portainerGet(path: string): Promise<unknown> {
  const url = `${PORTAINER_URL}/api${path}`;
  try {
    const res = await fetch(url, {
      method: "GET",
      headers: { "X-API-Key": API_KEY },
      signal: AbortSignal.timeout(10_000),
    });
    if (!res.ok) {
      // Log full error to container stdout (only visible via Portainer logs)
      const body = await res.text().catch(() => "(unreadable)");
      console.error(`[portainer] GET /api${path}: ${res.status} — ${body.slice(0, 200)}`);
      // Throw generic error — never include API response body in thrown message
      throw new Error(`Portainer API error (${res.status})`);
    }
    return res.json();
  } catch (err: unknown) {
    if (err instanceof Error && err.message.startsWith("Portainer API error"))
      throw err;
    // Network/timeout errors may contain URLs — strip them
    throw new Error("Portainer API request failed");
  }
}

async function portainerPost(path: string): Promise<unknown> {
  const url = `${PORTAINER_URL}/api${path}`;
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { "X-API-Key": API_KEY },
      signal: AbortSignal.timeout(10_000),
    });
    if (!res.ok) {
      const body = await res.text().catch(() => "(unreadable)");
      console.error(`[portainer] POST /api${path}: ${res.status} — ${body.slice(0, 200)}`);
      throw new Error(`Portainer API error (${res.status})`);
    }
    // Restart returns 204 No Content
    if (res.status === 204) return { status: "ok" };
    return res.json();
  } catch (err: unknown) {
    if (err instanceof Error && err.message.startsWith("Portainer API error"))
      throw err;
    throw new Error("Portainer API request failed");
  }
}

async function portainerGetRaw(path: string): Promise<ArrayBuffer> {
  const url = `${PORTAINER_URL}/api${path}`;
  try {
    const res = await fetch(url, {
      method: "GET",
      headers: { "X-API-Key": API_KEY },
      signal: AbortSignal.timeout(15_000),
    });
    if (!res.ok) {
      const body = await res.text().catch(() => "(unreadable)");
      console.error(`[portainer] GET /api${path}: ${res.status} — ${body.slice(0, 200)}`);
      throw new Error(`Portainer API error (${res.status})`);
    }
    return res.arrayBuffer();
  } catch (err: unknown) {
    if (err instanceof Error && err.message.startsWith("Portainer API error"))
      throw err;
    throw new Error("Portainer API request failed");
  }
}

/** Demux Docker multiplexed stream format (8-byte header per frame). */
function demuxDockerLogs(buf: Uint8Array): string {
  if (buf.length === 0) return "(empty)";
  // Detect multiplexed format: first byte is stream type (0-2), bytes 1-3 are zero padding
  if (buf.length >= 8 && buf[0] <= 2 && buf[1] === 0 && buf[2] === 0 && buf[3] === 0) {
    const chunks: string[] = [];
    const decoder = new TextDecoder();
    let offset = 0;
    while (offset + 8 <= buf.length) {
      const frameSize = (buf[offset + 4] << 24) | (buf[offset + 5] << 16) |
                        (buf[offset + 6] << 8) | buf[offset + 7];
      offset += 8;
      if (frameSize <= 0 || offset + frameSize > buf.length) break;
      chunks.push(decoder.decode(buf.slice(offset, offset + frameSize)));
      offset += frameSize;
    }
    return chunks.join("") || "(empty)";
  }
  // Plain text (TTY mode)
  return new TextDecoder().decode(buf);
}

const SENSITIVE_PATTERNS = [
  /Bearer\s+[A-Za-z0-9._\-]{20,}/gi,
  /["']?(?:api[_-]?key|token|secret|password|authorization)["']?\s*[:=]\s*["']?[^\s"',]{8,}["']?/gi,
];

// Extended patterns for docker-compose files (keys, credentials, connection strings)
const COMPOSE_SENSITIVE_PATTERNS = [
  ...SENSITIVE_PATTERNS,
  // Key-value pairs with sensitive key names not covered by base patterns
  /["']?(?:PRIVATE_KEY|SIGNING_KEY|ENCRYPTION_KEY|ACCESS_KEY|SECRET_KEY|CLIENT_SECRET|CERT_KEY|CREDENTIALS|PASSPHRASE|SMTP_PASS|DB_PASS|AWS_ACCESS_KEY_ID)["']?\s*[:=]\s*["']?[^\s"',]{4,}["']?/gi,
  // Connection strings with embedded credentials
  /(?:postgres|postgresql|mysql|redis|mongodb|amqp|smtp):\/\/[^\s"']+/gi,
  // AWS access key IDs
  /AKIA[0-9A-Z]{16}/g,
  // PEM-encoded keys/certs (BEGIN blocks)
  /-----BEGIN\s+(?:RSA\s+)?(?:PRIVATE\s+KEY|CERTIFICATE|EC\s+PRIVATE\s+KEY)-----[\s\S]*?-----END\s+[A-Z\s]+-----/gi,
];

function sanitizeLogs(text: string): string {
  let result = text;
  for (const pattern of SENSITIVE_PATTERNS) {
    result = result.replace(pattern, "[REDACTED]");
  }
  return result;
}

function sanitizeComposeFile(text: string): string {
  let result = text;
  for (const pattern of COMPOSE_SENSITIVE_PATTERNS) {
    result = result.replace(pattern, "[REDACTED]");
  }
  return result;
}

// ── Tool: portainer-list-stacks ────────────────────────────

interface PortainerStack {
  Id: number;
  Name: string;
  Status: number;
  Type: number;
}

interface PortainerContainer {
  Id: string;
  Names: string[];
  State: string;
  Status: string;
  Image: string;
}

const ListStacksInput = {};

async function listStacks(): Promise<string> {
  try {
    const stacks = (await portainerGet("/stacks")) as PortainerStack[];
    const containers = (await portainerGet(
      `/endpoints/${ENVIRONMENT_ID}/docker/containers/json?all=true`
    )) as PortainerContainer[];

    const stackLines = stacks.map((s) => {
      const statusLabel = s.Status === 1 ? "active" : s.Status === 2 ? "inactive" : `status:${s.Status}`;
      return `  ${s.Name} (id:${s.Id}) — ${statusLabel}`;
    });

    const containerLines = containers.map((c) => {
      const name = c.Names[0]?.replace(/^\//, "") ?? "unnamed";
      return `  ${name} — ${c.State} (${c.Status}) [${c.Image}]`;
    });

    return [
      `## Stacks (${stacks.length})`,
      ...stackLines,
      "",
      `## Containers (${containers.length})`,
      ...containerLines,
    ].join("\n");
  } catch {
    return "Failed to list stacks — Portainer API error. Check container logs for details.";
  }
}

// ── Tool: portainer-restart ────────────────────────────────

const CONTAINER_NAME_REGEX = /^[a-zA-Z0-9][a-zA-Z0-9_.-]+$/;

const RestartInput = {
  container_name: z.string()
    .min(1)
    .max(128)
    .regex(CONTAINER_NAME_REGEX, "Container name must be alphanumeric with dashes, dots, or underscores")
    .describe("Name of the container to restart (e.g., 'mcp-second-brain')"),
};

async function restartContainer(params: { container_name: string }): Promise<string> {
  try {
    // Find container by name
    const containers = (await portainerGet(
      `/endpoints/${ENVIRONMENT_ID}/docker/containers/json?all=true`
    )) as PortainerContainer[];

    const target = containers.find((c) =>
      c.Names.some((n) => n === `/${params.container_name}` || n === params.container_name)
    );

    if (!target) {
      const available = containers
        .map((c) => c.Names[0]?.replace(/^\//, ""))
        .filter(Boolean)
        .join(", ");
      return `Container "${params.container_name}" not found. Available: ${available}`;
    }

    // Enforce allowlist if configured
    if (RESTART_ALLOWLIST.length > 0 && !RESTART_ALLOWLIST.includes(params.container_name)) {
      return `Container "${params.container_name}" is not in the restart allowlist.`;
    }

    await portainerPost(
      `/endpoints/${ENVIRONMENT_ID}/docker/containers/${target.Id}/restart`
    );

    return `Container "${params.container_name}" (${target.Id.slice(0, 12)}) restarted successfully.`;
  } catch {
    return `Failed to restart "${params.container_name}" — Portainer API error. Check container logs for details.`;
  }
}

// ── Tool: portainer-debug ──────────────────────────────────

async function debugConnection(): Promise<string> {
  const lines = [
    "## Portainer MCP Debug Info",
    "",
    `PORTAINER_URL: ${PORTAINER_URL}`,
    `ENVIRONMENT_ID: ${ENVIRONMENT_ID}`,
    `API_KEY: ${API_KEY ? "loaded" : "NOT LOADED"}`,
    "",
  ];

  // Test 1: Portainer status (unauthenticated)
  try {
    const statusRes = await fetch(`${PORTAINER_URL}/api/system/status`, {
      signal: AbortSignal.timeout(5_000),
    });
    lines.push(`GET /api/system/status: ${statusRes.status}`);
  } catch {
    lines.push("GET /api/system/status: FAILED — connection error");
  }

  // Test 2: Stacks endpoint (authenticated)
  try {
    const stacksRes = await fetch(`${PORTAINER_URL}/api/stacks`, {
      headers: { "X-API-Key": API_KEY },
      signal: AbortSignal.timeout(5_000),
    });
    lines.push(`GET /api/stacks: ${stacksRes.status}`);
  } catch {
    lines.push("GET /api/stacks: FAILED — connection error");
  }

  // Test 3: Docker containers for configured environment
  try {
    const containersRes = await fetch(
      `${PORTAINER_URL}/api/endpoints/${ENVIRONMENT_ID}/docker/containers/json?all=true`,
      { headers: { "X-API-Key": API_KEY }, signal: AbortSignal.timeout(5_000) },
    );
    lines.push(`GET /api/endpoints/${ENVIRONMENT_ID}/docker/containers: ${containersRes.status}`);
  } catch {
    lines.push(`GET /api/endpoints/${ENVIRONMENT_ID}/docker/containers: FAILED — connection error`);
  }

  return lines.join("\n");
}

// ── Tool: portainer-logs ──────────────────────────────────

const LogsInput = {
  container_name: z.string()
    .min(1)
    .max(128)
    .regex(CONTAINER_NAME_REGEX, "Container name must be alphanumeric with dashes, dots, or underscores")
    .describe("Name of the container to fetch logs from (e.g., 'mcp-accounting')"),
  lines: z.number()
    .int()
    .min(1)
    .max(500)
    .default(100)
    .describe("Number of recent log lines to return (default: 100, max: 500)"),
};

async function getContainerLogs(params: { container_name: string; lines: number }): Promise<string> {
  try {
    const containers = (await portainerGet(
      `/endpoints/${ENVIRONMENT_ID}/docker/containers/json?all=true`
    )) as PortainerContainer[];

    const target = containers.find((c) =>
      c.Names.some((n) => n === `/${params.container_name}` || n === params.container_name)
    );

    if (!target) {
      const available = containers
        .map((c) => c.Names[0]?.replace(/^\//, ""))
        .filter(Boolean)
        .join(", ");
      return `Container "${params.container_name}" not found. Available: ${available}`;
    }

    const raw = await portainerGetRaw(
      `/endpoints/${ENVIRONMENT_ID}/docker/containers/${target.Id}/logs?stdout=1&stderr=1&tail=${params.lines}&timestamps=1`
    );

    const text = demuxDockerLogs(new Uint8Array(raw));
    const sanitized = sanitizeLogs(text);

    return `## Logs: ${params.container_name} (last ${params.lines} lines)\n\n${sanitized}`;
  } catch {
    return `Failed to fetch logs for "${params.container_name}" — Portainer API error.`;
  }
}

// ── Tool: portainer-stack-file ────────────────────────────

const StackFileInput = {
  stack_id: z.number()
    .int()
    .min(1)
    .describe("Stack ID (use portainer-list-stacks to find IDs)"),
};

async function getStackFile(params: { stack_id: number }): Promise<string> {
  try {
    const data = (await portainerGet(`/stacks/${params.stack_id}/file`)) as {
      StackFileContent?: string;
    };

    if (!data.StackFileContent) {
      return `Stack ${params.stack_id}: no compose file content returned.`;
    }

    // Sanitize: redact passwords/secrets in compose files (extended patterns)
    const sanitized = sanitizeComposeFile(data.StackFileContent);

    return `## Stack ${params.stack_id} — docker-compose.yml\n\n\`\`\`yaml\n${sanitized}\n\`\`\``;
  } catch {
    return `Failed to fetch stack file for stack ${params.stack_id} — Portainer API error.`;
  }
}

// ── MCP Server ─────────────────────────────────────────────

function createServer(): McpServer {
  const server = new McpServer({
    name: "mcp-portainer",
    version: "0.1.0",
  });

  server.tool(
    "portainer-list-stacks",
    "List all Portainer stacks and Docker containers with their status. READ-ONLY — no modifications.",
    ListStacksInput,
    async () => ({
      content: [{ type: "text" as const, text: await listStacks() }],
    }),
  );

  server.tool(
    "portainer-restart",
    "Restart a Docker container by name. This is the ONLY write operation available — no create, inspect, exec, or logs.",
    RestartInput,
    async (params) => ({
      content: [{ type: "text" as const, text: await restartContainer(params) }],
    }),
  );

  server.tool(
    "portainer-debug",
    "Debug Portainer API connectivity. Tests status, auth, and endpoint access. No secrets exposed.",
    {},
    async () => ({
      content: [{ type: "text" as const, text: await debugConnection() }],
    }),
  );

  server.tool(
    "portainer-logs",
    "Fetch recent logs from a Docker container. Output is sanitized — sensitive values are redacted.",
    LogsInput,
    async (params) => ({
      content: [{ type: "text" as const, text: await getContainerLogs(params) }],
    }),
  );

  server.tool(
    "portainer-stack-file",
    "Get the docker-compose.yml content for a Portainer stack by stack ID. Use portainer-list-stacks to find IDs.",
    StackFileInput,
    async (params) => ({
      content: [{ type: "text" as const, text: await getStackFile(params) }],
    }),
  );

  return server;
}

// ── HTTP Server (stateless mode) ───────────────────────────

const httpServer = Bun.serve({
  port: PORT,
  hostname: "0.0.0.0", // Inside container — Docker port mapping handles 127.0.0.1 binding
  async fetch(req: Request): Promise<Response> {
    const url = new URL(req.url);

    if (url.pathname === "/health") {
      return new Response(JSON.stringify({ status: "ok", service: "mcp-portainer", port: PORT }), {
        headers: { "Content-Type": "application/json" },
      });
    }

    if (url.pathname === "/mcp") {
      if (isRateLimited()) {
        return new Response("Rate limit exceeded", { status: 429 });
      }
      const transport = new WebStandardStreamableHTTPServerTransport({
        sessionIdGenerator: undefined, // stateless
      });
      const server = createServer();
      await server.connect(transport);
      return transport.handleRequest(req);
    }

    return new Response("Not Found", { status: 404 });
  },
});

console.log(`mcp-portainer listening on http://0.0.0.0:${PORT}/mcp`);
console.log(`Tools: portainer-list-stacks, portainer-restart, portainer-debug, portainer-logs, portainer-stack-file`);

process.on("SIGTERM", () => {
  httpServer.stop();
  process.exit(0);
});

process.on("SIGINT", () => {
  httpServer.stop();
  process.exit(0);
});
