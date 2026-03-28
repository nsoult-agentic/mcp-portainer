/**
 * MCP server for Portainer — READ-ONLY monitoring and restart.
 * Deployed via GitHub Actions → ghcr.io → Portainer CE GitOps polling.
 *
 * Tools:
 *   portainer-list-stacks  — List all stacks with status
 *   portainer-restart      — Restart a container by name
 *
 * SECURITY: This server has NO create, inspect, exec, or logs capability.
 * Portainer API key = root access via Docker socket. Restricting to
 * list + restart prevents credential exposure and container escape.
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
console.log(`Tools: portainer-list-stacks, portainer-restart (READ-ONLY)`);

process.on("SIGTERM", () => {
  httpServer.stop();
  process.exit(0);
});

process.on("SIGINT", () => {
  httpServer.stop();
  process.exit(0);
});
