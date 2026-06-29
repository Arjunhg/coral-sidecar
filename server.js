import "dotenv/config";
import express from "express";
import fs from "node:fs";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import dotenv from "dotenv";

const exec = promisify(execFile);
const app = express();
app.use(express.json({ limit: "1mb" }));

const SHARED_SECRET = process.env.SIDECAR_SHARED_SECRET;
const CORAL_BIN = process.env.CORAL_BIN || "coral";
const CURL_BIN = process.env.CURL_BIN || "curl";
const CORAL_CONFIG_DIR = process.env.CORAL_CONFIG_DIR || "/coral-config";
const TENANT_CONFIG_ROOT = path.join(CORAL_CONFIG_DIR, "users");
const CONFIG_PATH = path.join(CORAL_CONFIG_DIR, "config.json");
const TENANT_CONNECTIONS_FILE = "tenant-connections.json";
const DEFAULT_TIMEOUT_MS = 15_000;
const MAX_SQL_LEN = 8000; 

function authenticate(req, res, next) {
  const got = req.headers["x-sidecar-secret"];
  if (!SHARED_SECRET || got !== SHARED_SECRET) {
    return res.status(401).json({ error: "unauthorized" });
  }
  next();
}

async function runCoral(args, timeoutMs = DEFAULT_TIMEOUT_MS) {
  try {
    const { stdout, stderr } = await exec(CORAL_BIN, args, {
      timeout: timeoutMs,
      maxBuffer: 32 * 1024 * 1024, // 32MB for large result sets
    });
    return { ok: true, stdout, stderr };
  } catch (err) {
    return {
      ok: false,
      stderr: err.stderr?.toString() || err.message,
      stdout: err.stdout?.toString() || "",
      code: err.code,
    };
  }
}

async function runCoralWithConfig(configDir, args, options = {}) {
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const extraEnv = options.env ?? {};

  try {
    const { stdout, stderr } = await exec(CORAL_BIN, args, {
      timeout: timeoutMs,
      maxBuffer: 32 * 1024 * 1024,
      env: {
        ...process.env,
        CORAL_CONFIG_DIR: configDir,
        ...extraEnv,
      },
    });
    return { ok: true, stdout, stderr };
  } catch (err) {
    return {
      ok: false,
      stderr: err.stderr?.toString() || err.message,
      stdout: err.stdout?.toString() || "",
      code: err.code,
    };
  }
}

async function runCurl(args, timeoutMs = DEFAULT_TIMEOUT_MS) {
  try {
    const { stdout, stderr } = await exec(CURL_BIN, args, {
      timeout: timeoutMs,
      maxBuffer: 32 * 1024 * 1024,
    });
    return { ok: true, stdout, stderr };
  } catch (err) {
    return {
      ok: false,
      stderr: err.stderr?.toString() || err.message,
      stdout: err.stdout?.toString() || "",
      code: err.code,
    };
  }
}

function requireLoopback(req, res, next) {
  const remote = req.socket?.remoteAddress || "";
  const forwardedFor = String(req.headers["x-forwarded-for"] || "");
  const isLoopback =
    remote === "::1" ||
    remote === "127.0.0.1" ||
    remote === "::ffff:127.0.0.1" ||
    forwardedFor.includes("127.0.0.1") ||
    forwardedFor.includes("::1");

  if (!isLoopback) {
    return res.status(403).json({ error: "loopback_only" });
  }

  next();
}

function getSplunkProxyConfig(req) {
  const splunkHost = String(req.headers["x-splunk-host"] || "").trim().replace(/\/+$/, "");
  const splunkToken = String(req.headers["x-splunk-token"] || "").trim();

  if (!splunkHost || !splunkToken) {
    return { error: "x-splunk-host and x-splunk-token are required" };
  }

  return { splunkHost, splunkToken };
}

function sanitizeTenantId(rawTenantId) {
  const tenantId = String(rawTenantId || "").trim();
  if (!tenantId) return null;
  if (!/^[A-Za-z0-9_-]{1,128}$/.test(tenantId)) {
    return null;
  }
  return tenantId;
}

function getTenantConfigDir(tenantId) {
  return path.join(TENANT_CONFIG_ROOT, tenantId);
}

function getTenantConnectionsPath(configDir) {
  return path.join(configDir, TENANT_CONNECTIONS_FILE);
}

function ensureConfigTemplate(configDir) {
  if (!fs.existsSync(configDir)) {
    fs.mkdirSync(configDir, { recursive: true });
  }

  const configPath = path.join(configDir, "config.json");
  if (!fs.existsSync(configPath)) {
    const defaultConfig = { initializedAt: new Date().toISOString(), version: "1.0.0" };
    fs.writeFileSync(configPath, JSON.stringify(defaultConfig, null, 2));
  }
}

function ensureTenantSeededFromShared(tenantConfigDir) {
  if (fs.existsSync(tenantConfigDir)) {
    ensureConfigTemplate(tenantConfigDir);
    return;
  }

  fs.mkdirSync(tenantConfigDir, { recursive: true });

  if (fs.existsSync(CORAL_CONFIG_DIR)) {
    fs.cpSync(CORAL_CONFIG_DIR, tenantConfigDir, {
      recursive: true,
      force: true,
      filter: (sourcePath) => path.basename(sourcePath) !== "users",
    });
  }

  ensureConfigTemplate(tenantConfigDir);
}

function readTenantConnections(configDir) {
  const filePath = getTenantConnectionsPath(configDir);
  if (!fs.existsSync(filePath)) {
    return { sources: {} };
  }

  try {
    const parsed = JSON.parse(fs.readFileSync(filePath, "utf8"));
    return parsed && typeof parsed === "object" && parsed.sources ? parsed : { sources: {} };
  } catch {
    return { sources: {} };
  }
}

function writeTenantConnections(configDir, data) {
  const filePath = getTenantConnectionsPath(configDir);
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
}

function upsertTenantConnection(configDir, sourceName, status) {
  const next = readTenantConnections(configDir);
  next.sources[sourceName] = {
    scope: "personal",
    status,
    last_verified_at: new Date().toISOString(),
  };
  writeTenantConnections(configDir, next);
  return next.sources[sourceName];
}

async function listConfiguredSources(configDir) {
  if (!fs.existsSync(configDir)) {
    return new Set();
  }
  const result = await runCoralWithConfig(
    configDir,
    [
      "sql",
      "--format",
      "json",
      `SELECT DISTINCT schema_name AS source_name
       FROM (
         SELECT schema_name FROM coral.tables
         UNION ALL
         SELECT schema_name FROM coral.table_functions
       ) configured_sources
       ORDER BY source_name`,
    ],
    { timeoutMs: 8000 }
  );

  if (!result.ok) {
    return new Set();
  }

  try {
    const rows = JSON.parse(result.stdout || "[]");
    return new Set(
      rows
        .map((row) => String(row.source_name || "").trim())
        .filter(Boolean)
    );
  } catch {
    return new Set();
  }
}

async function resolveCoralConfigForTenant(rawTenantId) {
  const tenantId = sanitizeTenantId(rawTenantId);
  if (!tenantId) {
    return { tenantId: null, configDir: CORAL_CONFIG_DIR, scope: "shared" };
  }

  const tenantConfigDir = getTenantConfigDir(tenantId);
  const tenantSources = await listConfiguredSources(tenantConfigDir);
  if (tenantSources.size > 0) {
    return { tenantId, configDir: tenantConfigDir, scope: "tenant", tenantSources };
  }

  return { tenantId, configDir: CORAL_CONFIG_DIR, scope: "shared", tenantSources };
}

function getTenantIdFromRequest(req) {
  const rawTenantId = req.headers["x-coral-tenant"];
  if (!rawTenantId) return null;
  const tenantId = sanitizeTenantId(rawTenantId);
  if (!tenantId) {
    return { error: "invalid_tenant_id" };
  }
  return { tenantId };
}

const CORAL_SOURCES_DIR = process.env.CORAL_SOURCES_DIR || "";

function resolveSourceManifestPath(source) {
  const candidates = [
    // Explicit override via env var (highest priority)
    ...(CORAL_SOURCES_DIR ? [path.join(CORAL_SOURCES_DIR, `${source}.yaml`)] : []),
    // Inside the coral config directory
    path.join(CORAL_CONFIG_DIR, "coral-sources", `${source}.yaml`),
    path.join(CORAL_CONFIG_DIR, "sources", `${source}.yaml`),
    // Relative to sidecar cwd
    path.join(process.cwd(), "coral-sources", `${source}.yaml`),
    path.join(process.cwd(), "..", "coral-sources", `${source}.yaml`),
    // Docker / absolute paths
    path.join("/app", "coral-sources", `${source}.yaml`),
    path.join("/coral-sources", `${source}.yaml`),
  ];

  const found = candidates.find((candidate) => fs.existsSync(candidate)) || null;
  if (!found) {
    console.error(`[sidecar] source_manifest_not_found for "${source}". Searched:\n${candidates.map(c => `  - ${c}`).join("\n")}`);
  }
  return found;
}

function normalizeSplunkEntry(entry, mapper) {
  const content = entry?.content && typeof entry.content === "object" ? entry.content : {};
  return mapper(entry, content);
}

function parseJsonOrFail(result, res, errorCode) {
  try {
    return JSON.parse(result.stdout || "{}");
  } catch (error) {
    res.status(500).json({ error: errorCode, detail: error.message });
    return null;
  }
}

function normalizeSavedSearches(payload) {
  const entries = Array.isArray(payload.entry) ? payload.entry : [];
  return entries.map((entry) =>
    normalizeSplunkEntry(entry, (row, content) => ({
      name: row.name ?? null,
      id: row.id ?? null,
      updated: row.updated ?? null,
      description: content.description ?? null,
      search: content.search ?? null,
      disabled: content.disabled ?? null,
      cron_schedule: content.cron_schedule ?? null,
      actions: content.actions ?? null,
      alert_type: content.alert_type ?? null,
      alert_condition: content.alert_condition ?? null,
      alert_threshold: content.alert_threshold ?? null,
      raw_content: content,
    }))
  );
}

function normalizeFiredAlerts(payload) {
  const entries = Array.isArray(payload.entry) ? payload.entry : [];
  return entries.map((entry) =>
    normalizeSplunkEntry(entry, (row, content) => ({
      name: row.name ?? null,
      id: row.id ?? null,
      updated: row.updated ?? null,
      triggered_alert_count: content.triggered_alert_count ?? null,
      raw_content: content,
    }))
  );
}

function normalizeIndexes(payload) {
  const entries = Array.isArray(payload.entry) ? payload.entry : [];
  return entries.map((entry) =>
    normalizeSplunkEntry(entry, (row, content) => ({
      name: row.name ?? null,
      id: row.id ?? null,
      updated: row.updated ?? null,
      datatype: content.datatype ?? null,
      disabled: content.disabled ?? null,
      total_event_count: content.totalEventCount ?? null,
      current_db_size_mb: content.currentDBSizeMB ?? null,
      max_total_data_size_mb: content.maxTotalDataSizeMB ?? null,
      is_internal: content.isInternal ?? null,
      home_path: content.homePath_expanded ?? null,
      cold_path: content.coldPath_expanded ?? null,
      raw_content: content,
    }))
  );
}

function normalizeSearchResults(payload) {
  const fields = Array.isArray(payload.fields) ? payload.fields : [];
  const rows = Array.isArray(payload.rows) ? payload.rows : [];
  return rows.map((row) => {
    const out = {};
    fields.forEach((field, index) => {
      out[field] = Array.isArray(row) ? row[index] ?? null : null;
    });
    return out;
  });
}

async function splunkCurlJson(req, res, endpoint, errorCode) {
  const config = getSplunkProxyConfig(req);
  if (config.error) {
    return res.status(400).json({ error: config.error });
  }

  const { splunkHost, splunkToken } = config;
  const result = await runCurl(
    [
      "-k",
      "-sS",
      "-H",
      `Authorization: Bearer ${splunkToken}`,
      `${splunkHost}${endpoint}`,
    ],
    DEFAULT_TIMEOUT_MS
  );

  if (!result.ok) {
    return res.status(502).json({ error: errorCode, detail: result.stderr });
  }

  return parseJsonOrFail(result, res, `${errorCode}_invalid_json`);
}

app.get("/health", async (_req, res) => {
  const result = await runCoral(["--version"], 5000);
  res.json({ ok: result.ok, version: result.stdout?.trim() });
});

app.post("/sql", authenticate, async (req, res) => {
  const tenant = getTenantIdFromRequest(req);
  if (tenant?.error) {
    return res.status(400).json({ error: tenant.error });
  }

  const { sql } = req.body ?? {};
  if (typeof sql !== "string" || sql.length === 0) {
    return res.status(400).json({ error: "sql is required" });
  }
  if (sql.length > MAX_SQL_LEN) {
    return res.status(400).json({ error: "sql too long" });
  }
  const resolved = await resolveCoralConfigForTenant(tenant?.tenantId);
  console.log(`[sidecar][tenant:${resolved.tenantId ?? "shared"}][scope:${resolved.scope}] /sql`);
  const result = await runCoralWithConfig(resolved.configDir, ["sql", "--format", "json", sql]);
  if (!result.ok) {
    return res.status(422).json({ error: "coral_query_failed", detail: result.stderr });
  }
  try {
    const rows = JSON.parse(result.stdout || "[]");
    res.json({ rows });
  } catch (e) {
    res.status(500).json({ error: "invalid_coral_output", detail: e.message });
  }
});

app.get("/list-catalog", authenticate, async (req, res) => {
  const tenant = getTenantIdFromRequest(req);
  if (tenant?.error) {
    return res.status(400).json({ error: tenant.error });
  }

  const resolved = await resolveCoralConfigForTenant(tenant?.tenantId);
  console.log(`[sidecar][tenant:${resolved.tenantId ?? "shared"}][scope:${resolved.scope}] /list-catalog`);

  // NOTE: These two relations are queried separately and merged in JS rather
  // than via a single SQL `UNION ALL`. Combining the plain column scan from
  // coral.tables with the aggregated (string_agg/COALESCE) column from
  // coral.table_functions triggers an Apache Arrow / DataFusion offset-buffer
  // bug: "Offset invariant failure: non-monotonic offset". Running them apart
  // avoids the engine concatenating those two Utf8 buffers.
  const tablesResult = await runCoralWithConfig(resolved.configDir, [
    "sql",
    "--format",
    "json",
    `SELECT schema_name,
            table_name,
            description,
            required_filters,
            guide,
            'table' AS relation_type
     FROM coral.tables`,
  ]);
  if (!tablesResult.ok) {
    return res.status(422).json({ error: "catalog_failed", detail: tablesResult.stderr });
  }

  const functionsResult = await runCoralWithConfig(resolved.configDir, [
    "sql",
    "--format",
    "json",
    `SELECT tf.schema_name,
            tf.function_name AS table_name,
            tf.description,
            COALESCE(string_agg(CASE WHEN f.is_required THEN f.filter_name END, ', ' ORDER BY f.filter_name), '') AS required_filters,
            CASE
              WHEN tf.kind = 'search' THEN 'Call as a table function: schema.function(arg => ''value'').'
              ELSE 'Call as a table function with named arguments.'
            END AS guide,
            'table_function' AS relation_type
     FROM coral.table_functions tf
     LEFT JOIN coral.filters f
       ON f.schema_name = tf.schema_name
      AND f.table_name = tf.function_name
     GROUP BY tf.schema_name, tf.function_name, tf.description, tf.kind`,
  ]);
  if (!functionsResult.ok) {
    return res.status(422).json({ error: "catalog_failed", detail: functionsResult.stderr });
  }

  try {
    const tables = JSON.parse(tablesResult.stdout || "[]");
    const functions = JSON.parse(functionsResult.stdout || "[]");
    const catalog = [...tables, ...functions].sort((a, b) => {
      const schemaCmp = String(a.schema_name).localeCompare(String(b.schema_name));
      return schemaCmp !== 0 ? schemaCmp : String(a.table_name).localeCompare(String(b.table_name));
    });
    res.json({ tables: catalog });
  } catch (e) {
    res.status(500).json({ error: "invalid_coral_output", detail: e.message });
  }
});

app.get("/list-columns", authenticate, async (req, res) => {
  const tenant = getTenantIdFromRequest(req);
  if (tenant?.error) {
    return res.status(400).json({ error: tenant.error });
  }

  const { schema, table } = req.query;
  if (!schema || !table) return res.status(400).json({ error: "schema and table required" });
  const resolved = await resolveCoralConfigForTenant(tenant?.tenantId);
  console.log(`[sidecar][tenant:${resolved.tenantId ?? "shared"}][scope:${resolved.scope}] /list-columns ${schema}.${table}`);
  const result = await runCoralWithConfig(resolved.configDir, [
    "sql",
    "--format",
    "json",
    `SELECT column_name, data_type, is_nullable, is_required_filter, description
     FROM (
       SELECT column_name,
              data_type,
              is_nullable,
              is_required_filter,
              description,
              ordinal_position
       FROM coral.columns
       WHERE schema_name = '${String(schema).replace(/'/g, "''")}'
         AND table_name = '${String(table).replace(/'/g, "''")}'
       UNION ALL
       SELECT filter_name AS column_name,
              data_type,
              true AS is_nullable,
              is_required AS is_required_filter,
              description,
              1000000 AS ordinal_position
       FROM coral.filters
       WHERE schema_name = '${String(schema).replace(/'/g, "''")}'
         AND table_name = '${String(table).replace(/'/g, "''")}'
     ) relation_fields
     ORDER BY ordinal_position, column_name`,
  ]);
  if (!result.ok) {
    return res.status(422).json({ error: "columns_failed", detail: result.stderr });
  }
  res.json({ columns: JSON.parse(result.stdout || "[]") });
});

app.post("/provision", authenticate, async (req, res) => {
  const { tenant_id: rawTenantId, source, vars } = req.body ?? {};
  const tenantId = sanitizeTenantId(rawTenantId);
  if (!tenantId) {
    return res.status(400).json({ error: "invalid_tenant_id" });
  }
  if (typeof source !== "string" || !/^[A-Za-z0-9_-]+$/.test(source)) {
    return res.status(400).json({ error: "invalid_source" });
  }
  if (!vars || typeof vars !== "object" || Array.isArray(vars)) {
    return res.status(400).json({ error: "vars must be an object" });
  }

  const sourceFile = resolveSourceManifestPath(source);
  if (!sourceFile) {
    return res.status(404).json({ error: "source_manifest_not_found" });
  }

  const tenantConfigDir = getTenantConfigDir(tenantId);
  ensureTenantSeededFromShared(tenantConfigDir);
  console.log(`[sidecar][tenant:${tenantId}][scope:tenant] /provision ${source}`);

  const envVars = Object.fromEntries(
    Object.entries(vars)
      .filter(([key, value]) => /^[A-Za-z_][A-Za-z0-9_]*$/.test(key) && value !== null && value !== undefined)
      .map(([key, value]) => [key, String(value)])
  );

  await runCoralWithConfig(tenantConfigDir, ["source", "remove", source], {
    timeoutMs: 5000,
  });

  const addResult = await runCoralWithConfig(tenantConfigDir, ["source", "add", "--file", sourceFile], {
    env: envVars,
    timeoutMs: 30000,
  });
  if (!addResult.ok) {
    return res.status(422).json({ error: "provision_add_failed", detail: addResult.stderr });
  }

  const testResult = await runCoralWithConfig(tenantConfigDir, ["source", "test", source], {
    timeoutMs: 30000,
  });
  if (!testResult.ok) {
    upsertTenantConnection(tenantConfigDir, source, "failed");
    return res.status(422).json({ error: "provision_test_failed", detail: testResult.stderr });
  }

  const connection = upsertTenantConnection(tenantConfigDir, source, "connected");
  const configuredSources = [...(await listConfiguredSources(tenantConfigDir))];

  res.json({
    ok: true,
    tenant_id: tenantId,
    source,
    status: connection.status,
    last_verified_at: connection.last_verified_at,
    configured_sources: configuredSources,
  });
});

app.get("/connections", authenticate, async (req, res) => {
  const tenantId = sanitizeTenantId(req.query.tenant_id);
  if (!tenantId) {
    return res.status(400).json({ error: "invalid_tenant_id" });
  }

  const sharedSources = await listConfiguredSources(CORAL_CONFIG_DIR);
  const tenantConfigDir = getTenantConfigDir(tenantId);
  const tenantSources = await listConfiguredSources(tenantConfigDir);
  const tenantMetadata = readTenantConnections(tenantConfigDir);

  const allSources = new Set([
    ...sharedSources,
    ...tenantSources,
    ...Object.keys(tenantMetadata.sources || {}),
  ]);

  const connections = [...allSources]
    .sort((a, b) => a.localeCompare(b))
    .map((sourceName) => {
      const personalMeta = tenantMetadata.sources?.[sourceName];
      const scope =
        personalMeta?.scope === "personal" || (!sharedSources.has(sourceName) && tenantSources.has(sourceName))
          ? "personal"
          : "inherited";
      const active_via = tenantSources.has(sourceName) ? "tenant" : sharedSources.has(sourceName) ? "shared" : null;

      return {
        source_name: sourceName,
        scope,
        active_via,
        status: personalMeta?.status ?? "connected",
        last_verified_at: personalMeta?.last_verified_at ?? null,
      };
    });

  console.log(`[sidecar][tenant:${tenantId}][scope:${tenantSources.size > 0 ? "tenant" : "shared"}] /connections`);
  res.json({ tenant_id: tenantId, connections });
});

app.get("/debug/volume", authenticate, async (_req, res) => {
  try {
    if (!fs.existsSync(CORAL_CONFIG_DIR)) {
      return res.status(404).json({ error: "Volume directory does not exist" });
    }
    const files = fs.readdirSync(CORAL_CONFIG_DIR);
    res.json({ volumePath: CORAL_CONFIG_DIR, files });
  } catch (err) {
    res.status(500).json({ error: "Failed to read volume", detail: err.message });
  }
});

app.get("/splunk-proxy/indexes", requireLoopback, async (req, res) => {
  const payload = await splunkCurlJson(
    req,
    res,
    "/services/data/indexes?output_mode=json&count=100",
    "splunk_indexes_failed"
  );
  if (!payload) return;
  res.json({ rows: normalizeIndexes(payload) });
});

app.get("/splunk-proxy/saved-searches", requireLoopback, async (req, res) => {
  const payload = await splunkCurlJson(
    req,
    res,
    "/services/saved/searches?output_mode=json&count=100",
    "splunk_saved_searches_failed"
  );
  if (!payload) return;
  res.json({ rows: normalizeSavedSearches(payload) });
});

app.get("/splunk-proxy/fired-alerts", requireLoopback, async (req, res) => {
  const payload = await splunkCurlJson(
    req,
    res,
    "/services/alerts/fired_alerts?output_mode=json&count=100",
    "splunk_fired_alerts_failed"
  );
  if (!payload) return;
  res.json({ rows: normalizeFiredAlerts(payload) });
});

app.get("/splunk-proxy/search-results", requireLoopback, async (req, res) => {
  const config = getSplunkProxyConfig(req);
  if (config.error) {
    return res.status(400).json({ error: config.error });
  }

  const search = String(req.query.search || "").trim();
  if (!search) {
    return res.status(400).json({ error: "search is required" });
  }

  const { splunkHost, splunkToken } = config;
  const result = await runCurl(
    [
      "-k",
      "-sS",
      "-H",
      `Authorization: Bearer ${splunkToken}`,
      "-X",
      "POST",
      `${splunkHost}/services/search/jobs/export`,
      "-d",
      "output_mode=json_rows",
      "-d",
      `search=${search}`,
    ],
    DEFAULT_TIMEOUT_MS
  );

  if (!result.ok) {
    return res.status(502).json({ error: "splunk_search_results_failed", detail: result.stderr });
  }

  const payload = parseJsonOrFail(result, res, "splunk_search_results_invalid_json");
  if (!payload) return;
  res.json({ rows: normalizeSearchResults(payload) });
});

// Ensure the volume directory and config file exist before starting the server.
try {
  if (!fs.existsSync(CORAL_CONFIG_DIR)) {
    fs.mkdirSync(CORAL_CONFIG_DIR, { recursive: true });
    console.log(`Created volume directory at ${CORAL_CONFIG_DIR}`);
  }

  if (!fs.existsSync(CONFIG_PATH)) {
    const defaultConfig = { initializedAt: new Date().toISOString(), version: "1.0.0" };
    fs.writeFileSync(CONFIG_PATH, JSON.stringify(defaultConfig, null, 2));
    console.log(`Initialized default config template at ${CONFIG_PATH}`);
  }

  // Auto-seed coral-sources into CORAL_CONFIG_DIR if they exist locally but not in config dir
  const localSourcesDirs = [
    path.join(process.cwd(), "coral-sources"),
    path.join(process.cwd(), "..", "coral-sources"),
  ];
  const configSourcesDir = path.join(CORAL_CONFIG_DIR, "coral-sources");
  if (!fs.existsSync(configSourcesDir)) {
    for (const srcDir of localSourcesDirs) {
      if (fs.existsSync(srcDir)) {
        fs.cpSync(srcDir, configSourcesDir, { recursive: true });
        console.log(`Seeded coral-sources from ${srcDir} → ${configSourcesDir}`);
        break;
      }
    }
  }
} catch (error) {
  console.error("Failed to initialize volume paths:", error);
}

const PORT = Number(process.env.PORT || 3000);
app.listen(PORT, () => console.log(`Coral sidecar listening on ${PORT}`));
