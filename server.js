import express from "express";
import fs from "node:fs";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const exec = promisify(execFile);
const app = express();
app.use(express.json({ limit: "1mb" }));

const SHARED_SECRET = process.env.SIDECAR_SHARED_SECRET;
const CORAL_BIN = process.env.CORAL_BIN || "coral";
const CORAL_CONFIG_DIR = process.env.CORAL_CONFIG_DIR || "/coral-config";
const CONFIG_PATH = path.join(CORAL_CONFIG_DIR, "config.json");
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

app.get("/health", async (_req, res) => {
  const result = await runCoral(["--version"], 5000);
  res.json({ ok: result.ok, version: result.stdout?.trim() });
});

app.post("/sql", authenticate, async (req, res) => {
  const { sql } = req.body ?? {};
  if (typeof sql !== "string" || sql.length === 0) {
    return res.status(400).json({ error: "sql is required" });
  }
  if (sql.length > MAX_SQL_LEN) {
    return res.status(400).json({ error: "sql too long" });
  }
  const result = await runCoral(["sql", "--format", "json", sql]);
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

app.get("/list-catalog", authenticate, async (_req, res) => {
  const result = await runCoral([
    "sql",
    "--format",
    "json",
    "SELECT schema_name, table_name, description, required_filters, guide FROM coral.tables ORDER BY schema_name, table_name",
  ]);
  if (!result.ok) {
    return res.status(422).json({ error: "catalog_failed", detail: result.stderr });
  }
  res.json({ tables: JSON.parse(result.stdout || "[]") });
});

app.get("/list-columns", authenticate, async (req, res) => {
  const { schema, table } = req.query;
  if (!schema || !table) return res.status(400).json({ error: "schema and table required" });
  const result = await runCoral([
    "sql",
    "--format",
    "json",
    `SELECT column_name, data_type, is_nullable, is_required_filter, description
     FROM coral.columns WHERE schema_name = '${String(schema).replace(/'/g, "''")}'
     AND table_name = '${String(table).replace(/'/g, "''")}' ORDER BY ordinal_position`,
  ]);
  if (!result.ok) {
    return res.status(422).json({ error: "columns_failed", detail: result.stderr });
  }
  res.json({ columns: JSON.parse(result.stdout || "[]") });
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
} catch (error) {
  console.error("Failed to initialize volume paths:", error);
}

const PORT = Number(process.env.PORT || 3000);
app.listen(PORT, () => console.log(`Coral sidecar listening on ${PORT}`));
