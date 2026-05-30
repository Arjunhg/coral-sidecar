import express from "express";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const exec = promisify(execFile);
const app = express();
app.use(express.json({ limit: "1mb" }));

const SHARED_SECRET = process.env.SIDECAR_SHARED_SECRET;
const CORAL_BIN = process.env.CORAL_BIN || "coral";
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

const PORT = Number(process.env.PORT || 3000);
app.listen(PORT, () => console.log(`Coral sidecar listening on ${PORT}`));
