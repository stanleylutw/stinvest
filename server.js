import "dotenv/config";
import express from "express";
import session from "express-session";
import { google } from "googleapis";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";

const app = express();
const port = Number(process.env.PORT || 3000);
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const isProduction = process.env.NODE_ENV === "production";
const ALLOWED_ORIGINS = [
  "http://localhost:3000",
  "https://stanleylutw.github.io"
];
const ALLOWED_RETURN_ORIGINS = new Set(ALLOWED_ORIGINS);
const API_TOKEN_TTL_MS = 1000 * 60 * 60 * 24 * 7;
const issuedApiTokens = new Map();

const supabaseUrl = process.env.SUPABASE_URL || "";
const supabaseServiceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY || "";

if (isProduction) {
  app.set("trust proxy", 1);
}

const requiredEnvs = [
  "GOOGLE_CLIENT_ID",
  "GOOGLE_CLIENT_SECRET",
  "GOOGLE_REDIRECT_URI",
  "SESSION_SECRET",
  "GOOGLE_SPREADSHEET_ID"
];

const missing = requiredEnvs.filter((k) => !process.env[k]);
if (missing.length > 0) {
  console.error(`Missing env vars: ${missing.join(", ")}`);
  process.exit(1);
}

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: isProduction ? "none" : "lax",
      secure: isProduction
    }
  })
);

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
    res.setHeader("Access-Control-Allow-Credentials", "true");
    res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
    res.setHeader(
      "Access-Control-Allow-Headers",
      "Content-Type, Authorization, X-St-Token, X-Supabase-Access-Token"
    );
  }

  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }

  next();
});
app.use(express.json({ limit: "1mb" }));

const oauth2Client = new google.auth.OAuth2(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  process.env.GOOGLE_REDIRECT_URI
);

const SCOPES = ["https://www.googleapis.com/auth/spreadsheets.readonly"];
const spreadsheetId = process.env.GOOGLE_SPREADSHEET_ID;

// Customize your sheet tabs here, e.g. "01_股票_基金!A1:Z300"
const DEFAULT_RANGES = [
  "'01_股票基金'!A1:Z300",
  "'02_投資分布圖'!A1:Z300",
  "'09_歷史紀錄'!A1:M5000"
];

app.use(express.static(__dirname));

app.get("/health", (_req, res) => {
  res.type("text/plain").send("ok");
});

function normalizeReturnTo(raw) {
  if (!raw || typeof raw !== "string") return null;
  try {
    const u = new URL(raw);
    if (!ALLOWED_RETURN_ORIGINS.has(u.origin)) return null;
    return u.toString();
  } catch (_err) {
    return null;
  }
}

function encodeState(payload) {
  return Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
}

function decodeState(stateText) {
  if (!stateText || typeof stateText !== "string") return {};
  try {
    const json = Buffer.from(stateText, "base64url").toString("utf8");
    return JSON.parse(json);
  } catch (_err) {
    return {};
  }
}

function issueApiToken(tokens) {
  const apiToken = crypto.randomBytes(24).toString("base64url");
  issuedApiTokens.set(apiToken, {
    tokens,
    expiresAt: Date.now() + API_TOKEN_TTL_MS
  });
  return apiToken;
}

function getTokensFromApiToken(apiToken) {
  if (!apiToken || typeof apiToken !== "string") return null;
  const item = issuedApiTokens.get(apiToken);
  if (!item) return null;
  if (Date.now() > item.expiresAt) {
    issuedApiTokens.delete(apiToken);
    return null;
  }
  return item.tokens;
}

function pickAuthToken(req) {
  const h = String(req.headers.authorization || "").trim();
  if (h.toLowerCase().startsWith("bearer ")) {
    return h.slice(7).trim();
  }
  if (typeof req.query.st_token === "string") {
    return req.query.st_token.trim();
  }
  return "";
}

function pickStToken(req) {
  const fromHeader = String(req.headers["x-st-token"] || "").trim();
  if (fromHeader) return fromHeader;
  return pickAuthToken(req);
}

function pickSupabaseAccessToken(req) {
  const fromHeader = String(req.headers["x-supabase-access-token"] || "").trim();
  if (fromHeader) return fromHeader;
  const h = String(req.headers.authorization || "").trim();
  if (h.toLowerCase().startsWith("bearer ")) {
    const token = h.slice(7).trim();
    if (token.split(".").length === 3) return token;
  }
  return "";
}

async function supabaseRequest(pathname, { method = "GET", body, headers = {} } = {}) {
  if (!supabaseUrl || !supabaseServiceRoleKey) {
    throw new Error("Supabase env not configured: SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY");
  }
  const url = `${supabaseUrl}${pathname}`;
  const reqHeaders = {
    apikey: supabaseServiceRoleKey,
    Authorization: `Bearer ${supabaseServiceRoleKey}`,
    ...headers
  };

  if (body !== undefined && !reqHeaders["Content-Type"]) {
    reqHeaders["Content-Type"] = "application/json";
  }

  const response = await fetch(url, {
    method,
    headers: reqHeaders,
    body: body === undefined ? undefined : JSON.stringify(body)
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`Supabase ${method} ${pathname} failed: ${response.status} ${text}`);
  }

  const text = await response.text();
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch (_err) {
    return text;
  }
}

async function getSupabaseUser(accessToken) {
  if (!supabaseUrl || !supabaseServiceRoleKey) {
    throw new Error("Supabase env not configured");
  }

  const response = await fetch(`${supabaseUrl}/auth/v1/user`, {
    headers: {
      apikey: supabaseServiceRoleKey,
      Authorization: `Bearer ${accessToken}`
    }
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`Supabase auth failed: ${response.status} ${text}`);
  }

  return response.json();
}

function toNumber(value) {
  const raw = String(value ?? "").trim();
  if (!raw) return null;
  const cleaned = raw.replace(/[\s,]/g, "").replace(/%$/, "");
  const n = Number(cleaned);
  if (!Number.isFinite(n)) return null;
  return n;
}

function getCell(row, index) {
  return String(row?.[index] ?? "").trim();
}

function findIndexByCandidates(headerRow, candidates) {
  for (let i = 0; i < headerRow.length; i += 1) {
    const normalized = String(headerRow[i] || "").replace(/^\*/, "").trim();
    if (candidates.includes(normalized)) return i;
  }
  return -1;
}

function buildPortfolioItemsFromSheet(valueRanges, { userId, sheetId, logId, sourceSpreadsheetId }) {
  const rows = valueRanges?.[0]?.values || [];
  if (!rows.length) return [];

  const headerRow = rows[0] || [];
  const idx = {
    name: findIndexByCandidates(headerRow, ["股票/ETF", "標的"]),
    price: findIndexByCandidates(headerRow, ["股價"]),
    move: findIndexByCandidates(headerRow, ["漲跌"]),
    accDividend: findIndexByCandidates(headerRow, ["累積配息"]),
    profitWithDividend: findIndexByCandidates(headerRow, ["含息損益"]),
    profitWithDividendRate: findIndexByCandidates(headerRow, ["含息損益率"]),
    marketValue: findIndexByCandidates(headerRow, ["市值"]),
    monthlyIncome: findIndexByCandidates(headerRow, ["月配額", "預估月配額"])
  };

  const items = [];
  let currentAccount = "未分類";
  let sheetOrder = 0;

  rows.slice(1).forEach((row) => {
    const accountMarkerCell = row.find((cell) => String(cell || "").trim().startsWith("#"));
    if (accountMarkerCell) {
      currentAccount = String(accountMarkerCell).trim().replace(/^#/, "").trim() || "未分類";
      return;
    }

    const name = getCell(row, idx.name);
    const hasStarMarkedCell = row.some((cell) => String(cell || "").trim().startsWith("*"));
    if (!name || name === "全帳戶" || hasStarMarkedCell) return;

    const hasAnyValue =
      getCell(row, idx.price) || getCell(row, idx.marketValue) || getCell(row, idx.profitWithDividend);
    if (!hasAnyValue) return;

    items.push({
      user_id: userId,
      sheet_id: sheetId,
      sync_log_id: logId,
      spreadsheet_id: sourceSpreadsheetId,
      account: currentAccount,
      item_name: name,
      sheet_order: sheetOrder,
      price: toNumber(getCell(row, idx.price)),
      move_text: getCell(row, idx.move) || null,
      acc_dividend: toNumber(getCell(row, idx.accDividend)),
      profit_with_dividend: toNumber(getCell(row, idx.profitWithDividend)),
      profit_with_dividend_rate: toNumber(getCell(row, idx.profitWithDividendRate)),
      market_value: toNumber(getCell(row, idx.marketValue)),
      monthly_income: toNumber(getCell(row, idx.monthlyIncome)),
      row_json: row
    });

    sheetOrder += 1;
  });

  return items;
}

async function fetchSheetDataBySpreadsheetId(tokens, targetSpreadsheetId, ranges = DEFAULT_RANGES) {
  oauth2Client.setCredentials(tokens);
  const sheets = google.sheets({ version: "v4", auth: oauth2Client });
  const response = await sheets.spreadsheets.values.batchGet({
    spreadsheetId: targetSpreadsheetId,
    ranges
  });

  return {
    spreadsheetId: targetSpreadsheetId,
    ranges,
    valueRanges: response.data.valueRanges || []
  };
}

setInterval(() => {
  const now = Date.now();
  for (const [k, v] of issuedApiTokens.entries()) {
    if (now > v.expiresAt) issuedApiTokens.delete(k);
  }
}, 1000 * 60 * 30).unref();

app.get("/auth/google", (req, res) => {
  const returnTo = normalizeReturnTo(req.query.returnTo);
  const authUrl = oauth2Client.generateAuthUrl({
    access_type: "offline",
    prompt: "consent",
    scope: SCOPES,
    state: encodeState({ returnTo })
  });
  res.redirect(authUrl);
});

app.get("/oauth2/callback", async (req, res) => {
  const code = req.query.code;
  if (!code || typeof code !== "string") {
    return res.status(400).send("Missing authorization code");
  }

  try {
    const { tokens } = await oauth2Client.getToken(code);
    req.session.tokens = tokens;
    const apiToken = issueApiToken(tokens);
    const state = decodeState(req.query.state);
    const returnTo = normalizeReturnTo(state.returnTo);
    req.session.save(() => {
      if (returnTo) {
        const to = new URL(returnTo);
        to.hash = `st_token=${encodeURIComponent(apiToken)}`;
        return res.redirect(to.toString());
      }
      return res.type("text/plain").send(
        "OAuth success. Now open /api/portfolio to fetch Google Sheets data."
      );
    });
  } catch (error) {
    console.error("OAuth callback error:", error);
    res.status(500).send("OAuth failed. Check server logs.");
  }
});

app.get("/api/portfolio", async (req, res) => {
  const authToken = pickStToken(req);
  const tokenFromBearer = getTokensFromApiToken(authToken);
  const tokens = req.session.tokens || tokenFromBearer;
  if (!tokens) {
    return res.status(401).json({
      error: "Unauthorized",
      message: "Please login first: /auth/google"
    });
  }

  try {
    const rangesQuery = req.query.ranges;
    let ranges = DEFAULT_RANGES;

    if (typeof rangesQuery === "string" && rangesQuery.trim()) {
      ranges = rangesQuery.split(",").map((r) => r.trim()).filter(Boolean);
    }

    const data = await fetchSheetDataBySpreadsheetId(tokens, spreadsheetId, ranges);

    return res.json({
      spreadsheetId: data.spreadsheetId,
      ranges: data.ranges,
      valueRanges: data.valueRanges
    });
  } catch (error) {
    console.error("Sheets read error:", error);
    return res.status(500).json({
      error: "ReadFailed",
      message: error.message
    });
  }
});

app.get("/api/portfolio-cached", async (req, res) => {
  const supabaseAccessToken = pickSupabaseAccessToken(req);
  if (!supabaseAccessToken) {
    return res.status(401).json({
      error: "Unauthorized",
      message: "Missing Supabase access token"
    });
  }

  try {
    const user = await getSupabaseUser(supabaseAccessToken);
    const userId = user?.id;
    if (!userId) throw new Error("Invalid Supabase user");

    const logs = await supabaseRequest(
      `/rest/v1/sync_logs?user_id=eq.${encodeURIComponent(userId)}&status=eq.success&order=finished_at.desc.nullslast,created_at.desc&limit=1&select=id,finished_at,row_count,spreadsheet_id,payload_json`
    );
    const latest = Array.isArray(logs) && logs.length ? logs[0] : null;
    if (!latest?.payload_json) {
      return res.status(404).json({
        error: "NoCache",
        message: "No synced cache found. Please run sync first."
      });
    }

    return res.json({
      source: "supabase-cache",
      cachedAt: latest.finished_at || null,
      syncLogId: latest.id || null,
      rowCount: latest.row_count ?? null,
      spreadsheetId: latest.spreadsheet_id || null,
      data: latest.payload_json
    });
  } catch (error) {
    console.error("Cached portfolio read error:", error);
    return res.status(500).json({
      error: "CacheReadFailed",
      message: error.message
    });
  }
});

app.post("/api/sync", async (req, res) => {
  const stToken = pickStToken(req);
  const tokenFromBearer = getTokensFromApiToken(stToken);
  const googleTokens = req.session.tokens || tokenFromBearer;
  if (!googleTokens) {
    return res.status(401).json({
      error: "Unauthorized",
      message: "Please login first: /auth/google"
    });
  }

  const supabaseAccessToken = pickSupabaseAccessToken(req);
  if (!supabaseAccessToken) {
    return res.status(401).json({
      error: "Unauthorized",
      message: "Missing Supabase access token"
    });
  }

  let syncLogId = "";
  try {
    const user = await getSupabaseUser(supabaseAccessToken);
    const userId = user?.id;
    if (!userId) {
      throw new Error("Invalid Supabase user");
    }

    const sheetRows = await supabaseRequest(
      `/rest/v1/user_sheets?user_id=eq.${encodeURIComponent(userId)}&is_active=eq.true&order=updated_at.desc&limit=1&select=id,sheet_url,spreadsheet_id`
    );
    const linkedSheet = Array.isArray(sheetRows) && sheetRows.length ? sheetRows[0] : null;
    if (!linkedSheet?.spreadsheet_id) {
      return res.status(400).json({
        error: "NoLinkedSheet",
        message: "Please bind Google Sheet URL first"
      });
    }

    const logRows = await supabaseRequest("/rest/v1/sync_logs", {
      method: "POST",
      headers: { Prefer: "return=representation" },
      body: {
        user_id: userId,
        sheet_id: linkedSheet.id,
        spreadsheet_id: linkedSheet.spreadsheet_id,
        status: "running",
        started_at: new Date().toISOString(),
        source_ranges: DEFAULT_RANGES
      }
    });
    syncLogId = Array.isArray(logRows) && logRows.length ? logRows[0].id : "";

    const sheetData = await fetchSheetDataBySpreadsheetId(
      googleTokens,
      linkedSheet.spreadsheet_id,
      DEFAULT_RANGES
    );

    const items = buildPortfolioItemsFromSheet(sheetData.valueRanges, {
      userId,
      sheetId: linkedSheet.id,
      logId: syncLogId || null,
      sourceSpreadsheetId: linkedSheet.spreadsheet_id
    });

    await supabaseRequest(
      `/rest/v1/portfolio_items?user_id=eq.${encodeURIComponent(userId)}&sheet_id=eq.${encodeURIComponent(linkedSheet.id)}`,
      { method: "DELETE" }
    );

    if (items.length > 0) {
      await supabaseRequest("/rest/v1/portfolio_items", {
        method: "POST",
        body: items
      });
    }

    const finishedAt = new Date().toISOString();

    await supabaseRequest(
      `/rest/v1/user_sheets?id=eq.${encodeURIComponent(linkedSheet.id)}&user_id=eq.${encodeURIComponent(userId)}`,
      {
        method: "PATCH",
        body: { last_synced_at: finishedAt }
      }
    );

    if (syncLogId) {
      await supabaseRequest(`/rest/v1/sync_logs?id=eq.${encodeURIComponent(syncLogId)}`, {
        method: "PATCH",
        body: {
          status: "success",
          finished_at: finishedAt,
          row_count: items.length,
          message: "sync completed",
          payload_json: sheetData
        }
      });
    }

    return res.json({
      ok: true,
      userId,
      sheetId: linkedSheet.id,
      spreadsheetId: linkedSheet.spreadsheet_id,
      syncedRows: items.length,
      finishedAt
    });
  } catch (error) {
    console.error("Sync error:", error);
    if (syncLogId) {
      try {
        await supabaseRequest(`/rest/v1/sync_logs?id=eq.${encodeURIComponent(syncLogId)}`, {
          method: "PATCH",
          body: {
            status: "failed",
            finished_at: new Date().toISOString(),
            error_message: String(error?.message || error).slice(0, 1000)
          }
        });
      } catch (logError) {
        console.error("Sync log update failed:", logError);
      }
    }

    return res.status(500).json({
      error: "SyncFailed",
      message: error.message
    });
  }
});

app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
