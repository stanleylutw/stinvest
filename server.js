import "dotenv/config";
import express from "express";
import session from "express-session";
import { google } from "googleapis";
import path from "node:path";
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
    res.setHeader("Access-Control-Allow-Methods", "GET,OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  }

  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }

  next();
});

const oauth2Client = new google.auth.OAuth2(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  process.env.GOOGLE_REDIRECT_URI
);

const SCOPES = ["https://www.googleapis.com/auth/spreadsheets.readonly"];
const spreadsheetId = process.env.GOOGLE_SPREADSHEET_ID;

// Customize your sheet tabs here, e.g. "01_股票_基金!A1:Z300"
const DEFAULT_RANGES = [
  "'01_股票基金'!A1:Z300"
];

app.use(express.static(__dirname));

app.get("/health", (_req, res) => {
  res.type("text/plain").send("ok");
});

app.get("/auth/google", (_req, res) => {
  const authUrl = oauth2Client.generateAuthUrl({
    access_type: "offline",
    prompt: "consent",
    scope: SCOPES
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
    res.type("text/plain").send(
      "OAuth success. Now open /api/portfolio to fetch Google Sheets data."
    );
  } catch (error) {
    console.error("OAuth callback error:", error);
    res.status(500).send("OAuth failed. Check server logs.");
  }
});

app.get("/api/portfolio", async (req, res) => {
  if (!req.session.tokens) {
    return res.status(401).json({
      error: "Unauthorized",
      message: "Please login first: /auth/google"
    });
  }

  try {
    oauth2Client.setCredentials(req.session.tokens);
    const sheets = google.sheets({ version: "v4", auth: oauth2Client });

    const rangesQuery = req.query.ranges;
    let ranges = DEFAULT_RANGES;

    if (typeof rangesQuery === "string" && rangesQuery.trim()) {
      ranges = rangesQuery.split(",").map((r) => r.trim()).filter(Boolean);
    }

    const response = await sheets.spreadsheets.values.batchGet({
      spreadsheetId,
      ranges
    });

    return res.json({
      spreadsheetId,
      ranges,
      valueRanges: response.data.valueRanges || []
    });
  } catch (error) {
    console.error("Sheets read error:", error);
    return res.status(500).json({
      error: "ReadFailed",
      message: error.message
    });
  }
});

app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
