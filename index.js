// ============================================================
//  proxy-server/index.js  (Node.js Backend)
//
//  ⚠️  DEPLOY ON YOUR SERVER ONLY — NEVER SHIP IN APK
//
//  Security Layers:
//    1. HMAC-SHA256 request signing  → Only YOUR app can call this
//    2. Timestamp check (5 min)      → Replay attacks blocked
//    3. Rate limiting per IP         → Abuse slowed down
//    4. Helmet headers               → HTTP attack surface reduced
//    5. Input size limits            → Injection/DoS prevented
//
//  Model Swap (ONE LINE):
//    Change MODEL_ID in .env — zero app/APK changes needed.
//
//  Setup:
//    npm install express axios dotenv helmet express-rate-limit
//    Fill .env (see .env.example)
//    node index.js
// ============================================================

require("dotenv").config();
const express   = require("express");
const axios     = require("axios");
const helmet    = require("helmet");
const rateLimit = require("express-rate-limit");
const crypto    = require("crypto"); // Built-in Node.js — no install needed

const app = express();
app.use(express.json({ limit: "50kb" }));
app.use(helmet());

// ── Config (ALL from .env — NOTHING hardcoded) ───────────────
const OPENROUTER_BASE = "https://openrouter.ai/api/v1";
const API_KEY         = process.env.OPENROUTER_API_KEY;
const APP_SECRET      = process.env.APP_HMAC_SECRET;   // Shared with Android app
const MODEL_ID        = process.env.MODEL_ID || "meta-llama/llama-3.2-3b-instruct:free";
const PORT            = process.env.PORT || 3000;

// Fail fast — don't start with missing config
if (!API_KEY)    { console.error("❌  OPENROUTER_API_KEY not set"); process.exit(1); }
if (!APP_SECRET) { console.error("❌  APP_HMAC_SECRET not set");    process.exit(1); }

// ── Rate limiting ─────────────────────────────────────────────
// Even if someone bypasses HMAC, they still hit this wall
const limiter = rateLimit({
  windowMs: 60 * 1000,   // 1 minute
  max: 20,               // 20 requests per minute per IP
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests. Please slow down." }
});
app.use("/api/", limiter);

// ── HMAC Authentication Middleware ────────────────────────────
// Android app signs every request with: HMAC-SHA256(timestamp, APP_SECRET)
// This ensures ONLY your app (which knows the secret) can use this proxy.
// Even if someone finds your proxy URL, they can't forge valid signatures.
function hmacAuthMiddleware(req, res, next) {
  const timestamp = req.headers["x-timestamp"];
  const signature = req.headers["x-signature"];

  // Both headers must be present
  if (!timestamp || !signature) {
    return res.status(401).json({ error: "Missing auth headers." });
  }

  // Reject requests older than 5 minutes (prevents replay attacks)
  const age = Date.now() - parseInt(timestamp, 10);
  if (isNaN(age) || age < 0 || age > 5 * 60 * 1000) {
    return res.status(401).json({ error: "Request expired or invalid timestamp." });
  }

  // Compute expected HMAC
  const expected = crypto
    .createHmac("sha256", APP_SECRET)
    .update(timestamp)
    .digest("hex");

  // Constant-time comparison — prevents timing attacks
  const sigBuffer      = Buffer.from(signature, "hex");
  const expectedBuffer = Buffer.from(expected,  "hex");

  if (
    sigBuffer.length !== expectedBuffer.length ||
    !crypto.timingSafeEqual(sigBuffer, expectedBuffer)
  ) {
    console.warn(`⚠️  Invalid HMAC from IP: ${req.ip}`);
    return res.status(401).json({ error: "Unauthorized." });
  }

  next();
}

// Apply HMAC auth to ALL /api/ routes
app.use("/api/", hmacAuthMiddleware);

// ── System prompts per mode ───────────────────────────────────
function getSystemPrompt(mode) {
  switch (mode) {
    case "summarize":
      return "You are a concise summarizer. Summarize the given note in 2-3 clear sentences. Return only the summary, nothing else.";
    case "fix_grammar":
      return "You are a grammar expert. Fix all grammar, spelling, and punctuation errors. Return only the corrected text, no explanations or extra words.";
    case "chat":
    default:
      return "You are a helpful AI assistant. The user shares a note and asks questions about it. Be concise and context-aware.";
  }
}

// ── POST /api/ai/process ──────────────────────────────────────
app.post("/api/ai/process", async (req, res) => {
  const { noteContent, userMessage, mode } = req.body;

  // Input validation — defend against injection/oversized payloads
  if (!userMessage || typeof userMessage !== "string" || userMessage.trim().length === 0) {
    return res.status(400).json({ error: "userMessage is required." });
  }
  if (userMessage.length > 2_000) {
    return res.status(400).json({ error: "userMessage too long (max 2000 chars)." });
  }
  if (noteContent && noteContent.length > 8_000) {
    return res.status(400).json({ error: "Note content too long (max 8000 chars)." });
  }
  const allowedModes = ["chat", "summarize", "fix_grammar"];
  if (mode && !allowedModes.includes(mode)) {
    return res.status(400).json({ error: "Invalid mode." });
  }

  // Build message for Llama
  const userContent = noteContent?.trim()
    ? `Note content:\n\n${noteContent}\n\n${userMessage}`
    : userMessage;

  try {
    const response = await axios.post(
      `${OPENROUTER_BASE}/chat/completions`,
      {
        model: MODEL_ID,   // "meta-llama/llama-3.2-3b-instruct:free"
        messages: [
          { role: "system", content: getSystemPrompt(mode || "chat") },
          { role: "user",   content: userContent }
        ],
        max_tokens:  600,
        temperature: mode === "fix_grammar" ? 0.1 : 0.7
      },
      {
        headers: {
          "Authorization": `Bearer ${API_KEY}`,
          "Content-Type":  "application/json",
          "HTTP-Referer":  "https://notemania.app",
          "X-Title":       "NoteManiaApp"
        },
        timeout: 45_000   // Llama free tier can be slow
      }
    );

    const result     = response.data.choices?.[0]?.message?.content?.trim();
    const tokensUsed = response.data.usage?.total_tokens ?? 0;

    if (!result) {
      return res.status(502).json({ error: "AI returned empty response." });
    }

    return res.json({ result, tokens: tokensUsed });

  } catch (err) {
    const status  = err.response?.status  ?? 500;
    const message = err.response?.data?.error?.message ?? err.message;
    // Log server-side but don't expose internals to client
    console.error(`AI proxy error [${status}]: ${message}`);
    return res.status(status >= 400 && status < 600 ? status : 500).json({
      error: "AI request failed. Please try again."
    });
  }
});

// ── Health check (no auth — just uptime ping) ─────────────────
app.get("/health", (_, res) =>
  res.json({ status: "ok", model: MODEL_ID, time: new Date().toISOString() })
);

app.listen(PORT, () =>
  console.log(`✅  NoteManiaProxy | port: ${PORT} | model: ${MODEL_ID}`)
);