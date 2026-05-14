const express = require('express');
const path    = require('path');
const fs      = require('fs');
const crypto  = require('crypto');

const app  = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname)));

// ── Auth ─────────────────────────────────────────────────────
function makeToken(password) {
  return crypto.createHmac('sha256', password).update('gantt-auth-v1').digest('hex');
}

function authMiddleware(req, res, next) {
  if (!process.env.APP_PASSWORD) return next(); // no password set = open
  const auth = req.headers['authorization'];
  if (auth === `Bearer ${makeToken(process.env.APP_PASSWORD)}`) return next();
  res.status(401).json({ error: 'Unauthorized' });
}

app.post('/api/login', (req, res) => {
  if (!process.env.APP_PASSWORD) return res.json({ ok: true, token: null });
  if (req.body.password === process.env.APP_PASSWORD) {
    res.json({ ok: true, token: makeToken(req.body.password) });
  } else {
    res.status(401).json({ ok: false });
  }
});

// ── Storage: Postgres on Railway, file-based locally ─────────
let pool = null;

if (process.env.DATABASE_URL) {
  const { Pool } = require('pg');
  pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
  });
  pool.query(
    `CREATE TABLE IF NOT EXISTS gantt (
       id         INT PRIMARY KEY DEFAULT 1,
       data       JSONB NOT NULL,
       updated_at TIMESTAMPTZ DEFAULT NOW()
     )`
  ).catch(err => console.error('DB init error:', err.message));
} else {
  fs.mkdirSync(path.join(__dirname, 'data'), { recursive: true });
}

const DATA_FILE = path.join(__dirname, 'data', 'gantt.json');

async function readData() {
  if (pool) {
    const r = await pool.query('SELECT data FROM gantt WHERE id = 1');
    return r.rows[0]?.data ?? null;
  }
  if (fs.existsSync(DATA_FILE)) return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
  return null;
}

async function writeData(payload) {
  if (pool) {
    await pool.query(
      `INSERT INTO gantt (id, data) VALUES (1, $1)
       ON CONFLICT (id) DO UPDATE SET data = $1, updated_at = NOW()`,
      [payload]
    );
  } else {
    fs.writeFileSync(DATA_FILE, JSON.stringify(payload));
  }
}

// ── API routes ───────────────────────────────────────────────
app.get('/api/data', authMiddleware, async (_req, res) => {
  try   { res.json(await readData()); }
  catch (e) { console.error(e); res.status(500).json({ error: e.message }); }
});

app.post('/api/data', authMiddleware, async (req, res) => {
  try   { await writeData(req.body); res.json({ ok: true }); }
  catch (e) { console.error(e); res.status(500).json({ error: e.message }); }
});

app.listen(PORT, () => console.log(`Listening on :${PORT}`));
