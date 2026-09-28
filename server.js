'use strict';

const express = require('express');
const crypto = require('crypto');
const { Pool } = require('pg');

const app = express();
app.use(express.json({ limit: '2mb' }));

/* =========================================================
   CONFIG
   ========================================================= */

const PORT = process.env.PORT || 3000;
const BOT_TOKEN = process.env.BOT_TOKEN;
const DATABASE_URL = process.env.DATABASE_URL;
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET || 'adewa_webhook_secret';
const BOT_USERNAME = String(process.env.BOT_USERNAME || '').replace('@', '');

const FRONTEND_ORIGIN = 'https://abdulselamahemade608-prog.github.io';
// Cache-buster so Telegram's WebView always fetches the latest frontend.
const MINI_APP_URL = `${FRONTEND_ORIGIN}/Adewa-frontend/?v=${Date.now()}`;
const WEBHOOK_URL = 'https://adewa.vercel.app/telegram/webhook';

const TELEGRAM_API = `https://api.telegram.org/bot${BOT_TOKEN}`;
const TELEGRAM_FILE_API = `https://api.telegram.org/file/bot${BOT_TOKEN}`;
const TZ = 'Africa/Addis_Ababa';

// Comma separated Telegram IDs: "111,222"
const ADMIN_IDS = String(process.env.ADMIN_IDS || '')
  .split(',').map((x) => x.trim()).filter(Boolean).map(Number);

if (!BOT_TOKEN) console.warn('WARNING: BOT_TOKEN is not configured.');
if (!DATABASE_URL) console.warn('WARNING: DATABASE_URL is not configured.');
if (!ADMIN_IDS.length) console.warn('WARNING: ADMIN_IDS is not configured.');
if (!BOT_USERNAME) console.warn('WARNING: BOT_USERNAME is not configured (invite links need it).');

const DEFAULT_SETTINGS = {
  ad_daily_limit: '10',
  ad_reward: '5',
  ad_min_seconds: '8',
  adsgram_block_id: '50476',
  adsbitvex_zone: '',
  adsbitvex_script: 'https://sdk.adsbitvex.com/functions/v1/ad-script?appid=000463',
  birr_per_coin: '0.05',
  usdt_per_coin: '0.0004',
  min_withdraw_coins: '2000',
  referral_required: '5',
  referral_ad_days: '2',
  spin_rewards: '1,2,3,5,8,10'
};

const SETTING_KEYS = Object.keys(DEFAULT_SETTINGS);

/* =========================================================
   POSTGRES
   ========================================================= */

const pool = new Pool({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false } });

class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

let databaseReady = null;

function initDatabase() {
  if (databaseReady) return databaseReady;

  databaseReady = (async () => {
    const q = (sql) => pool.query(sql);

    await q(`CREATE TABLE IF NOT EXISTS fraud_users (
      telegram_id BIGINT PRIMARY KEY,
      username TEXT NOT NULL DEFAULT '',
      first_name TEXT NOT NULL DEFAULT '',
      ip_hash TEXT NOT NULL DEFAULT '',
      device_hash TEXT NOT NULL DEFAULT '',
      vpn_detected BOOLEAN NOT NULL DEFAULT FALSE,
      proxy_detected BOOLEAN NOT NULL DEFAULT FALSE,
      risk_score INTEGER NOT NULL DEFAULT 0,
      status TEXT NOT NULL DEFAULT 'pending',
      ban_reason TEXT NOT NULL DEFAULT '',
      verification_message_sent BOOLEAN NOT NULL DEFAULT FALSE,
      ban_message_sent BOOLEAN NOT NULL DEFAULT FALSE,
      admin_verified BOOLEAN NOT NULL DEFAULT FALSE,
      first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      request_count INTEGER NOT NULL DEFAULT 0
    )`);
    await q(`ALTER TABLE fraud_users ADD COLUMN IF NOT EXISTS verification_message_sent BOOLEAN NOT NULL DEFAULT FALSE`);
    await q(`ALTER TABLE fraud_users ADD COLUMN IF NOT EXISTS ban_message_sent BOOLEAN NOT NULL DEFAULT FALSE`);
    await q(`ALTER TABLE fraud_users ADD COLUMN IF NOT EXISTS admin_verified BOOLEAN NOT NULL DEFAULT FALSE`);

    await q(`CREATE TABLE IF NOT EXISTS required_channels (
      id SERIAL PRIMARY KEY,
      chat_id TEXT NOT NULL,
      title TEXT NOT NULL DEFAULT '',
      invite_link TEXT NOT NULL DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )`);

    await q(`CREATE TABLE IF NOT EXISTS users (
      telegram_id BIGINT PRIMARY KEY,
      first_name TEXT NOT NULL DEFAULT '',
      username TEXT NOT NULL DEFAULT '',
      coins BIGINT NOT NULL DEFAULT 0,
      total_earned BIGINT NOT NULL DEFAULT 0,
      referred_by BIGINT,
      streak INTEGER NOT NULL DEFAULT 0,
      best_streak INTEGER NOT NULL DEFAULT 0,
      last_active TEXT NOT NULL DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )`);
    await q(`CREATE INDEX IF NOT EXISTS users_referred_idx ON users (referred_by)`);
    await q(`CREATE INDEX IF NOT EXISTS users_earned_idx ON users (total_earned DESC)`);

    await q(`CREATE TABLE IF NOT EXISTS ledger (
      id BIGSERIAL PRIMARY KEY,
      telegram_id BIGINT NOT NULL,
      amount BIGINT NOT NULL,
      kind TEXT NOT NULL,
      ref TEXT NOT NULL DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )`);

    await q(`CREATE TABLE IF NOT EXISTS ad_views (
      id BIGSERIAL PRIMARY KEY,
      telegram_id BIGINT NOT NULL,
      day TEXT NOT NULL,
      provider TEXT NOT NULL DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )`);
    await q(`CREATE INDEX IF NOT EXISTS ad_views_user_day_idx ON ad_views (telegram_id, day)`);

    await q(`CREATE TABLE IF NOT EXISTS ad_sessions (
      token TEXT PRIMARY KEY,
      telegram_id BIGINT NOT NULL,
      provider TEXT NOT NULL DEFAULT '',
      started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      used BOOLEAN NOT NULL DEFAULT FALSE
    )`);

    await q(`CREATE TABLE IF NOT EXISTS tasks (
      id SERIAL PRIMARY KEY,
      kind TEXT NOT NULL,
      title TEXT NOT NULL,
      description TEXT NOT NULL DEFAULT '',
      link TEXT NOT NULL DEFAULT '',
      chat_id TEXT NOT NULL DEFAULT '',
      provider TEXT NOT NULL DEFAULT '',
      reward INTEGER NOT NULL,
      max_users INTEGER NOT NULL,
      done_count INTEGER NOT NULL DEFAULT 0,
      active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )`);

    await q(`CREATE TABLE IF NOT EXISTS task_completions (
      id SERIAL PRIMARY KEY,
      task_id INTEGER NOT NULL,
      telegram_id BIGINT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      proof_file_id TEXT NOT NULL DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE (task_id, telegram_id)
    )`);

    await q(`CREATE TABLE IF NOT EXISTS proof_state (
      telegram_id BIGINT PRIMARY KEY,
      task_id INTEGER NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )`);

    await q(`CREATE TABLE IF NOT EXISTS promo_codes (
      code TEXT PRIMARY KEY,
      reward INTEGER NOT NULL,
      max_uses INTEGER NOT NULL,
      used_count INTEGER NOT NULL DEFAULT 0,
      active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )`);

    await q(`CREATE TABLE IF NOT EXISTS promo_redemptions (
      code TEXT NOT NULL,
      telegram_id BIGINT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY (code, telegram_id)
    )`);

    await q(`CREATE TABLE IF NOT EXISTS withdrawals (
      id SERIAL PRIMARY KEY,
      telegram_id BIGINT NOT NULL,
      method TEXT NOT NULL,
      address TEXT NOT NULL,
      coins BIGINT NOT NULL,
      amount_birr NUMERIC NOT NULL DEFAULT 0,
      amount_usdt NUMERIC NOT NULL DEFAULT 0,
      status TEXT NOT NULL DEFAULT 'pending',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      processed_at TIMESTAMPTZ
    )`);

    await q(`CREATE TABLE IF NOT EXISTS spins (
      telegram_id BIGINT NOT NULL,
      day TEXT NOT NULL,
      reward INTEGER NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY (telegram_id, day)
    )`);

    await q(`CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL DEFAULT ''
    )`);

    console.log('Database initialized.');
  })().catch((error) => {
    databaseReady = null;
    console.error('Database initialization error:', error);
    throw error;
  });

  return databaseReady;
}

async function withTx(fn) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function dayKey(date = new Date()) {
  return date.toLocaleDateString('en-CA', { timeZone: TZ });
}

/* =========================================================
   TELEGRAM API
   ========================================================= */

async function telegram(method, data = {}) {
  if (!BOT_TOKEN) throw new Error('BOT_TOKEN is missing.');

  const response = await fetch(`${TELEGRAM_API}/${method}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data)
  });

  const result = await response.json();
  if (!result.ok) throw new Error(`Telegram API error: ${JSON.stringify(result)}`);
  return result;
}

async function sendTelegramMessage(chatId, text, extra = {}) {
  try {
    await telegram('sendMessage', { chat_id: chatId, text, ...extra });
    return true;
  } catch (error) {
    console.error('Telegram sendMessage error:', error.message);
    return false;
  }
}

async function notifyAdmins(text, extra = {}) {
  await Promise.all(ADMIN_IDS.map((id) => sendTelegramMessage(id, text, extra)));
}

async function sendBanMessage(chatId, type) {
  const tail = 'Your account has been permanently banned from Adewa.';
  if (type === 'vpn') return sendTelegramMessage(chatId, `VPN/Proxy detected.\n\n${tail}`);
  if (type === 'multi') return sendTelegramMessage(chatId, `Multiple accounts detected.\n\n${tail}`);
  return sendTelegramMessage(chatId, tail);
}

function getBanType(banReason) {
  const r = String(banReason || '').toLowerCase();
  if (r.includes('vpn') || r.includes('proxy') || r.includes('tor')) return 'vpn';
  if (r.includes('multiple') || r.includes('multi account')) return 'multi';
  return 'other';
}

/* =========================================================
   INIT DATA VERIFICATION + ADMIN / USER GUARDS
   ========================================================= */

function verifyTelegramInitData(initData) {
  if (!initData) return { ok: false, reason: 'Missing Telegram initData' };
  if (!BOT_TOKEN) return { ok: false, reason: 'BOT_TOKEN is missing' };

  try {
    const params = new URLSearchParams(initData);
    const hash = params.get('hash');
    if (!hash) return { ok: false, reason: 'Missing hash' };
    params.delete('hash');

    const dataCheckString = [...params.entries()]
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([k, v]) => `${k}=${v}`)
      .join('\n');

    const secretKey = crypto.createHmac('sha256', 'WebAppData').update(BOT_TOKEN).digest();
    const calculated = crypto.createHmac('sha256', secretKey).update(dataCheckString).digest('hex');

    const a = Buffer.from(hash, 'hex');
    const b = Buffer.from(calculated, 'hex');
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
      return { ok: false, reason: 'Invalid Telegram signature' };
    }

    const authDate = Number(params.get('auth_date'));
    if (!authDate) return { ok: false, reason: 'Missing auth_date' };
    if (Math.floor(Date.now() / 1000) - authDate > 86400) {
      return { ok: false, reason: 'Telegram initData expired' };
    }

    const userString = params.get('user');
    if (!userString) return { ok: false, reason: 'Missing Telegram user' };

    const user = JSON.parse(userString);
    if (!user.id) return { ok: false, reason: 'Invalid Telegram user' };

    return { ok: true, user };
  } catch (error) {
    console.error('initData verification error:', error);
    return { ok: false, reason: 'Invalid initData' };
  }
}

const isAdmin = (id) => ADMIN_IDS.includes(Number(id));

function requireAdmin(req) {
  const v = verifyTelegramInitData(req.headers['x-init-data']);
  if (!v.ok) throw new HttpError(401, v.reason);
  if (!isAdmin(v.user.id)) throw new HttpError(403, 'Admin access required.');
  return v.user;
}

// Verified (non-banned) mini app user. Also makes sure the users row exists.
async function requireUser(req) {
  const v = verifyTelegramInitData(req.headers['x-init-data']);
  if (!v.ok) throw new HttpError(401, v.reason);

  const f = await pool.query('SELECT status FROM fraud_users WHERE telegram_id = $1', [v.user.id]);
  if (!f.rows.length || f.rows[0].status !== 'verified') throw new HttpError(403, 'Account is not verified.');

  await ensureUser(pool, v.user);
  return v.user;
}

const route = (fn) => async (req, res) => {
  try {
    await initDatabase();
    await fn(req, res);
  } catch (error) {
    if (error instanceof HttpError) return res.status(error.status).json({ ok: false, message: error.message });
    console.error('Route error:', error);
    return res.status(500).json({ ok: false, message: 'Server error' });
  }
};

/* =========================================================
   ECONOMY HELPERS
   ========================================================= */

async function getSettings() {
  const r = await pool.query('SELECT key, value FROM settings');
  const s = { ...DEFAULT_SETTINGS };
  r.rows.forEach((row) => { s[row.key] = row.value; });
  return s;
}

async function ensureUser(db, from, referrer = null) {
  let ref = null;
  if (referrer && Number(referrer) !== Number(from.id)) {
    const r = await db.query('SELECT 1 FROM users WHERE telegram_id = $1', [referrer]);
    if (r.rows.length) ref = referrer;
  }
  await db.query(
    `INSERT INTO users (telegram_id, first_name, username, referred_by)
     VALUES ($1, $2, $3, $4)
     ON CONFLICT (telegram_id) DO UPDATE SET
       first_name = EXCLUDED.first_name,
       username = EXCLUDED.username`,
    [from.id, from.first_name || '', from.username || '', ref]
  );
}

async function credit(db, id, amount, kind, ref = '') {
  await db.query(
    'UPDATE users SET coins = coins + $2, total_earned = total_earned + $2 WHERE telegram_id = $1',
    [id, amount]
  );
  await db.query('INSERT INTO ledger (telegram_id, amount, kind, ref) VALUES ($1,$2,$3,$4)', [id, amount, kind, ref]);
}

async function touchStreak(id) {
  const today = dayKey();
  const yesterday = dayKey(new Date(Date.now() - 86400000));
  const r = await pool.query('SELECT streak, best_streak, last_active FROM users WHERE telegram_id = $1', [id]);
  if (!r.rows.length) return;
  const u = r.rows[0];
  if (u.last_active === today) return;
  const streak = u.last_active === yesterday ? u.streak + 1 : 1;
  await pool.query(
    'UPDATE users SET streak = $2, best_streak = GREATEST(best_streak, $2), last_active = $3 WHERE telegram_id = $1',
    [id, streak, today]
  );
}

async function referralStats(id, needDays) {
  const r = await pool.query(
    `SELECT COUNT(*)::int AS total,
            COUNT(*) FILTER (WHERE d.days >= $2)::int AS active
     FROM users u
     LEFT JOIN LATERAL (
       SELECT COUNT(DISTINCT day) AS days FROM ad_views a WHERE a.telegram_id = u.telegram_id
     ) d ON TRUE
     WHERE u.referred_by = $1`,
    [id, needDays]
  );
  return r.rows[0];
}

const displayName = (row) => String(row.first_name || row.username || 'User').slice(0, 16);

function taskLink(t) {
  if (t.link) return t.link;
  if (t.chat_id && t.chat_id.startsWith('@')) return `https://t.me/${t.chat_id.slice(1)}`;
  return '';
}

/* =========================================================
   REQUIRED CHANNELS (start gate)
   ========================================================= */

async function getRequiredChannels() {
  const r = await pool.query('SELECT * FROM required_channels ORDER BY id ASC');
  return r.rows;
}

function buildChannelKeyboard(channels) {
  const rows = channels.map((c) => [{
    text: c.title || c.chat_id,
    url: c.invite_link || `https://t.me/${String(c.chat_id).replace('@', '')}`
  }]);
  rows.push([{ text: 'Joined', callback_data: 'check_joined' }]);
  return { inline_keyboard: rows };
}

async function isChatMember(chatId, userId) {
  try {
    const r = await telegram('getChatMember', { chat_id: chatId, user_id: userId });
    return ['member', 'administrator', 'creator'].includes(r.result?.status);
  } catch (error) {
    console.error('getChatMember error:', chatId, error.message);
    return false;
  }
}

async function checkAllChannelsJoined(channels, userId) {
  const missing = [];
  for (const c of channels) {
    if (!(await isChatMember(c.chat_id, userId))) missing.push(c.title || c.chat_id);
  }
  return { allJoined: missing.length === 0, missing };
}

async function sendChannelGate(chatId, firstName) {
  const channels = await getRequiredChannels();
  const openButton = { inline_keyboard: [[{ text: 'Open Adewa', web_app: { url: MINI_APP_URL } }]] };

  if (!channels.length) {
    return sendTelegramMessage(chatId, `Hello ${firstName}\n\nWelcome to Adewa.`, { reply_markup: openButton });
  }

  return sendTelegramMessage(
    chatId,
    `ውድ ${firstName} እንኳን በሰላም መጡ!\n\nእባክዎ ከታች ያሉትን ቻናሎች ሁሉ ይቀላቀሉ፣ ከዚያ "Joined" የሚለውን ይጫኑ።`,
    { reply_markup: buildChannelKeyboard(channels) }
  );
}

/* =========================================================
   BAN / UNBAN
   ========================================================= */

async function banUserById(telegramId, reason) {
  const r = await pool.query(
    `INSERT INTO fraud_users (telegram_id, status, ban_reason, admin_verified, last_seen, request_count)
     VALUES ($1, 'banned', $2, FALSE, NOW(), 1)
     ON CONFLICT (telegram_id) DO UPDATE SET
       status = 'banned', ban_reason = EXCLUDED.ban_reason, admin_verified = FALSE, last_seen = NOW()
     RETURNING *`,
    [telegramId, reason || 'Admin ban']
  );
  await sendBanMessage(telegramId, getBanType(reason || 'Admin ban'));
  return r.rows[0];
}

async function unbanUserById(telegramId) {
  const r = await pool.query(
    `UPDATE fraud_users SET
       status = 'verified', ban_reason = '', vpn_detected = FALSE, proxy_detected = FALSE,
       risk_score = 0, ban_message_sent = FALSE, admin_verified = TRUE, last_seen = NOW()
     WHERE telegram_id = $1 RETURNING *`,
    [telegramId]
  );
  if (r.rows.length) await sendTelegramMessage(telegramId, 'Your account has been unbanned. Send /start to continue.');
  return r.rows[0] || null;
}

/* =========================================================
   FRAUD DETECTION
   ========================================================= */

const sha256 = (v) => crypto.createHash('sha256').update(String(v || '')).digest('hex');

function getClientIP(req) {
  const f = req.headers['x-forwarded-for'];
  if (f) return String(f).split(',')[0].trim();
  return req.headers['x-real-ip'] || req.socket?.remoteAddress || '';
}

async function detectVPNProxy(ip) {
  const result = { checked: false, vpn: false, proxy: false, tor: false, hosting: false, detected: false };
  if (!ip) return result;

  const clean = String(ip).replace(/^::ffff:/, '').trim();
  if (clean === '127.0.0.1' || clean === '::1' || clean.startsWith('10.') || clean.startsWith('192.168.') || clean.startsWith('172.16.')) {
    return result;
  }

  try {
    const response = await fetch(`https://ipwho.is/${encodeURIComponent(clean)}`, {
      headers: { Accept: 'application/json' },
      signal: AbortSignal.timeout(5000)
    });
    if (!response.ok) return result;

    const data = await response.json();
    if (!data || data.success === false) return result;

    const sec = data.security || {};
    result.checked = true;
    result.vpn = sec.vpn === true;
    result.proxy = sec.proxy === true;
    result.tor = sec.tor === true;
    result.hosting = sec.hosting === true;
    result.detected = result.vpn || result.proxy || result.tor;
    return result;
  } catch (error) {
    console.error('VPN detection error:', error.message);
    return result;
  }
}

async function detectMultiAccount(telegramId, ipHash, deviceHash) {
  if (!deviceHash && !ipHash) return { detected: false, reason: '' };

  if (deviceHash) {
    const d = await pool.query(
      'SELECT telegram_id FROM fraud_users WHERE device_hash = $1 AND telegram_id <> $2 LIMIT 1',
      [deviceHash, telegramId]
    );
    if (d.rows.length) return { detected: true, reason: 'Multiple Telegram accounts detected on the same device.' };
  }

  if (ipHash) {
    const i = await pool.query(
      `SELECT telegram_id, device_hash FROM fraud_users
       WHERE ip_hash = $1 AND telegram_id <> $2 AND status = 'verified' LIMIT 1`,
      [ipHash, telegramId]
    );
    if (i.rows.length) {
      const old = i.rows[0].device_hash;
      if (old && deviceHash && old !== deviceHash) {
        return { detected: true, reason: 'Multiple Telegram accounts detected from the same IP address.' };
      }
    }
  }

  return { detected: false, reason: '' };
}

async function recordBan(id, username, firstName, ipHash, deviceHash, vpn, proxy, reason) {
  await pool.query(
    `INSERT INTO fraud_users
       (telegram_id, username, first_name, ip_hash, device_hash, vpn_detected, proxy_detected,
        risk_score, status, ban_reason, last_seen, request_count)
     VALUES ($1,$2,$3,$4,$5,$6,$7,100,'banned',$8,NOW(),1)
     ON CONFLICT (telegram_id) DO UPDATE SET
       username = EXCLUDED.username, first_name = EXCLUDED.first_name,
       ip_hash = EXCLUDED.ip_hash, device_hash = EXCLUDED.device_hash,
       vpn_detected = EXCLUDED.vpn_detected, proxy_detected = EXCLUDED.proxy_detected,
       risk_score = 100, status = 'banned', ban_reason = EXCLUDED.ban_reason,
       last_seen = NOW(), request_count = fraud_users.request_count + 1`,
    [id, username, firstName, ipHash, deviceHash, vpn, proxy, reason]
  );
}

/* =========================================================
   CORS
   ========================================================= */

app.use((req, res, next) => {
  if (req.headers.origin === FRONTEND_ORIGIN) res.setHeader('Access-Control-Allow-Origin', FRONTEND_ORIGIN);
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, x-init-data, x-device');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,DELETE,OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

/* =========================================================
   WEBHOOK SETUP
   ========================================================= */

let webhookPromise = null;

async function setupWebhook() {
  if (webhookPromise) return webhookPromise;
  webhookPromise = telegram('setWebhook', {
    url: WEBHOOK_URL,
    secret_token: WEBHOOK_SECRET,
    allowed_updates: ['message', 'callback_query'],
    drop_pending_updates: false
  }).catch((error) => {
    webhookPromise = null;
    console.error('setWebhook error:', error.message);
    throw error;
  });
  return webhookPromise;
}

app.get('/', async (req, res) => {
  try { await setupWebhook(); } catch (error) { console.error('Webhook setup error:', error.message); }
  res.json({ ok: true, app: 'Adewa', status: 'online' });
});

app.get('/api/webhook-status', async (req, res) => {
  try { res.json(await telegram('getWebhookInfo')); }
  catch (error) { res.status(500).json({ ok: false, error: error.message }); }
});

/* =========================================================
   TASK PROOF DECISIONS (shared by bot buttons + admin panel)
   ========================================================= */

async function decideCompletion(id, approve) {
  return withTx(async (c) => {
    const cr = (await c.query('SELECT * FROM task_completions WHERE id = $1 FOR UPDATE', [id])).rows[0];
    if (!cr || cr.status !== 'pending') return { ok: false, message: 'Already processed.' };

    const t = (await c.query('SELECT * FROM tasks WHERE id = $1 FOR UPDATE', [cr.task_id])).rows[0];

    if (!approve) {
      await c.query("UPDATE task_completions SET status = 'rejected' WHERE id = $1", [id]);
      return { ok: true, status: 'rejected', cr, t };
    }

    if (t.done_count >= t.max_users) {
      await c.query("UPDATE task_completions SET status = 'rejected' WHERE id = $1", [id]);
      return { ok: true, status: 'full', cr, t };
    }

    const next = t.done_count + 1;
    await c.query("UPDATE task_completions SET status = 'approved' WHERE id = $1", [id]);
    await c.query('UPDATE tasks SET done_count = $2, active = $3 WHERE id = $1', [t.id, next, next < t.max_users]);
    await credit(c, cr.telegram_id, t.reward, 'task', `task:${t.id}`);
    return { ok: true, status: 'approved', cr, t };
  });
}

async function notifyDecision(result) {
  if (!result.ok) return;
  const { status, cr, t } = result;
  if (status === 'approved') {
    await sendTelegramMessage(cr.telegram_id, `Your task "${t.title}" was approved. +${t.reward} coins added.`);
  } else if (status === 'rejected') {
    await sendTelegramMessage(cr.telegram_id, `Your task "${t.title}" was rejected.`);
  } else if (status === 'full') {
    await sendTelegramMessage(cr.telegram_id, `Task "${t.title}" reached its user limit before your proof was reviewed.`);
  }
}

/* =========================================================
   BOT: MESSAGE + CALLBACK HANDLERS
   ========================================================= */

async function startProof(chatId, from, taskId) {
  const f = (await pool.query('SELECT status, ban_reason FROM fraud_users WHERE telegram_id = $1', [from.id])).rows[0];

  if (f && f.status === 'banned') return sendBanMessage(chatId, getBanType(f.ban_reason));
  if (!f || f.status !== 'verified') return sendTelegramMessage(chatId, 'Please open the Adewa app first to verify your account.');

  const t = (await pool.query(
    "SELECT * FROM tasks WHERE id = $1 AND active = TRUE AND kind IN ('social','partner')", [taskId]
  )).rows[0];
  if (!t) return sendTelegramMessage(chatId, 'This task is no longer available.');

  const done = await pool.query('SELECT 1 FROM task_completions WHERE task_id = $1 AND telegram_id = $2', [taskId, from.id]);
  if (done.rows.length) return sendTelegramMessage(chatId, 'You have already submitted this task.');

  await pool.query(
    `INSERT INTO proof_state (telegram_id, task_id) VALUES ($1, $2)
     ON CONFLICT (telegram_id) DO UPDATE SET task_id = EXCLUDED.task_id, created_at = NOW()`,
    [from.id, taskId]
  );

  return sendTelegramMessage(chatId, `Task: ${t.title}\nReward: ${t.reward} coins\n\nSend your screenshot now as a photo. An admin will review it.`);
}

async function handleProof(message, fileId) {
  const from = message.from;
  const chatId = message.chat.id;

  const st = (await pool.query(
    "SELECT task_id FROM proof_state WHERE telegram_id = $1 AND created_at > NOW() - INTERVAL '60 minutes'", [from.id]
  )).rows[0];

  if (!st) return sendTelegramMessage(chatId, 'Open a task in the app and press "Submit proof" first.');

  const t = (await pool.query('SELECT * FROM tasks WHERE id = $1 AND active = TRUE', [st.task_id])).rows[0];
  if (!t) return sendTelegramMessage(chatId, 'This task is no longer available.');

  const ins = await pool.query(
    `INSERT INTO task_completions (task_id, telegram_id, status, proof_file_id)
     VALUES ($1, $2, 'pending', $3) ON CONFLICT (task_id, telegram_id) DO NOTHING RETURNING id`,
    [t.id, from.id, fileId]
  );
  await pool.query('DELETE FROM proof_state WHERE telegram_id = $1', [from.id]);

  if (!ins.rows.length) return sendTelegramMessage(chatId, 'You have already submitted this task.');

  const id = ins.rows[0].id;
  await sendTelegramMessage(chatId, 'Proof received. You will be notified after it is reviewed.');

  const caption =
    `Proof #${id}\nTask: ${t.title}\nUser: ${displayName(from)}${from.username ? ' @' + from.username : ''} [${from.id}]\nReward: ${t.reward} coins`;

  await Promise.all(ADMIN_IDS.map((adminId) =>
    telegram('sendPhoto', {
      chat_id: adminId,
      photo: fileId,
      caption,
      reply_markup: { inline_keyboard: [[
        { text: 'Approve', callback_data: `ap:${id}` },
        { text: 'Reject', callback_data: `rj:${id}` }
      ]] }
    }).catch(async () => {
      // Screenshot sent as a document instead of a photo.
      await telegram('sendDocument', { chat_id: adminId, document: fileId, caption }).catch(() => {});
    })
  ));
}

async function handleCallback(callback) {
  const chatId = callback.message?.chat?.id;
  const userId = callback.from?.id;
  const data = callback.data || '';
  const answer = (text, alert = false) =>
    telegram('answerCallbackQuery', { callback_query_id: callback.id, text, show_alert: alert }).catch(() => {});

  // ---- Admin approve / reject on a proof ----
  if (data.startsWith('ap:') || data.startsWith('rj:')) {
    if (!isAdmin(userId)) return answer('Not allowed.', true);

    const approve = data.startsWith('ap:');
    const result = await decideCompletion(Number(data.slice(3)), approve);
    if (!result.ok) return answer(result.message, true);

    await answer(approve ? 'Approved' : 'Rejected');
    await telegram('editMessageReplyMarkup', {
      chat_id: chatId, message_id: callback.message.message_id, reply_markup: { inline_keyboard: [] }
    }).catch(() => {});
    await sendTelegramMessage(chatId, `Proof #${data.slice(3)}: ${result.status}.`);
    await notifyDecision(result);
    return;
  }

  // ---- "Joined" button ----
  if (data === 'check_joined' && chatId && userId) {
    const b = (await pool.query('SELECT status, ban_reason FROM fraud_users WHERE telegram_id = $1 LIMIT 1', [userId])).rows[0];

    if (b && b.status === 'banned') {
      await answer('You are banned.', true);
      await sendBanMessage(chatId, getBanType(b.ban_reason));
      return;
    }

    const channels = await getRequiredChannels();
    const { allJoined, missing } = await checkAllChannelsJoined(channels, userId);

    if (!allJoined) return answer(`እባክዎ መጀመሪያ ሁሉንም ቻናሎች ይቀላቀሉ:\n${missing.join(', ')}`, true);

    await answer('Verified');
    await sendTelegramMessage(chatId, 'ሁሉንም ቻናሎች ተቀላቅለዋል። ወደ Adewa ይግቡ።', {
      reply_markup: { inline_keyboard: [[{ text: 'Open Adewa', web_app: { url: MINI_APP_URL } }]] }
    });
  }
}

async function handleMessage(message) {
  const chatId = message.chat?.id;
  const from = message.from;
  if (!chatId || !from) return;

  // Screenshot proof (photo or image document)
  const fileId = message.photo?.length
    ? message.photo[message.photo.length - 1].file_id
    : (message.document?.mime_type?.startsWith('image/') ? message.document.file_id : null);

  if (fileId) return handleProof(message, fileId);

  const text = typeof message.text === 'string' ? message.text.trim() : '';
  const command = text.split(' ')[0].split('@')[0];

  if (command === '/start') {
    const payload = text.split(' ')[1] || '';
    const referrer = payload.startsWith('ref_') ? Number(payload.slice(4)) || null : null;

    await ensureUser(pool, from, referrer);

    if (payload.startsWith('proof_')) return startProof(chatId, from, Number(payload.slice(6)));
    return sendChannelGate(chatId, from.first_name || 'there');
  }

  if (command === '/ban' || command === '/unban') {
    if (!isAdmin(from.id)) return;

    const target = Number(text.split(' ')[1]);
    if (!Number.isFinite(target)) return sendTelegramMessage(chatId, `Usage: ${command} <telegram_id>`);

    if (command === '/ban') {
      await banUserById(target, 'Admin ban');
      return sendTelegramMessage(chatId, `User ${target} has been banned.`);
    }

    const done = await unbanUserById(target);
    return sendTelegramMessage(chatId, done ? `User ${target} has been unbanned.` : `User ${target} was not found.`);
  }
}

app.post('/telegram/webhook', async (req, res) => {
  try {
    if (req.headers['x-telegram-bot-api-secret-token'] !== WEBHOOK_SECRET) {
      console.warn('Invalid webhook secret.');
      return res.sendStatus(403);
    }

    await initDatabase();
    const update = req.body || {};

    if (update.callback_query) await handleCallback(update.callback_query);
    else if (update.message) await handleMessage(update.message);

    return res.sendStatus(200);
  } catch (error) {
    console.error('Webhook error:', error);
    return res.sendStatus(200);
  }
});

/* =========================================================
   AUTH  (anti-fraud gate for the mini app)
   ========================================================= */

app.post('/api/auth', route(async (req, res) => {
  const v = verifyTelegramInitData(req.headers['x-init-data']);
  if (!v.ok) return res.status(401).json({ ok: false, status: 'invalid', message: v.reason });

  const user = v.user;
  const telegramId = Number(user.id);
  const username = user.username || '';
  const firstName = user.first_name || '';

  const deviceId = String(req.headers['x-device'] || '').trim();
  const ip = getClientIP(req);
  const ipHash = sha256(ip);
  const deviceHash = sha256(deviceId);

  const existing = (await pool.query('SELECT * FROM fraud_users WHERE telegram_id = $1 LIMIT 1', [telegramId])).rows[0];

  // Already banned
  if (existing && existing.status === 'banned') {
    await sendBanMessage(telegramId, getBanType(existing.ban_reason));
    return res.status(403).json({
      ok: false, status: 'banned', reason: existing.ban_reason,
      message: 'Your account has been permanently banned.'
    });
  }

  // Accounts an admin unbanned are trusted going forward.
  const trusted = !!existing && existing.admin_verified === true;

  // 1) Multi-account check FIRST (the bigger problem)
  const multi = trusted ? { detected: false } : await detectMultiAccount(telegramId, ipHash, deviceHash);
  if (multi.detected) {
    await recordBan(telegramId, username, firstName, ipHash, deviceHash, false, false, multi.reason);
    await sendBanMessage(telegramId, 'multi');
    return res.status(403).json({
      ok: false, status: 'banned', reason: multi.reason,
      message: 'Multiple accounts detected. Your account has been permanently banned.'
    });
  }

  // 2) VPN / proxy check
  const net = trusted ? { detected: false } : await detectVPNProxy(ip);
  if (net.detected) {
    const reason = net.vpn ? 'VPN detected' : net.proxy ? 'Proxy detected' : net.tor ? 'Tor detected' : 'Restricted network detected';
    await recordBan(telegramId, username, firstName, ipHash, deviceHash, net.vpn || net.tor, net.proxy, reason);
    await sendBanMessage(telegramId, 'vpn');
    return res.status(403).json({
      ok: false, status: 'banned', reason,
      message: 'VPN/Proxy detected. Your account has been permanently banned.'
    });
  }

  // Normal user
  await pool.query(
    `INSERT INTO fraud_users
       (telegram_id, username, first_name, ip_hash, device_hash, vpn_detected, proxy_detected,
        risk_score, status, ban_reason, last_seen, request_count)
     VALUES ($1,$2,$3,$4,$5,FALSE,FALSE,0,'verified','',NOW(),1)
     ON CONFLICT (telegram_id) DO UPDATE SET
       username = EXCLUDED.username, first_name = EXCLUDED.first_name,
       ip_hash = EXCLUDED.ip_hash, device_hash = EXCLUDED.device_hash,
       status = 'verified', last_seen = NOW(), request_count = fraud_users.request_count + 1`,
    [telegramId, username, firstName, ipHash, deviceHash]
  );

  await ensureUser(pool, user);

  const sent = (await pool.query('SELECT verification_message_sent FROM fraud_users WHERE telegram_id = $1', [telegramId])).rows[0];
  if (!sent?.verification_message_sent) {
    if (await sendTelegramMessage(telegramId, 'Your verification is successful.')) {
      await pool.query('UPDATE fraud_users SET verification_message_sent = TRUE WHERE telegram_id = $1', [telegramId]);
    }
  }

  return res.json({ ok: true, status: 'verified', admin: isAdmin(telegramId), message: 'Verified.' });
}));

/* =========================================================
   ME  (everything the home / profile screens need)
   ========================================================= */

app.get('/api/me', route(async (req, res) => {
  const u = await requireUser(req);
  await touchStreak(u.id);

  const s = await getSettings();
  const today = dayKey();

  const row = (await pool.query('SELECT * FROM users WHERE telegram_id = $1', [u.id])).rows[0];
  const watched = Number((await pool.query('SELECT COUNT(*) AS c FROM ad_views WHERE telegram_id = $1 AND day = $2', [u.id, today])).rows[0].c);
  const spun = (await pool.query('SELECT 1 FROM spins WHERE telegram_id = $1 AND day = $2', [u.id, today])).rows.length > 0;
  const refs = await referralStats(u.id, Number(s.referral_ad_days));

  res.json({
    ok: true,
    admin: isAdmin(u.id),
    bot_username: BOT_USERNAME,
    user: { id: u.id, first_name: row.first_name, username: row.username },
    coins: Number(row.coins),
    total_earned: Number(row.total_earned),
    streak: row.streak,
    best_streak: row.best_streak,
    rates: { birr_per_coin: Number(s.birr_per_coin), usdt_per_coin: Number(s.usdt_per_coin) },
    ads: { watched, limit: Number(s.ad_daily_limit), reward: Number(s.ad_reward) },
    spin: {
      available: !spun,
      rewards: String(s.spin_rewards).split(',').map(Number).filter((n) => n > 0)
    },
    referrals: {
      total: refs.total,
      active: refs.active,
      required: Number(s.referral_required),
      ad_days: Number(s.referral_ad_days)
    },
    withdraw: { min_coins: Number(s.min_withdraw_coins) }
  });
}));

/* =========================================================
   ADS
   ========================================================= */

app.post('/api/ads/start', route(async (req, res) => {
  const u = await requireUser(req);
  const s = await getSettings();

  const watched = Number((await pool.query('SELECT COUNT(*) AS c FROM ad_views WHERE telegram_id = $1 AND day = $2', [u.id, dayKey()])).rows[0].c);
  if (watched >= Number(s.ad_daily_limit)) throw new HttpError(429, 'Daily ad limit reached. Come back tomorrow.');

  // Alternate providers in turn.
  const order = watched % 2 === 0 ? ['adsgram', 'adsbitvex'] : ['adsbitvex', 'adsgram'];
  const token = crypto.randomBytes(16).toString('hex');

  await pool.query('INSERT INTO ad_sessions (token, telegram_id, provider) VALUES ($1,$2,$3)', [token, u.id, order[0]]);

  res.json({
    ok: true,
    token,
    provider: order[0],
    fallback: order[1],
    config: {
      adsgram_block_id: s.adsgram_block_id,
      adsbitvex_zone: s.adsbitvex_zone,
      adsbitvex_script: s.adsbitvex_script
    }
  });
}));

app.post('/api/ads/complete', route(async (req, res) => {
  const u = await requireUser(req);
  const s = await getSettings();
  const token = String(req.body?.token || '');
  const provider = ['adsgram', 'adsbitvex'].includes(req.body?.provider) ? req.body.provider : '';

  const reward = Number(s.ad_reward);
  const minSeconds = Number(s.ad_min_seconds);
  const today = dayKey();

  await withTx(async (c) => {
    const ses = (await c.query('SELECT * FROM ad_sessions WHERE token = $1 AND telegram_id = $2 FOR UPDATE', [token, u.id])).rows[0];
    if (!ses || ses.used) throw new HttpError(400, 'Invalid ad session.');

    const elapsed = (Date.now() - new Date(ses.started_at).getTime()) / 1000;
    if (elapsed < minSeconds) throw new HttpError(400, 'Ad was not completed.');

    const watched = Number((await c.query('SELECT COUNT(*) AS c FROM ad_views WHERE telegram_id = $1 AND day = $2', [u.id, today])).rows[0].c);
    if (watched >= Number(s.ad_daily_limit)) throw new HttpError(429, 'Daily ad limit reached.');

    await c.query('UPDATE ad_sessions SET used = TRUE WHERE token = $1', [token]);
    await c.query('INSERT INTO ad_views (telegram_id, day, provider) VALUES ($1,$2,$3)', [u.id, today, provider]);
    await credit(c, u.id, reward, 'ad', provider);
  });

  res.json({ ok: true, reward });
}));

/* =========================================================
   TASKS
   ========================================================= */

app.get('/api/tasks', route(async (req, res) => {
  const u = await requireUser(req);

  const r = await pool.query(
    `SELECT t.*, c.status AS my_status
     FROM tasks t
     LEFT JOIN task_completions c ON c.task_id = t.id AND c.telegram_id = $1
     WHERE t.active = TRUE AND (c.status IS NULL OR c.status = 'pending')
     ORDER BY t.id DESC`,
    [u.id]
  );

  res.json({
    ok: true,
    tasks: r.rows.map((t) => ({
      id: t.id, kind: t.kind, title: t.title, description: t.description,
      link: taskLink(t), provider: t.provider, reward: t.reward,
      remaining: Math.max(t.max_users - t.done_count, 0), my_status: t.my_status || ''
    }))
  });
}));

// Channel / group tasks: verified automatically through the Telegram API.
app.post('/api/tasks/:id/claim', route(async (req, res) => {
  const u = await requireUser(req);
  const id = Number(req.params.id);

  const t = (await pool.query("SELECT * FROM tasks WHERE id = $1 AND active = TRUE AND kind = 'channel'", [id])).rows[0];
  if (!t) throw new HttpError(404, 'Task is not available.');

  const done = await pool.query('SELECT 1 FROM task_completions WHERE task_id = $1 AND telegram_id = $2', [id, u.id]);
  if (done.rows.length) throw new HttpError(409, 'You already completed this task.');

  if (!(await isChatMember(t.chat_id, u.id))) throw new HttpError(422, 'Join the channel or group first, then verify again.');

  await withTx(async (c) => {
    const lock = (await c.query('SELECT * FROM tasks WHERE id = $1 FOR UPDATE', [id])).rows[0];
    if (!lock.active || lock.done_count >= lock.max_users) throw new HttpError(410, 'This task is already full.');

    const ins = await c.query(
      "INSERT INTO task_completions (task_id, telegram_id, status) VALUES ($1,$2,'approved') ON CONFLICT DO NOTHING RETURNING id",
      [id, u.id]
    );
    if (!ins.rows.length) throw new HttpError(409, 'You already completed this task.');

    const next = lock.done_count + 1;
    await c.query('UPDATE tasks SET done_count = $2, active = $3 WHERE id = $1', [id, next, next < lock.max_users]);
    await credit(c, u.id, lock.reward, 'task', `task:${id}`);
  });

  res.json({ ok: true, reward: t.reward });
}));

/* =========================================================
   PROMO / SPIN / LEADERBOARD / WINNERS
   ========================================================= */

app.post('/api/promo', route(async (req, res) => {
  const u = await requireUser(req);
  const code = String(req.body?.code || '').trim().toUpperCase();
  if (!code) throw new HttpError(400, 'Enter a promo code.');

  const reward = await withTx(async (c) => {
    const p = (await c.query('SELECT * FROM promo_codes WHERE code = $1 FOR UPDATE', [code])).rows[0];
    if (!p || !p.active) throw new HttpError(404, 'Invalid promo code.');
    if (p.used_count >= p.max_uses) throw new HttpError(410, 'This promo code is fully used.');

    const ins = await c.query('INSERT INTO promo_redemptions (code, telegram_id) VALUES ($1,$2) ON CONFLICT DO NOTHING RETURNING code', [code, u.id]);
    if (!ins.rows.length) throw new HttpError(409, 'You already used this promo code.');

    await c.query('UPDATE promo_codes SET used_count = used_count + 1 WHERE code = $1', [code]);
    await credit(c, u.id, p.reward, 'promo', code);
    return p.reward;
  });

  res.json({ ok: true, reward });
}));

app.post('/api/spin', route(async (req, res) => {
  const u = await requireUser(req);
  const s = await getSettings();
  const rewards = String(s.spin_rewards).split(',').map(Number).filter((n) => n > 0);
  if (!rewards.length) throw new HttpError(503, 'Spin is not available.');

  const reward = rewards[crypto.randomInt(rewards.length)];

  await withTx(async (c) => {
    const ins = await c.query('INSERT INTO spins (telegram_id, day, reward) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING RETURNING reward', [u.id, dayKey(), reward]);
    if (!ins.rows.length) throw new HttpError(409, 'You already spun today.');
    await credit(c, u.id, reward, 'spin');
  });

  res.json({ ok: true, reward });
}));

app.get('/api/winners', route(async (req, res) => {
  await requireUser(req);
  const r = await pool.query(
    `SELECT s.reward, s.created_at, u.first_name, u.username
     FROM spins s JOIN users u ON u.telegram_id = s.telegram_id
     ORDER BY s.created_at DESC LIMIT 12`
  );
  res.json({ ok: true, winners: r.rows.map((w) => ({ name: displayName(w), reward: w.reward, at: w.created_at })) });
}));

app.get('/api/leaderboard', route(async (req, res) => {
  const u = await requireUser(req);

  const mine = await pool.query(
    `SELECT first_name, username, total_earned FROM users
     WHERE referred_by = $1 ORDER BY total_earned DESC LIMIT 10`, [u.id]
  );
  const top = await pool.query(
    `SELECT telegram_id, first_name, username, total_earned FROM users
     WHERE total_earned > 0 ORDER BY total_earned DESC LIMIT 15`
  );

  res.json({
    ok: true,
    invitees: mine.rows.map((r) => ({ name: displayName(r), earned: Number(r.total_earned) })),
    top: top.rows.map((r) => ({ name: displayName(r), earned: Number(r.total_earned), me: Number(r.telegram_id) === Number(u.id) }))
  });
}));

/* =========================================================
   WITHDRAW
   ========================================================= */

app.get('/api/withdrawals', route(async (req, res) => {
  const u = await requireUser(req);
  const r = await pool.query(
    'SELECT id, method, address, coins, amount_birr, amount_usdt, status, created_at FROM withdrawals WHERE telegram_id = $1 ORDER BY id DESC LIMIT 20',
    [u.id]
  );
  res.json({ ok: true, withdrawals: r.rows });
}));

app.post('/api/withdraw', route(async (req, res) => {
  const u = await requireUser(req);
  const s = await getSettings();

  const method = String(req.body?.method || '').toLowerCase();
  const address = String(req.body?.address || '').trim();
  const coins = Math.floor(Number(req.body?.coins));

  if (!['bep20', 'ton'].includes(method)) throw new HttpError(400, 'Choose a payout method.');
  if (method === 'bep20' && !/^0x[a-fA-F0-9]{40}$/.test(address)) throw new HttpError(400, 'Invalid BEP20 address.');
  if (method === 'ton' && !/^([A-Za-z0-9_-]{48}|-?\d:[a-fA-F0-9]{64})$/.test(address)) throw new HttpError(400, 'Invalid TON address.');

  const min = Number(s.min_withdraw_coins);
  if (!Number.isFinite(coins) || coins < min) throw new HttpError(400, `Minimum withdrawal is ${min} coins.`);

  const refs = await referralStats(u.id, Number(s.referral_ad_days));
  if (refs.active < Number(s.referral_required)) {
    throw new HttpError(403, `You need ${s.referral_required} active invited friends (each must watch ads on ${s.referral_ad_days} different days).`);
  }

  const birr = coins * Number(s.birr_per_coin);
  const usdt = coins * Number(s.usdt_per_coin);

  const id = await withTx(async (c) => {
    const d = await c.query('UPDATE users SET coins = coins - $2 WHERE telegram_id = $1 AND coins >= $2 RETURNING coins', [u.id, coins]);
    if (!d.rows.length) throw new HttpError(400, 'Not enough balance.');

    await c.query('INSERT INTO ledger (telegram_id, amount, kind, ref) VALUES ($1,$2,$3,$4)', [u.id, -coins, 'withdraw', method]);
    const w = await c.query(
      'INSERT INTO withdrawals (telegram_id, method, address, coins, amount_birr, amount_usdt) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id',
      [u.id, method, address, coins, birr, usdt]
    );
    return w.rows[0].id;
  });

  await notifyAdmins(
    `Withdrawal request #${id}\nUser: ${displayName(u)}${u.username ? ' @' + u.username : ''} [${u.id}]\nMethod: ${method.toUpperCase()}\nAddress: ${address}\nCoins: ${coins}\nAmount: ${birr.toFixed(2)} ETB / ${usdt.toFixed(3)} USDT`
  );

  res.json({ ok: true, id });
}));

/* =========================================================
   ADMIN API
   ========================================================= */

app.get('/api/admin/stats', route(async (req, res) => {
  requireAdmin(req);
  const r = await pool.query(`
    SELECT
      (SELECT COUNT(*) FROM fraud_users) AS total,
      (SELECT COUNT(*) FROM fraud_users WHERE status = 'verified') AS verified,
      (SELECT COUNT(*) FROM fraud_users WHERE status = 'banned') AS banned,
      (SELECT COUNT(*) FROM task_completions WHERE status = 'pending' AND proof_file_id <> '') AS proofs,
      (SELECT COUNT(*) FROM withdrawals WHERE status = 'pending') AS withdrawals,
      (SELECT COALESCE(SUM(coins),0) FROM users) AS coins_in_wallets
  `);
  res.json({ ok: true, stats: r.rows[0] });
}));

app.get('/api/admin/settings', route(async (req, res) => {
  requireAdmin(req);
  res.json({ ok: true, settings: await getSettings() });
}));

app.post('/api/admin/settings', route(async (req, res) => {
  requireAdmin(req);
  const body = req.body || {};
  for (const key of SETTING_KEYS) {
    if (body[key] === undefined) continue;
    await pool.query(
      'INSERT INTO settings (key, value) VALUES ($1,$2) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value',
      [key, String(body[key]).trim()]
    );
  }
  res.json({ ok: true });
}));

// ---- users ----
app.get('/api/admin/user/:id', route(async (req, res) => {
  requireAdmin(req);
  const id = Number(req.params.id);
  if (!Number.isFinite(id)) throw new HttpError(400, 'Invalid user ID');
  const r = await pool.query(
    `SELECT f.telegram_id, f.username, f.first_name, f.status, f.ban_reason, u.coins, u.total_earned, u.streak
     FROM fraud_users f LEFT JOIN users u ON u.telegram_id = f.telegram_id WHERE f.telegram_id = $1`, [id]
  );
  res.json({ ok: true, user: r.rows[0] || null });
}));

app.post('/api/admin/ban/:id', route(async (req, res) => {
  requireAdmin(req);
  await banUserById(Number(req.params.id), req.body?.reason || 'Admin ban');
  res.json({ ok: true, message: 'User permanently banned.' });
}));

app.post('/api/admin/unban/:id', route(async (req, res) => {
  requireAdmin(req);
  await unbanUserById(Number(req.params.id));
  res.json({ ok: true, message: 'User unbanned.' });
}));

// ---- required channels ----
app.get('/api/admin/channels', route(async (req, res) => {
  requireAdmin(req);
  res.json({ ok: true, channels: await getRequiredChannels() });
}));

app.post('/api/admin/channels', route(async (req, res) => {
  requireAdmin(req);
  const { chat_id, title, invite_link } = req.body || {};
  if (!chat_id) throw new HttpError(400, 'chat_id is required.');
  const r = await pool.query(
    'INSERT INTO required_channels (chat_id, title, invite_link) VALUES ($1,$2,$3) RETURNING *',
    [String(chat_id).trim(), title || '', invite_link || '']
  );
  res.json({ ok: true, channel: r.rows[0] });
}));

app.delete('/api/admin/channels/:id', route(async (req, res) => {
  requireAdmin(req);
  await pool.query('DELETE FROM required_channels WHERE id = $1', [Number(req.params.id)]);
  res.json({ ok: true });
}));

// ---- tasks ----
app.get('/api/admin/tasks', route(async (req, res) => {
  requireAdmin(req);
  const r = await pool.query('SELECT * FROM tasks ORDER BY id DESC LIMIT 100');
  res.json({ ok: true, tasks: r.rows });
}));

app.post('/api/admin/tasks', route(async (req, res) => {
  requireAdmin(req);
  const b = req.body || {};
  const kind = String(b.kind || '');
  const title = String(b.title || '').trim();
  const reward = Math.floor(Number(b.reward));
  const maxUsers = Math.floor(Number(b.max_users));

  if (!['channel', 'social', 'partner'].includes(kind)) throw new HttpError(400, 'Invalid task type.');
  if (!title) throw new HttpError(400, 'Title is required.');
  if (!(reward > 0) || !(maxUsers > 0)) throw new HttpError(400, 'Reward and user limit must be positive numbers.');

  let chatId = String(b.chat_id || '').trim();
  const link = String(b.link || '').trim();

  if (kind === 'channel') {
    if (!chatId) throw new HttpError(400, 'Channel or group username is required.');
    if (!chatId.startsWith('@') && !chatId.startsWith('-')) chatId = '@' + chatId;
    if (chatId.startsWith('-') && !link) throw new HttpError(400, 'An invite link is required for private chats.');
  } else if (!link) {
    throw new HttpError(400, 'A task link is required.');
  }

  const r = await pool.query(
    `INSERT INTO tasks (kind, title, description, link, chat_id, provider, reward, max_users)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
    [kind, title, String(b.description || '').trim(), link, chatId, String(b.provider || '').trim(), reward, maxUsers]
  );

  res.json({ ok: true, task: r.rows[0] });
}));

app.delete('/api/admin/tasks/:id', route(async (req, res) => {
  requireAdmin(req);
  await pool.query('UPDATE tasks SET active = FALSE WHERE id = $1', [Number(req.params.id)]);
  res.json({ ok: true });
}));

// ---- proofs ----
app.get('/api/admin/proofs', route(async (req, res) => {
  requireAdmin(req);
  const r = await pool.query(
    `SELECT c.id, c.task_id, c.telegram_id, c.created_at, t.title, t.reward, u.first_name, u.username
     FROM task_completions c
     JOIN tasks t ON t.id = c.task_id
     LEFT JOIN users u ON u.telegram_id = c.telegram_id
     WHERE c.status = 'pending' AND c.proof_file_id <> ''
     ORDER BY c.id ASC LIMIT 50`
  );
  res.json({ ok: true, proofs: r.rows });
}));

app.get('/api/admin/proofs/:id/image', route(async (req, res) => {
  requireAdmin(req);
  const r = await pool.query('SELECT proof_file_id FROM task_completions WHERE id = $1', [Number(req.params.id)]);
  if (!r.rows.length) throw new HttpError(404, 'Not found');

  const file = await telegram('getFile', { file_id: r.rows[0].proof_file_id });
  const image = await fetch(`${TELEGRAM_FILE_API}/${file.result.file_path}`);

  res.setHeader('Content-Type', image.headers.get('content-type') || 'image/jpeg');
  res.setHeader('Cache-Control', 'no-store');
  res.send(Buffer.from(await image.arrayBuffer()));
}));

async function proofDecision(req, res, approve) {
  requireAdmin(req);
  const result = await decideCompletion(Number(req.params.id), approve);
  if (!result.ok) throw new HttpError(409, result.message);
  await notifyDecision(result);
  res.json({ ok: true, status: result.status });
}

app.post('/api/admin/proofs/:id/approve', route((req, res) => proofDecision(req, res, true)));
app.post('/api/admin/proofs/:id/reject', route((req, res) => proofDecision(req, res, false)));

// ---- promo codes ----
app.get('/api/admin/promos', route(async (req, res) => {
  requireAdmin(req);
  const r = await pool.query('SELECT * FROM promo_codes ORDER BY created_at DESC LIMIT 100');
  res.json({ ok: true, promos: r.rows });
}));

app.post('/api/admin/promos', route(async (req, res) => {
  requireAdmin(req);
  const code = String(req.body?.code || '').trim().toUpperCase().replace(/[^A-Z0-9_-]/g, '');
  const reward = Math.floor(Number(req.body?.reward));
  const maxUses = Math.floor(Number(req.body?.max_uses));

  if (!code) throw new HttpError(400, 'Code is required.');
  if (!(reward > 0) || !(maxUses > 0)) throw new HttpError(400, 'Reward and max uses must be positive numbers.');

  const r = await pool.query(
    'INSERT INTO promo_codes (code, reward, max_uses) VALUES ($1,$2,$3) ON CONFLICT (code) DO NOTHING RETURNING *',
    [code, reward, maxUses]
  );
  if (!r.rows.length) throw new HttpError(409, 'That code already exists.');
  res.json({ ok: true, promo: r.rows[0] });
}));

app.delete('/api/admin/promos/:code', route(async (req, res) => {
  requireAdmin(req);
  await pool.query('UPDATE promo_codes SET active = FALSE WHERE code = $1', [String(req.params.code).toUpperCase()]);
  res.json({ ok: true });
}));

// ---- withdrawals ----
app.get('/api/admin/withdrawals', route(async (req, res) => {
  requireAdmin(req);
  const status = req.query.status === 'all' ? null : 'pending';
  const r = await pool.query(
    `SELECT w.*, u.first_name, u.username FROM withdrawals w
     LEFT JOIN users u ON u.telegram_id = w.telegram_id
     ${status ? "WHERE w.status = 'pending'" : ''}
     ORDER BY w.id DESC LIMIT 50`
  );
  res.json({ ok: true, withdrawals: r.rows });
}));

app.post('/api/admin/withdrawals/:id/paid', route(async (req, res) => {
  requireAdmin(req);
  const r = await pool.query(
    "UPDATE withdrawals SET status = 'paid', processed_at = NOW() WHERE id = $1 AND status = 'pending' RETURNING *",
    [Number(req.params.id)]
  );
  if (!r.rows.length) throw new HttpError(409, 'Already processed.');
  await sendTelegramMessage(r.rows[0].telegram_id, `Your withdrawal #${r.rows[0].id} has been paid.`);
  res.json({ ok: true });
}));

app.post('/api/admin/withdrawals/:id/reject', route(async (req, res) => {
  requireAdmin(req);
  const w = await withTx(async (c) => {
    const r = await c.query(
      "UPDATE withdrawals SET status = 'rejected', processed_at = NOW() WHERE id = $1 AND status = 'pending' RETURNING *",
      [Number(req.params.id)]
    );
    if (!r.rows.length) throw new HttpError(409, 'Already processed.');
    // Refund the coins (not counted as new earnings).
    await c.query('UPDATE users SET coins = coins + $2 WHERE telegram_id = $1', [r.rows[0].telegram_id, r.rows[0].coins]);
    await c.query('INSERT INTO ledger (telegram_id, amount, kind, ref) VALUES ($1,$2,$3,$4)', [r.rows[0].telegram_id, r.rows[0].coins, 'refund', `withdrawal:${r.rows[0].id}`]);
    return r.rows[0];
  });
  await sendTelegramMessage(w.telegram_id, `Your withdrawal #${w.id} was rejected and ${w.coins} coins were returned to your balance.`);
  res.json({ ok: true });
}));

// ---- broadcast ----
app.post('/api/admin/broadcast', route(async (req, res) => {
  requireAdmin(req);
  const text = String(req.body?.text || '').trim();
  if (!text) throw new HttpError(400, 'Message is empty.');

  const r = await pool.query(
    `SELECT u.telegram_id FROM users u
     JOIN fraud_users f ON f.telegram_id = u.telegram_id
     WHERE f.status = 'verified' LIMIT 3000`
  );

  let sent = 0;
  const ids = r.rows.map((x) => x.telegram_id);

  // Telegram allows ~30 messages per second.
  for (let i = 0; i < ids.length; i += 25) {
    const batch = ids.slice(i, i + 25);
    const results = await Promise.all(batch.map((id) => sendTelegramMessage(id, text)));
    sent += results.filter(Boolean).length;
    if (i + 25 < ids.length) await sleep(1050);
  }

  res.json({ ok: true, sent, total: ids.length });
}));

/* =========================================================
   LOCAL SERVER + VERCEL
   ========================================================= */

if (require.main === module) {
  initDatabase()
    .then(() => setupWebhook())
    .then(() => app.listen(PORT, () => console.log(`Adewa server running on port ${PORT}`)))
    .catch((error) => { console.error('Startup error:', error); process.exit(1); });
}

if (process.env.VERCEL || process.env.VERCEL_ENV) {
  setupWebhook().catch(() => {});
}

module.exports = app;
