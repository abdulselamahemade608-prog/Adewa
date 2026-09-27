'use strict';

const express = require('express');
const crypto = require('crypto');
const { Pool } = require('pg');

const app = express();

app.use(express.json({ limit: '2mb' }));

// =========================================================
// CONFIG
// =========================================================

const PORT = process.env.PORT || 3000;

const BOT_TOKEN = process.env.BOT_TOKEN;
const DATABASE_URL = process.env.DATABASE_URL;

const WEBHOOK_SECRET =
  process.env.WEBHOOK_SECRET || 'adewa_webhook_secret';

const MINI_APP_URL_BASE =
  'https://abdulselamahemade608-prog.github.io/Adewa-frontend/';

// Cache-buster: changes on every cold start / deploy so Telegram's
// in-app WebView is forced to fetch the latest file instead of
// serving a stale cached copy.
const MINI_APP_URL =
  `${MINI_APP_URL_BASE}?v=${Date.now()}`;

const WEBHOOK_URL =
  'https://adewa.vercel.app/telegram/webhook';

const TELEGRAM_API =
  `https://api.telegram.org/bot${BOT_TOKEN}`;

// Comma separated Telegram user IDs, e.g. "111111,222222"
const ADMIN_IDS =
  String(process.env.ADMIN_IDS || '')
    .split(',')
    .map((id) => id.trim())
    .filter(Boolean)
    .map(Number);


// =========================================================
// BASIC CHECK
// =========================================================

if (!BOT_TOKEN) {
  console.warn('WARNING: BOT_TOKEN is not configured.');
}

if (!DATABASE_URL) {
  console.warn('WARNING: DATABASE_URL is not configured.');
}

if (ADMIN_IDS.length === 0) {
  console.warn('WARNING: ADMIN_IDS is not configured — no one will have admin access.');
}


// =========================================================
// POSTGRES
// =========================================================

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});


// =========================================================
// DATABASE INITIALIZATION
// =========================================================

let databaseReady = null;

function initDatabase() {

  if (databaseReady) {
    return databaseReady;
  }

  databaseReady = (async () => {

    await pool.query(`
      CREATE TABLE IF NOT EXISTS fraud_users (
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

        first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),

        request_count INTEGER NOT NULL DEFAULT 0
      )
    `);

    await pool.query(`
      ALTER TABLE fraud_users
      ADD COLUMN IF NOT EXISTS verification_message_sent
      BOOLEAN NOT NULL DEFAULT FALSE
    `);

    await pool.query(`
      ALTER TABLE fraud_users
      ADD COLUMN IF NOT EXISTS ban_message_sent
      BOOLEAN NOT NULL DEFAULT FALSE
    `);

    await pool.query(`
      ALTER TABLE fraud_users
      ADD COLUMN IF NOT EXISTS admin_verified
      BOOLEAN NOT NULL DEFAULT FALSE
    `);

    // -----------------------------------------------------
    // Required channels (admin-managed, not hardcoded)
    // -----------------------------------------------------

    await pool.query(`
      CREATE TABLE IF NOT EXISTS required_channels (
        id SERIAL PRIMARY KEY,

        chat_id TEXT NOT NULL,
        title TEXT NOT NULL DEFAULT '',
        invite_link TEXT NOT NULL DEFAULT '',

        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    // -----------------------------------------------------
    // ECONOMY: extra columns on fraud_users (acts as the
    // main "users" table — created at /api/auth time).
    // -----------------------------------------------------

    await pool.query(`
      ALTER TABLE fraud_users
      ADD COLUMN IF NOT EXISTS coins_ads INTEGER NOT NULL DEFAULT 0,
      ADD COLUMN IF NOT EXISTS coins_task INTEGER NOT NULL DEFAULT 0,
      ADD COLUMN IF NOT EXISTS coins_invite INTEGER NOT NULL DEFAULT 0,
      ADD COLUMN IF NOT EXISTS referred_by BIGINT,
      ADD COLUMN IF NOT EXISTS streak_count INTEGER NOT NULL DEFAULT 0,
      ADD COLUMN IF NOT EXISTS last_checkin DATE,
      ADD COLUMN IF NOT EXISTS bep20_address TEXT NOT NULL DEFAULT '',
      ADD COLUMN IF NOT EXISTS ton_address TEXT NOT NULL DEFAULT '',
      ADD COLUMN IF NOT EXISTS referral_rewarded BOOLEAN NOT NULL DEFAULT FALSE
    `);

    // -----------------------------------------------------
    // APP SETTINGS (key/value, admin editable)
    // -----------------------------------------------------

    await pool.query(`
      CREATE TABLE IF NOT EXISTS app_settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL DEFAULT ''
      )
    `);

    // -----------------------------------------------------
    // AD VIEWS (one row per user per day, counts views)
    // -----------------------------------------------------

    await pool.query(`
      CREATE TABLE IF NOT EXISTS ad_views (
        telegram_id BIGINT NOT NULL,
        view_date DATE NOT NULL DEFAULT CURRENT_DATE,
        count INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (telegram_id, view_date)
      )
    `);

    // -----------------------------------------------------
    // TASKS (admin-created: telegram join or social-media)
    // -----------------------------------------------------

    await pool.query(`
      CREATE TABLE IF NOT EXISTS tasks (
        id SERIAL PRIMARY KEY,
        type TEXT NOT NULL,              -- 'telegram' | 'social'
        title TEXT NOT NULL DEFAULT '',
        description TEXT NOT NULL DEFAULT '',
        target TEXT NOT NULL DEFAULT '', -- channel username OR link
        reward_coins INTEGER NOT NULL DEFAULT 0,
        user_limit INTEGER NOT NULL DEFAULT 0, -- 0 = unlimited
        completed_count INTEGER NOT NULL DEFAULT 0,
        active BOOLEAN NOT NULL DEFAULT TRUE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    // -----------------------------------------------------
    // TASK COMPLETIONS (per user, pending for social tasks)
    // -----------------------------------------------------

    await pool.query(`
      CREATE TABLE IF NOT EXISTS task_completions (
        id SERIAL PRIMARY KEY,
        task_id INTEGER NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
        telegram_id BIGINT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending', -- pending | approved | rejected
        proof_note TEXT NOT NULL DEFAULT '',
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        decided_at TIMESTAMPTZ,
        UNIQUE (task_id, telegram_id)
      )
    `);

    // -----------------------------------------------------
    // PROMO CODES
    // -----------------------------------------------------

    await pool.query(`
      CREATE TABLE IF NOT EXISTS promo_codes (
        code TEXT PRIMARY KEY,
        reward_coins INTEGER NOT NULL DEFAULT 0,
        max_uses INTEGER NOT NULL DEFAULT 1,
        used_count INTEGER NOT NULL DEFAULT 0,
        active BOOLEAN NOT NULL DEFAULT TRUE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS promo_redemptions (
        code TEXT NOT NULL,
        telegram_id BIGINT NOT NULL,
        redeemed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        PRIMARY KEY (code, telegram_id)
      )
    `);

    // -----------------------------------------------------
    // WITHDRAWALS
    // -----------------------------------------------------

    await pool.query(`
      CREATE TABLE IF NOT EXISTS withdrawals (
        id SERIAL PRIMARY KEY,
        telegram_id BIGINT NOT NULL,
        method TEXT NOT NULL,       -- 'BEP20' | 'TON'
        address TEXT NOT NULL,
        coins INTEGER NOT NULL,
        birr NUMERIC NOT NULL DEFAULT 0,
        status TEXT NOT NULL DEFAULT 'pending', -- pending | paid | rejected
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        decided_at TIMESTAMPTZ
      )
    `);

    // Seed default settings if missing.
    await pool.query(`
      INSERT INTO app_settings (key, value) VALUES
        ('daily_ad_limit', '10'),
        ('coins_per_ad', '10'),
        ('coins_per_birr', '100'),
        ('min_invites_for_withdraw', '5'),
        ('min_active_days_per_referral', '2'),
        ('invite_reward_coins', '50')
      ON CONFLICT (key) DO NOTHING
    `);

    console.log('Database initialized.');

  })().catch((error) => {

    databaseReady = null;

    console.error(
      'Database initialization error:',
      error
    );

    throw error;
  });

  return databaseReady;
}


// =========================================================
// TELEGRAM API
// =========================================================

async function telegram(method, data = {}) {

  if (!BOT_TOKEN) {
    throw new Error('BOT_TOKEN is missing.');
  }

  const response = await fetch(
    `${TELEGRAM_API}/${method}`,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(data)
    }
  );

  const result = await response.json();

  if (!result.ok) {
    throw new Error(
      `Telegram API error: ${JSON.stringify(result)}`
    );
  }

  return result;
}


// =========================================================
// SEND TELEGRAM MESSAGE
// =========================================================

async function sendTelegramMessage(chatId, text, extra = {}) {

  try {

    await telegram(
      'sendMessage',
      {
        chat_id: chatId,
        text,
        ...extra
      }
    );

    return true;

  } catch (error) {

    console.error(
      'Telegram sendMessage error:',
      error.message
    );

    return false;
  }
}


// =========================================================
// BAN MESSAGE BY REASON
// =========================================================

async function sendBanMessage(
  chatId,
  reason
) {

  if (reason === 'vpn') {

    return sendTelegramMessage(
      chatId,

      '🚫 VPN/Proxy detected.\n\n' +
      'Your account has been permanently banned from Adewa.'
    );
  }

  if (reason === 'multi') {

    return sendTelegramMessage(
      chatId,

      '🚫 Multiple accounts detected.\n\n' +
      'Your account has been permanently banned from Adewa.'
    );
  }

  return sendTelegramMessage(
    chatId,

    '🚫 Your account has been permanently banned from Adewa.'
  );
}


// =========================================================
// GET BAN REASON
// =========================================================

function getBanType(banReason) {

  const reason =
    String(banReason || '').toLowerCase();

  if (
    reason.includes('vpn') ||
    reason.includes('proxy') ||
    reason.includes('tor')
  ) {
    return 'vpn';
  }

  if (
    reason.includes('multiple') ||
    reason.includes('multi account')
  ) {
    return 'multi';
  }

  return 'other';
}


// =========================================================
// ADMIN HELPERS
// =========================================================

function isAdmin(telegramId) {
  return ADMIN_IDS.includes(Number(telegramId));
}

// Verifies x-init-data header AND that the resulting user is an admin.
// Returns { ok: true, user } or { ok: false, status, message }.
function requireAdminFromInitData(req) {

  const initData = req.headers['x-init-data'];

  const verification = verifyTelegramInitData(initData);

  if (!verification.ok) {

    return {
      ok: false,
      status: 401,
      message: verification.reason
    };
  }

  if (!isAdmin(verification.user.id)) {

    return {
      ok: false,
      status: 403,
      message: 'Admin access required.'
    };
  }

  return {
    ok: true,
    user: verification.user
  };
}


// Verifies x-init-data header for ANY verified (non-banned) user.
// Returns { ok: true, user } or { ok: false, status, message }.
function requireUserFromInitData(req) {

  const initData = req.headers['x-init-data'];

  const verification = verifyTelegramInitData(initData);

  if (!verification.ok) {
    return { ok: false, status: 401, message: verification.reason };
  }

  return { ok: true, user: verification.user };
}


// =========================================================
// BAN / UNBAN (shared by admin API and bot commands)
// =========================================================

async function banUserById(telegramId, reason) {

  await initDatabase();

  const result = await pool.query(
    `
    INSERT INTO fraud_users (
      telegram_id, status, ban_reason, admin_verified, last_seen, request_count
    )
    VALUES ($1, 'banned', $2, FALSE, NOW(), 1)

    ON CONFLICT (telegram_id)
    DO UPDATE SET
      status = 'banned',
      ban_reason = EXCLUDED.ban_reason,
      admin_verified = FALSE,
      last_seen = NOW()

    RETURNING *
    `,
    [telegramId, reason || 'Admin ban']
  );

  const banType = getBanType(reason || 'Admin ban');

  await sendBanMessage(telegramId, banType);

  return result.rows[0];
}

async function unbanUserById(telegramId) {

  await initDatabase();

  const result = await pool.query(
    `
    UPDATE fraud_users
    SET
      status = 'verified',
      ban_reason = '',
      vpn_detected = FALSE,
      proxy_detected = FALSE,
      risk_score = 0,
      ban_message_sent = FALSE,
      admin_verified = TRUE,
      last_seen = NOW()
    WHERE telegram_id = $1
    RETURNING *
    `,
    [telegramId]
  );

  if (result.rows.length > 0) {

    await sendTelegramMessage(
      telegramId,
      '✅ Your account has been unbanned. Send /start to continue.'
    );
  }

  return result.rows[0] || null;
}


// =========================================================
// REQUIRED CHANNELS
// =========================================================

async function getRequiredChannels() {

  await initDatabase();

  const result = await pool.query(
    `SELECT * FROM required_channels ORDER BY id ASC`
  );

  return result.rows;
}

async function addRequiredChannel(chatId, title, inviteLink) {

  await initDatabase();

  const result = await pool.query(
    `
    INSERT INTO required_channels (chat_id, title, invite_link)
    VALUES ($1, $2, $3)
    RETURNING *
    `,
    [chatId, title || '', inviteLink || '']
  );

  return result.rows[0];
}

async function removeRequiredChannel(id) {

  await initDatabase();

  await pool.query(
    `DELETE FROM required_channels WHERE id = $1`,
    [id]
  );
}

// =========================================================
// APP SETTINGS HELPERS
// =========================================================

async function getSettings() {
  await initDatabase();
  const result = await pool.query(`SELECT key, value FROM app_settings`);
  const map = {};
  for (const row of result.rows) map[row.key] = row.value;
  return {
    dailyAdLimit: Number(map.daily_ad_limit || 10),
    coinsPerAd: Number(map.coins_per_ad || 10),
    coinsPerBirr: Number(map.coins_per_birr || 100),
    minInvitesForWithdraw: Number(map.min_invites_for_withdraw || 5),
    minActiveDaysPerReferral: Number(map.min_active_days_per_referral || 2),
    inviteRewardCoins: Number(map.invite_reward_coins || 50)
  };
}

async function setSetting(key, value) {
  await initDatabase();
  await pool.query(
    `INSERT INTO app_settings (key, value) VALUES ($1, $2)
     ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`,
    [key, String(value)]
  );
}

// =========================================================
// COIN / BALANCE HELPERS
// =========================================================

async function addCoins(telegramId, bucket, amount) {
  // bucket: 'coins_ads' | 'coins_task' | 'coins_invite'
  await initDatabase();
  const column = ['coins_ads', 'coins_task', 'coins_invite'].includes(bucket)
    ? bucket
    : 'coins_task';
  await pool.query(
    `UPDATE fraud_users SET ${column} = ${column} + $2 WHERE telegram_id = $1`,
    [telegramId, amount]
  );
}

async function getUserRow(telegramId) {
  await initDatabase();
  const result = await pool.query(
    `SELECT * FROM fraud_users WHERE telegram_id = $1`,
    [telegramId]
  );
  return result.rows[0] || null;
}

function totalCoins(row) {
  return (row.coins_ads || 0) + (row.coins_task || 0) + (row.coins_invite || 0);
}

// =========================================================
// REFERRAL HELPERS
// =========================================================

async function recordReferralIfNew(telegramId, referrerId) {
  if (!referrerId || Number(referrerId) === Number(telegramId)) return;
  await initDatabase();
  await pool.query(
    `INSERT INTO fraud_users (telegram_id, referred_by, status, last_seen, request_count)
     VALUES ($1, $2, 'pending', NOW(), 0)
     ON CONFLICT (telegram_id)
     DO UPDATE SET referred_by = COALESCE(fraud_users.referred_by, EXCLUDED.referred_by)`,
    [telegramId, referrerId]
  );
}

// Counts how many people this user has invited who each watched
// ads on at least `minActiveDays` separate days.
async function countQualifiedInvites(telegramId, minActiveDays) {
  await initDatabase();
  const result = await pool.query(
    `
    SELECT COUNT(*) AS qualified
    FROM fraud_users u
    WHERE u.referred_by = $1
      AND u.status <> 'banned'
      AND (
        SELECT COUNT(DISTINCT av.view_date)
        FROM ad_views av
        WHERE av.telegram_id = u.telegram_id
      ) >= $2
    `,
    [telegramId, minActiveDays]
  );
  return Number(result.rows[0]?.qualified || 0);
}

async function countTotalInvites(telegramId) {
  await initDatabase();
  const result = await pool.query(
    `SELECT COUNT(*) AS c FROM fraud_users WHERE referred_by = $1 AND status <> 'banned'`,
    [telegramId]
  );
  return Number(result.rows[0]?.c || 0);
}

function buildChannelKeyboard(channels) {

  const rows = channels.map((channel) => ([
    {
      text: channel.title || channel.chat_id,
      url:
        channel.invite_link ||
        `https://t.me/${String(channel.chat_id).replace('@', '')}`
    }
  ]));

  rows.push([
    {
      text: '✅ Joined',
      callback_data: 'check_joined'
    }
  ]);

  return { inline_keyboard: rows };
}

// Checks Telegram membership for every required channel.
// Returns { allJoined, missing: [titles] }
async function checkAllChannelsJoined(channels, userId) {

  const missing = [];

  for (const channel of channels) {

    try {

      const result = await telegram(
        'getChatMember',
        {
          chat_id: channel.chat_id,
          user_id: userId
        }
      );

      const status = result.result?.status;

      const joined =
        status === 'member' ||
        status === 'administrator' ||
        status === 'creator';

      if (!joined) {
        missing.push(channel.title || channel.chat_id);
      }

    } catch (error) {

      // If we can't verify (bot not admin in channel, user never
      // started a chat with the bot, etc.) treat as not joined.
      console.error(
        'getChatMember error:',
        channel.chat_id,
        error.message
      );

      missing.push(channel.title || channel.chat_id);
    }
  }

  return {
    allJoined: missing.length === 0,
    missing
  };
}


// =========================================================
// TELEGRAM INIT DATA VERIFICATION
// =========================================================

function verifyTelegramInitData(initData) {

  if (!initData) {

    return {
      ok: false,
      reason: 'Missing Telegram initData'
    };
  }

  if (!BOT_TOKEN) {

    return {
      ok: false,
      reason: 'BOT_TOKEN is missing'
    };
  }

  try {

    const params =
      new URLSearchParams(initData);

    const hash =
      params.get('hash');

    if (!hash) {

      return {
        ok: false,
        reason: 'Missing hash'
      };
    }

    params.delete('hash');

    const dataCheckString =
      [...params.entries()]
        .sort(([a], [b]) =>
          a.localeCompare(b)
        )
        .map(
          ([key, value]) =>
            `${key}=${value}`
        )
        .join('\n');

    const secretKey =
      crypto
        .createHmac(
          'sha256',
          'WebAppData'
        )
        .update(BOT_TOKEN)
        .digest();

    const calculatedHash =
      crypto
        .createHmac(
          'sha256',
          secretKey
        )
        .update(dataCheckString)
        .digest('hex');

    const receivedBuffer =
      Buffer.from(hash, 'hex');

    const calculatedBuffer =
      Buffer.from(
        calculatedHash,
        'hex'
      );

    if (
      receivedBuffer.length !==
        calculatedBuffer.length ||
      !crypto.timingSafeEqual(
        receivedBuffer,
        calculatedBuffer
      )
    ) {

      return {
        ok: false,
        reason: 'Invalid Telegram signature'
      };
    }

    const authDate =
      Number(
        params.get('auth_date')
      );

    if (!authDate) {

      return {
        ok: false,
        reason: 'Missing auth_date'
      };
    }

    const now =
      Math.floor(
        Date.now() / 1000
      );

    if (
      now - authDate > 86400
    ) {

      return {
        ok: false,
        reason:
          'Telegram initData expired'
      };
    }

    const userString =
      params.get('user');

    if (!userString) {

      return {
        ok: false,
        reason:
          'Missing Telegram user'
      };
    }

    const user =
      JSON.parse(userString);

    if (!user.id) {

      return {
        ok: false,
        reason:
          'Invalid Telegram user'
      };
    }

    return {
      ok: true,
      user
    };

  } catch (error) {

    console.error(
      'initData verification error:',
      error
    );

    return {
      ok: false,
      reason:
        'Invalid initData'
    };
  }
}


// =========================================================
// HASH
// =========================================================

function sha256(value) {

  return crypto
    .createHash('sha256')
    .update(
      String(value || '')
    )
    .digest('hex');
}


// =========================================================
// CLIENT IP
// =========================================================

function getClientIP(req) {

  const forwarded =
    req.headers[
      'x-forwarded-for'
    ];

  if (forwarded) {

    return String(forwarded)
      .split(',')[0]
      .trim();
  }

  return (
    req.headers['x-real-ip'] ||
    req.socket?.remoteAddress ||
    ''
  );
}


// =========================================================
// VPN / PROXY DETECTION
// =========================================================

async function detectVPNProxy(ip) {

  const result = {

    checked: false,

    vpn: false,

    proxy: false,

    tor: false,

    hosting: false,

    detected: false
  };

  if (!ip) {
    return result;
  }

  const cleanIP =
    String(ip)
      .replace(/^::ffff:/, '')
      .trim();

  if (
    cleanIP === '127.0.0.1' ||
    cleanIP === '::1' ||
    cleanIP.startsWith('10.') ||
    cleanIP.startsWith('192.168.') ||
    cleanIP.startsWith('172.16.')
  ) {
    return result;
  }

  try {

    const response =
      await fetch(
        `https://ipwho.is/${encodeURIComponent(
          cleanIP
        )}`,
        {
          method: 'GET',

          headers: {
            'Accept':
              'application/json'
          },

          signal:
            AbortSignal.timeout(5000)
        }
      );

    if (!response.ok) {
      return result;
    }

    const data =
      await response.json();

    if (
      !data ||
      data.success === false
    ) {
      return result;
    }

    result.checked = true;

    const security =
      data.security || {};

    result.vpn =
      security.vpn === true;

    result.proxy =
      security.proxy === true;

    result.tor =
      security.tor === true;

    result.hosting =
      security.hosting === true;

    result.detected =
      result.vpn ||
      result.proxy ||
      result.tor;

    return result;

  } catch (error) {

    console.error(
      'VPN detection error:',
      error.message
    );

    return result;
  }
}


// =========================================================
// MULTI ACCOUNT DETECTION
// =========================================================

async function detectMultiAccount(
  telegramId,
  ipHash,
  deviceHash
) {

  const result = {

    detected: false,

    reason: ''
  };

  if (
    !deviceHash &&
    !ipHash
  ) {
    return result;
  }

  // -------------------------------------------------------
  // SAME DEVICE
  // -------------------------------------------------------

  if (deviceHash) {

    const deviceResult =
      await pool.query(
        `
        SELECT telegram_id
        FROM fraud_users
        WHERE device_hash = $1
          AND telegram_id <> $2
        LIMIT 1
        `,
        [
          deviceHash,
          telegramId
        ]
      );

    if (
      deviceResult.rows.length > 0
    ) {

      return {

        detected: true,

        reason:
          'Multiple Telegram accounts detected on the same device.'
      };
    }
  }

  // -------------------------------------------------------
  // SAME IP + DIFFERENT DEVICE
  // -------------------------------------------------------

  if (ipHash) {

    const ipResult =
      await pool.query(
        `
        SELECT
          telegram_id,
          device_hash
        FROM fraud_users
        WHERE ip_hash = $1
          AND telegram_id <> $2
          AND status = 'verified'
        LIMIT 1
        `,
        [
          ipHash,
          telegramId
        ]
      );

    if (
      ipResult.rows.length > 0
    ) {

      const oldDevice =
        ipResult.rows[0]
          .device_hash;

      if (
        oldDevice &&
        deviceHash &&
        oldDevice !== deviceHash
      ) {

        return {

          detected: true,

          reason:
            'Multiple Telegram accounts detected from the same IP address.'
        };
      }
    }
  }

  return result;
}


// =========================================================
// SUCCESS MESSAGE
// =========================================================

async function sendVerificationSuccess(
  user
) {

  return sendTelegramMessage(

    user.id,

    '✅ Your verification is successful.'
  );
}


// =========================================================
// CORS
// =========================================================

app.use(
  (req, res, next) => {

    const origin =
      req.headers.origin;

    if (
      origin ===
      'https://abdulselamahemade608-prog.github.io'
    ) {

      res.setHeader(
        'Access-Control-Allow-Origin',
        origin
      );
    }

    res.setHeader(
      'Access-Control-Allow-Headers',
      'Content-Type, x-init-data, x-device'
    );

    res.setHeader(
      'Access-Control-Allow-Methods',
      'GET,POST,DELETE,OPTIONS'
    );

    if (
      req.method === 'OPTIONS'
    ) {

      return res.sendStatus(204);
    }

    next();
  }
);


// =========================================================
// WEBHOOK SETUP
// =========================================================

let webhookPromise = null;

async function setupWebhook() {

  if (webhookPromise) {
    return webhookPromise;
  }

  webhookPromise =
    telegram(
      'setWebhook',
      {
        url: WEBHOOK_URL,

        secret_token:
          WEBHOOK_SECRET,

        allowed_updates:
          ['message', 'callback_query'],

        drop_pending_updates:
          false
      }
    )
    .catch((error) => {

      webhookPromise = null;

      console.error(
        'setWebhook error:',
        error.message
      );

      throw error;
    });

  return webhookPromise;
}


// =========================================================
// ROOT
// =========================================================

app.get(
  '/',
  async (req, res) => {

    try {

      await setupWebhook();

    } catch (error) {

      console.error(
        'Webhook setup error:',
        error.message
      );
    }

    res.json({

      ok: true,

      app:
        'Adewa Telegram Mini App',

      status:
        'online'
    });
  }
);


// =========================================================
// WEBHOOK STATUS
// =========================================================

app.get(
  '/api/webhook-status',
  async (req, res) => {

    try {

      const result =
        await telegram(
          'getWebhookInfo'
        );

      res.json(result);

    } catch (error) {

      res.status(500).json({

        ok: false,

        error:
          error.message
      });
    }
  }
);


// =========================================================
// SEND THE CHANNEL-GATE MESSAGE (used by /start)
// =========================================================

async function sendChannelGate(chatId, firstName) {

  const channels = await getRequiredChannels();

  if (channels.length === 0) {

    // No channels configured — skip straight to the Mini App.
    return sendTelegramMessage(
      chatId,
      `👋 Hello ${firstName}!\n\nWelcome to Adewa Mini App.`,
      {
        reply_markup: {
          inline_keyboard: [[
            { text: '🚀 OPEN ADEWA', web_app: { url: MINI_APP_URL } }
          ]]
        }
      }
    );
  }

  return sendTelegramMessage(
    chatId,

    `ውድ ${firstName} እንኳን በሰላም መጡ! 🎉\n\n` +
    `እባክዎ ከታች ያሉትን ቻናሎች ሁሉንም ይቀላቀሉ፣ ከዚያ "✅ Joined" የሚለውን ይጫኑ።`,

    { reply_markup: buildChannelKeyboard(channels) }
  );
}


// =========================================================
// TELEGRAM WEBHOOK
// =========================================================

app.post(
  '/telegram/webhook',
  async (req, res) => {

    try {

      const incomingSecret =
        req.headers[
          'x-telegram-bot-api-secret-token'
        ];

      if (
        incomingSecret !==
        WEBHOOK_SECRET
      ) {

        console.warn(
          'Invalid webhook secret.'
        );

        return res.sendStatus(403);
      }

      const update = req.body;

      await initDatabase();

      // ===================================================
      // CALLBACK QUERY ("✅ Joined" button)
      // ===================================================

      if (update?.callback_query) {

        const callback = update.callback_query;
        const chatId = callback.message?.chat?.id;
        const userId = callback.from?.id;
        const data = callback.data;

        if (data === 'check_joined' && chatId && userId) {

          // ---- Already banned? Stop here. ----

          const bannedUser = await pool.query(
            `SELECT status, ban_reason FROM fraud_users WHERE telegram_id = $1 LIMIT 1`,
            [userId]
          );

          if (
            bannedUser.rows.length > 0 &&
            bannedUser.rows[0].status === 'banned'
          ) {

            await telegram('answerCallbackQuery', {
              callback_query_id: callback.id,
              text: '🚫 You are banned.',
              show_alert: true
            });

            const banType = getBanType(bannedUser.rows[0].ban_reason);

            await sendBanMessage(chatId, banType);

            return res.sendStatus(200);
          }

          // ---- Verify channel membership ----

          const channels = await getRequiredChannels();

          const { allJoined, missing } =
            await checkAllChannelsJoined(channels, userId);

          if (!allJoined) {

            await telegram('answerCallbackQuery', {
              callback_query_id: callback.id,
              text:
                '⚠️ እባክዎ መጀመሪያ ሁሉንም ቻናሎች ይቀላቀሉ:\n' +
                missing.join(', '),
              show_alert: true
            });

            return res.sendStatus(200);
          }

          // ---- All joined: open the Mini App ----

          await telegram('answerCallbackQuery', {
            callback_query_id: callback.id,
            text: '✅ Verified!'
          });

          await sendTelegramMessage(
            chatId,
            '✅ ሁሉንም ቻናሎች ተቀላቅለዋል! ወደ Adewa ይግቡ 👇',
            {
              reply_markup: {
                inline_keyboard: [[
                  { text: '🚀 OPEN ADEWA', web_app: { url: MINI_APP_URL } }
                ]]
              }
            }
          );
        }

        return res.sendStatus(200);
      }

      // ===================================================
      // REGULAR MESSAGE
      // ===================================================

      const message = update?.message;

      if (!message) {
        return res.sendStatus(200);
      }

      const chatId = message.chat?.id;
      const fromId = message.from?.id;

      const text =
        typeof message.text === 'string'
          ? message.text.trim()
          : '';

      if (!chatId) {
        return res.sendStatus(200);
      }

      const command = text.split(' ')[0].split('@')[0];

      // ===================================================
      // /START — always shows the channel gate first
      // ===================================================

      if (command === '/start') {

        const firstName = message.from?.first_name || 'there';

        // ---- Capture referral payload: "/start ref_123456" ----
        const payload = text.split(' ')[1] || '';
        if (payload.startsWith('ref_')) {
          const referrerId = Number(payload.replace('ref_', ''));
          if (Number.isFinite(referrerId)) {
            await recordReferralIfNew(fromId, referrerId).catch((error) => {
              console.error('recordReferralIfNew error:', error.message);
            });
          }
        }

        await sendChannelGate(chatId, firstName);

        return res.sendStatus(200);
      }

      // ===================================================
      // ADMIN COMMANDS: /ban <id>  and  /unban <id>
      // ===================================================

      if (command === '/ban' || command === '/unban') {

        if (!isAdmin(fromId)) {
          // Silently ignore for non-admins.
          return res.sendStatus(200);
        }

        const targetId = Number(text.split(' ')[1]);

        if (!Number.isFinite(targetId)) {

          await sendTelegramMessage(
            chatId,
            `Usage: ${command} <telegram_id>`
          );

          return res.sendStatus(200);
        }

        if (command === '/ban') {

          await banUserById(targetId, 'Admin ban');

          await sendTelegramMessage(
            chatId,
            `🚫 User ${targetId} has been banned.`
          );

        } else {

          const unbanned = await unbanUserById(targetId);

          await sendTelegramMessage(
            chatId,
            unbanned
              ? `✅ User ${targetId} has been unbanned.`
              : `User ${targetId} was not found.`
          );
        }

        return res.sendStatus(200);
      }

      return res.sendStatus(200);

    } catch (error) {

      console.error(
        'Webhook error:',
        error
      );

      return res.sendStatus(200);
    }
  }
);


// =========================================================
// AUTH
// =========================================================

app.post(
  '/api/auth',
  async (req, res) => {

    try {

      await initDatabase();

      const initData =
        req.headers[
          'x-init-data'
        ];

      const deviceId =
        String(
          req.headers[
            'x-device'
          ] || ''
        ).trim();

      // ---------------------------------------------------
      // VERIFY TELEGRAM
      // ---------------------------------------------------

      const verification =
        verifyTelegramInitData(
          initData
        );

      if (!verification.ok) {

        return res.status(401).json({

          ok: false,

          status:
            'invalid',

          message:
            verification.reason
        });
      }

      const user =
        verification.user;

      const telegramId =
        Number(user.id);

      const username =
        user.username || '';

      const firstName =
        user.first_name || '';

      // ---------------------------------------------------
      // IP / DEVICE
      // ---------------------------------------------------

      const ip =
        getClientIP(req);

      const ipHash =
        sha256(ip);

      const deviceHash =
        sha256(deviceId);

      // ---------------------------------------------------
      // EXISTING USER
      // ---------------------------------------------------

      const existing =
        await pool.query(
          `
          SELECT *
          FROM fraud_users
          WHERE telegram_id = $1
          LIMIT 1
          `,
          [telegramId]
        );

      // ===================================================
      // ALREADY BANNED
      // ===================================================

      if (
        existing.rows.length > 0 &&
        existing.rows[0].status ===
          'banned'
      ) {

        const banType =
          getBanType(
            existing.rows[0]
              .ban_reason
          );

        // Send the same reason again
        await sendBanMessage(
          telegramId,
          banType
        );

        return res.status(403).json({

          ok: false,

          status:
            'banned',

          reason:
            existing.rows[0]
              .ban_reason,

          message:
            'Your account has been permanently banned.'
        });
      }

      // ===================================================
      // ADMIN-VERIFIED — skip automatic fraud checks.
      // An account an admin has manually unbanned is trusted
      // going forward; it should not be auto re-banned just
      // because it shares a device/IP with another account.
      // ===================================================

      const alreadyAdminVerified =
        existing.rows.length > 0 &&
        existing.rows[0].admin_verified === true;

      // ===================================================
      // MULTI ACCOUNT CHECK — runs FIRST.
      // A normal user might trip the VPN check (mobile
      // carrier NAT, shared wifi, etc.), but two Telegram
      // accounts on the same device/IP is the real problem,
      // so it takes priority and bans immediately.
      // ===================================================

      const multiAccount =
        alreadyAdminVerified
          ? { detected: false, reason: '' }
          : await detectMultiAccount(
              telegramId,
              ipHash,
              deviceHash
            );

      if (
        multiAccount.detected
      ) {

        await pool.query(
          `
          INSERT INTO fraud_users (
            telegram_id,
            username,
            first_name,
            ip_hash,
            device_hash,
            vpn_detected,
            proxy_detected,
            risk_score,
            status,
            ban_reason,
            last_seen,
            request_count
          )
          VALUES (
            $1,$2,$3,$4,$5,FALSE,FALSE,$6,'banned',$7,NOW(),1
          )

          ON CONFLICT (telegram_id)
          DO UPDATE SET

            username =
              EXCLUDED.username,

            first_name =
              EXCLUDED.first_name,

            ip_hash =
              EXCLUDED.ip_hash,

            device_hash =
              EXCLUDED.device_hash,

            risk_score =
              EXCLUDED.risk_score,

            status =
              'banned',

            ban_reason =
              EXCLUDED.ban_reason,

            last_seen =
              NOW(),

            request_count =
              fraud_users.request_count + 1
          `,
          [

            telegramId,

            username,

            firstName,

            ipHash,

            deviceHash,

            100,

            multiAccount.reason
          ]
        );

        await sendBanMessage(
          telegramId,
          'multi'
        );

        return res.status(403).json({

          ok: false,

          status:
            'banned',

          reason:
            multiAccount.reason,

          message:
            'Multiple accounts detected. Your account has been permanently banned.'
        });
      }

      // ===================================================
      // VPN / PROXY CHECK — runs second.
      // ===================================================

      const networkCheck =
        alreadyAdminVerified
          ? { detected: false }
          : await detectVPNProxy(ip);

      if (
        networkCheck.detected
      ) {

        const reason =
          networkCheck.vpn
            ? 'VPN detected'
            : networkCheck.proxy
              ? 'Proxy detected'
              : networkCheck.tor
                ? 'Tor detected'
                : 'Restricted network detected';

        await pool.query(
          `
          INSERT INTO fraud_users (
            telegram_id,
            username,
            first_name,
            ip_hash,
            device_hash,
            vpn_detected,
            proxy_detected,
            risk_score,
            status,
            ban_reason,
            last_seen,
            request_count
          )
          VALUES (
            $1,$2,$3,$4,$5,$6,$7,$8,'banned',$9,NOW(),1
          )

          ON CONFLICT (telegram_id)
          DO UPDATE SET

            username =
              EXCLUDED.username,

            first_name =
              EXCLUDED.first_name,

            ip_hash =
              EXCLUDED.ip_hash,

            device_hash =
              EXCLUDED.device_hash,

            vpn_detected =
              EXCLUDED.vpn_detected,

            proxy_detected =
              EXCLUDED.proxy_detected,

            risk_score =
              EXCLUDED.risk_score,

            status =
              'banned',

            ban_reason =
              EXCLUDED.ban_reason,

            last_seen =
              NOW(),

            request_count =
              fraud_users.request_count + 1
          `,
          [

            telegramId,

            username,

            firstName,

            ipHash,

            deviceHash,

            networkCheck.vpn ||
              networkCheck.tor,

            networkCheck.proxy,

            100,

            reason
          ]
        );

        await sendBanMessage(
          telegramId,
          'vpn'
        );

        return res.status(403).json({

          ok: false,

          status:
            'banned',

          reason,

          message:
            'VPN/Proxy detected. Your account has been permanently banned.'
        });
      }

      // ===================================================
      // NORMAL USER
      // ===================================================

      await pool.query(
        `
        INSERT INTO fraud_users (
          telegram_id,
          username,
          first_name,
          ip_hash,
          device_hash,
          vpn_detected,
          proxy_detected,
          risk_score,
          status,
          ban_reason,
          last_seen,
          request_count
        )
        VALUES (
          $1,$2,$3,$4,$5,FALSE,FALSE,0,'verified','',NOW(),1
        )

        ON CONFLICT (telegram_id)
        DO UPDATE SET

          username =
            EXCLUDED.username,

          first_name =
            EXCLUDED.first_name,

          ip_hash =
            EXCLUDED.ip_hash,

          device_hash =
            EXCLUDED.device_hash,

          status =
            'verified',

          last_seen =
            NOW(),

          request_count =
            fraud_users.request_count + 1
        `,
        [

          telegramId,

          username,

          firstName,

          ipHash,

          deviceHash
        ]
      );

      // ===================================================
      // SUCCESS MESSAGE
      // ===================================================

      const current =
        await pool.query(
          `
          SELECT
            verification_message_sent
          FROM fraud_users
          WHERE telegram_id = $1
          `,
          [telegramId]
        );

      const messageAlreadySent =
        current.rows[0]
          ?.verification_message_sent;

      if (
        !messageAlreadySent
      ) {

        const sent =
          await sendVerificationSuccess(
            user
          );

        if (sent) {

          await pool.query(
            `
            UPDATE fraud_users
            SET
              verification_message_sent = TRUE
            WHERE telegram_id = $1
            `,
            [telegramId]
          );
        }
      }

      return res.json({

        ok: true,

        status:
          'verified',

        admin:
          isAdmin(telegramId),

        message:
          'Your verification is successful.'
      });

    } catch (error) {

      console.error(
        'AUTH ERROR:',
        error
      );

      return res.status(500).json({

        ok: false,

        status:
          'error',

        message:
          'Verification server error.'
      });
    }
  }
);


// =========================================================
// ADMIN — GET USER
// =========================================================

app.get(
  '/api/admin/user/:id',
  async (req, res) => {

    const auth = requireAdminFromInitData(req);

    if (!auth.ok) {
      return res.status(auth.status).json({ ok: false, message: auth.message });
    }

    try {

      await initDatabase();

      const id =
        Number(req.params.id);

      if (
        !Number.isFinite(id)
      ) {

        return res.status(400).json({

          ok: false,

          error:
            'Invalid user ID'
        });
      }

      const result =
        await pool.query(
          `
          SELECT *
          FROM fraud_users
          WHERE telegram_id = $1
          `,
          [id]
        );

      return res.json({

        ok: true,

        user:
          result.rows[0] || null
      });

    } catch (error) {

      console.error(
        'Admin user error:',
        error
      );

      return res.status(500).json({

        ok: false,

        error:
          error.message
      });
    }
  }
);


// =========================================================
// ADMIN — LIST / SEARCH USERS
// =========================================================

app.get(
  '/api/admin/users',
  async (req, res) => {

    const auth = requireAdminFromInitData(req);

    if (!auth.ok) {
      return res.status(auth.status).json({ ok: false, message: auth.message });
    }

    try {

      await initDatabase();

      const status = req.query.status; // 'banned' | 'verified' | undefined

      const result = status
        ? await pool.query(
            `SELECT * FROM fraud_users WHERE status = $1 ORDER BY last_seen DESC LIMIT 200`,
            [status]
          )
        : await pool.query(
            `SELECT * FROM fraud_users ORDER BY last_seen DESC LIMIT 200`
          );

      return res.json({ ok: true, users: result.rows });

    } catch (error) {

      console.error('Admin users list error:', error);

      return res.status(500).json({ ok: false, error: error.message });
    }
  }
);


// =========================================================
// ADMIN — STATS
// =========================================================

app.get(
  '/api/admin/stats',
  async (req, res) => {

    const auth = requireAdminFromInitData(req);

    if (!auth.ok) {
      return res.status(auth.status).json({ ok: false, message: auth.message });
    }

    try {

      await initDatabase();

      const result = await pool.query(`
        SELECT
          COUNT(*) FILTER (WHERE status = 'verified') AS verified,
          COUNT(*) FILTER (WHERE status = 'banned') AS banned,
          COUNT(*) AS total
        FROM fraud_users
      `);

      return res.json({ ok: true, stats: result.rows[0] });

    } catch (error) {

      console.error('Admin stats error:', error);

      return res.status(500).json({ ok: false, error: error.message });
    }
  }
);


// =========================================================
// ADMIN — BAN / UNBAN
// =========================================================

app.post(
  '/api/admin/ban/:id',
  async (req, res) => {

    const auth = requireAdminFromInitData(req);

    if (!auth.ok) {
      return res.status(auth.status).json({ ok: false, message: auth.message });
    }

    try {

      const id = Number(req.params.id);

      const reason = req.body?.reason || 'Admin ban';

      await banUserById(id, reason);

      return res.json({ ok: true, message: 'User permanently banned.' });

    } catch (error) {

      console.error('Admin ban error:', error);

      return res.status(500).json({ ok: false, error: error.message });
    }
  }
);

app.post(
  '/api/admin/unban/:id',
  async (req, res) => {

    const auth = requireAdminFromInitData(req);

    if (!auth.ok) {
      return res.status(auth.status).json({ ok: false, message: auth.message });
    }

    try {

      const id = Number(req.params.id);

      await unbanUserById(id);

      return res.json({ ok: true, message: 'User unbanned.' });

    } catch (error) {

      console.error('Admin unban error:', error);

      return res.status(500).json({ ok: false, error: error.message });
    }
  }
);


// =========================================================
// ADMIN — REQUIRED CHANNELS (add / list / remove)
// =========================================================

app.get(
  '/api/admin/channels',
  async (req, res) => {

    const auth = requireAdminFromInitData(req);

    if (!auth.ok) {
      return res.status(auth.status).json({ ok: false, message: auth.message });
    }

    try {

      const channels = await getRequiredChannels();

      return res.json({ ok: true, channels });

    } catch (error) {

      console.error('Admin channels list error:', error);

      return res.status(500).json({ ok: false, error: error.message });
    }
  }
);

app.post(
  '/api/admin/channels',
  async (req, res) => {

    const auth = requireAdminFromInitData(req);

    if (!auth.ok) {
      return res.status(auth.status).json({ ok: false, message: auth.message });
    }

    try {

      const { chat_id, title, invite_link } = req.body || {};

      if (!chat_id) {

        return res.status(400).json({ ok: false, message: 'chat_id is required.' });
      }

      const channel = await addRequiredChannel(chat_id, title, invite_link);

      return res.json({ ok: true, channel });

    } catch (error) {

      console.error('Admin add channel error:', error);

      return res.status(500).json({ ok: false, error: error.message });
    }
  }
);

app.delete(
  '/api/admin/channels/:id',
  async (req, res) => {

    const auth = requireAdminFromInitData(req);

    if (!auth.ok) {
      return res.status(auth.status).json({ ok: false, message: auth.message });
    }

    try {

      await removeRequiredChannel(Number(req.params.id));

      return res.json({ ok: true, message: 'Channel removed.' });

    } catch (error) {

      console.error('Admin remove channel error:', error);

      return res.status(500).json({ ok: false, error: error.message });
    }
  }
);


// =========================================================
// USER — ME (balance, streak, invite info)
// =========================================================

app.get('/api/me', async (req, res) => {

  const auth = requireUserFromInitData(req);
  if (!auth.ok) return res.status(auth.status).json({ ok: false, message: auth.message });

  try {
    await initDatabase();
    const telegramId = Number(auth.user.id);
    const row = await getUserRow(telegramId);
    if (!row) return res.status(404).json({ ok: false, message: 'User not found.' });

    const settings = await getSettings();
    const coins = totalCoins(row);
    const birr = +(coins / settings.coinsPerBirr).toFixed(2);
    const totalInvites = await countTotalInvites(telegramId);
    const qualifiedInvites = await countQualifiedInvites(telegramId, settings.minActiveDaysPerReferral);

    return res.json({
      ok: true,
      user: {
        telegram_id: telegramId,
        username: row.username,
        first_name: row.first_name,
        coins_ads: row.coins_ads,
        coins_task: row.coins_task,
        coins_invite: row.coins_invite,
        coins_total: coins,
        birr,
        streak_count: row.streak_count,
        last_checkin: row.last_checkin,
        bep20_address: row.bep20_address,
        ton_address: row.ton_address,
        total_invites: totalInvites,
        qualified_invites: qualifiedInvites,
        is_admin: isAdmin(telegramId)
      },
      settings
    });
  } catch (error) {
    console.error('me error:', error);
    return res.status(500).json({ ok: false, message: error.message });
  }
});


// =========================================================
// USER — DAILY CHECK-IN / STREAK
// =========================================================

app.post('/api/checkin', async (req, res) => {

  const auth = requireUserFromInitData(req);
  if (!auth.ok) return res.status(auth.status).json({ ok: false, message: auth.message });

  try {
    await initDatabase();
    const telegramId = Number(auth.user.id);
    const row = await getUserRow(telegramId);
    if (!row) return res.status(404).json({ ok: false, message: 'User not found.' });

    const today = new Date().toISOString().slice(0, 10);
    const lastCheckin = row.last_checkin
      ? new Date(row.last_checkin).toISOString().slice(0, 10)
      : null;

    if (lastCheckin === today) {
      return res.json({ ok: true, already: true, streak_count: row.streak_count });
    }

    const yesterday = new Date(Date.now() - 86400000).toISOString().slice(0, 10);
    const newStreak = (lastCheckin === yesterday) ? (row.streak_count + 1) : 1;

    await pool.query(
      `UPDATE fraud_users SET streak_count = $2, last_checkin = $3 WHERE telegram_id = $1`,
      [telegramId, newStreak, today]
    );

    return res.json({ ok: true, already: false, streak_count: newStreak });
  } catch (error) {
    console.error('checkin error:', error);
    return res.status(500).json({ ok: false, message: error.message });
  }
});


// =========================================================
// USER — WATCH ADS
// =========================================================

app.get('/api/ads/status', async (req, res) => {

  const auth = requireUserFromInitData(req);
  if (!auth.ok) return res.status(auth.status).json({ ok: false, message: auth.message });

  try {
    await initDatabase();
    const telegramId = Number(auth.user.id);
    const settings = await getSettings();

    const result = await pool.query(
      `SELECT count FROM ad_views WHERE telegram_id = $1 AND view_date = CURRENT_DATE`,
      [telegramId]
    );

    const viewedToday = Number(result.rows[0]?.count || 0);

    return res.json({
      ok: true,
      viewed_today: viewedToday,
      daily_limit: settings.dailyAdLimit,
      coins_per_ad: settings.coinsPerAd,
      remaining: Math.max(0, settings.dailyAdLimit - viewedToday)
    });
  } catch (error) {
    console.error('ads status error:', error);
    return res.status(500).json({ ok: false, message: error.message });
  }
});

app.post('/api/ads/watch', async (req, res) => {

  const auth = requireUserFromInitData(req);
  if (!auth.ok) return res.status(auth.status).json({ ok: false, message: auth.message });

  try {
    await initDatabase();
    const telegramId = Number(auth.user.id);
    const settings = await getSettings();

    const existing = await pool.query(
      `SELECT count FROM ad_views WHERE telegram_id = $1 AND view_date = CURRENT_DATE`,
      [telegramId]
    );
    const viewedToday = Number(existing.rows[0]?.count || 0);

    if (viewedToday >= settings.dailyAdLimit) {
      return res.status(429).json({ ok: false, message: 'Daily ad limit reached.' });
    }

    await pool.query(
      `INSERT INTO ad_views (telegram_id, view_date, count)
       VALUES ($1, CURRENT_DATE, 1)
       ON CONFLICT (telegram_id, view_date)
       DO UPDATE SET count = ad_views.count + 1`,
      [telegramId]
    );

    await addCoins(telegramId, 'coins_ads', settings.coinsPerAd);

    // If this ad view just made the user a "qualified" referral
    // (distinct-day count reached the threshold) for the first
    // time, reward whoever referred them, once.
    const me = await getUserRow(telegramId);
    if (me?.referred_by && !me.referral_rewarded) {
      const distinctDays = await pool.query(
        `SELECT COUNT(DISTINCT view_date) AS c FROM ad_views WHERE telegram_id = $1`,
        [telegramId]
      );
      if (Number(distinctDays.rows[0]?.c || 0) >= settings.minActiveDaysPerReferral) {
        await addCoins(me.referred_by, 'coins_invite', settings.inviteRewardCoins);
        await pool.query(`UPDATE fraud_users SET referral_rewarded = TRUE WHERE telegram_id = $1`, [telegramId]);
        await sendTelegramMessage(
          me.referred_by,
          `🎉 One of your invites became active! +${settings.inviteRewardCoins} coins.`
        ).catch(() => {});
      }
    }

    return res.json({
      ok: true,
      rewarded: settings.coinsPerAd,
      viewed_today: viewedToday + 1,
      remaining: Math.max(0, settings.dailyAdLimit - viewedToday - 1)
    });
  } catch (error) {
    console.error('ads watch error:', error);
    return res.status(500).json({ ok: false, message: error.message });
  }
});


// =========================================================
// USER — TASKS (telegram-join / social-media)
// =========================================================

app.get('/api/tasks', async (req, res) => {

  const auth = requireUserFromInitData(req);
  if (!auth.ok) return res.status(auth.status).json({ ok: false, message: auth.message });

  try {
    await initDatabase();
    const telegramId = Number(auth.user.id);

    const result = await pool.query(
      `
      SELECT t.*
      FROM tasks t
      WHERE t.active = TRUE
        AND (t.user_limit = 0 OR t.completed_count < t.user_limit)
        AND NOT EXISTS (
          SELECT 1 FROM task_completions tc
          WHERE tc.task_id = t.id AND tc.telegram_id = $1
            AND tc.status IN ('approved', 'pending')
        )
      ORDER BY t.created_at DESC
      `,
      [telegramId]
    );

    return res.json({ ok: true, tasks: result.rows });
  } catch (error) {
    console.error('tasks list error:', error);
    return res.status(500).json({ ok: false, message: error.message });
  }
});

app.post('/api/tasks/:id/complete', async (req, res) => {

  const auth = requireUserFromInitData(req);
  if (!auth.ok) return res.status(auth.status).json({ ok: false, message: auth.message });

  try {
    await initDatabase();
    const telegramId = Number(auth.user.id);
    const taskId = Number(req.params.id);

    const taskRes = await pool.query(`SELECT * FROM tasks WHERE id = $1 AND active = TRUE`, [taskId]);
    const task = taskRes.rows[0];
    if (!task) return res.status(404).json({ ok: false, message: 'Task not found or inactive.' });

    if (task.user_limit > 0 && task.completed_count >= task.user_limit) {
      return res.status(400).json({ ok: false, message: 'This task is no longer available.' });
    }

    const already = await pool.query(
      `SELECT status FROM task_completions WHERE task_id = $1 AND telegram_id = $2`,
      [taskId, telegramId]
    );
    if (already.rows.length > 0 && already.rows[0].status !== 'rejected') {
      return res.status(400).json({ ok: false, message: 'Already submitted for this task.' });
    }

    if (task.type === 'telegram') {

      // Auto-verify membership via Bot API — no admin approval needed.
      const membershipCheck = await checkAllChannelsJoined(
        [{ chat_id: task.target, title: task.title }],
        telegramId
      );

      if (!membershipCheck.allJoined) {
        return res.status(400).json({ ok: false, message: 'You have not joined the channel/group yet.' });
      }

      await pool.query(
        `INSERT INTO task_completions (task_id, telegram_id, status, decided_at)
         VALUES ($1, $2, 'approved', NOW())
         ON CONFLICT (task_id, telegram_id)
         DO UPDATE SET status = 'approved', decided_at = NOW()`,
        [taskId, telegramId]
      );

      await pool.query(`UPDATE tasks SET completed_count = completed_count + 1 WHERE id = $1`, [taskId]);
      await addCoins(telegramId, 'coins_task', task.reward_coins);

      return res.json({ ok: true, status: 'approved', rewarded: task.reward_coins });
    }

    // Social-media task: needs a proof note / screenshot sent to the
    // bot separately; here we just record the submission as pending.
    const proofNote = String(req.body?.proof_note || '').slice(0, 500);

    await pool.query(
      `INSERT INTO task_completions (task_id, telegram_id, status, proof_note)
       VALUES ($1, $2, 'pending', $3)
       ON CONFLICT (task_id, telegram_id)
       DO UPDATE SET status = 'pending', proof_note = EXCLUDED.proof_note, created_at = NOW()`,
      [taskId, telegramId, proofNote]
    );

    // Notify admins to review the screenshot sent to the bot.
    for (const adminId of ADMIN_IDS) {
      await sendTelegramMessage(
        adminId,
        `📝 New task submission pending review.\nTask: ${task.title}\nUser: ${telegramId} (@${auth.user.username || ''})\nReward: ${task.reward_coins} coins\nNote: ${proofNote || '(see DM screenshot)'}`
      ).catch(() => {});
    }

    return res.json({ ok: true, status: 'pending' });

  } catch (error) {
    console.error('task complete error:', error);
    return res.status(500).json({ ok: false, message: error.message });
  }
});


// =========================================================
// USER — INVITE (link stats + leaderboards)
// =========================================================

app.get('/api/invite/stats', async (req, res) => {

  const auth = requireUserFromInitData(req);
  if (!auth.ok) return res.status(auth.status).json({ ok: false, message: auth.message });

  try {
    await initDatabase();
    const telegramId = Number(auth.user.id);
    const settings = await getSettings();

    const totalInvites = await countTotalInvites(telegramId);
    const qualifiedInvites = await countQualifiedInvites(telegramId, settings.minActiveDaysPerReferral);

    return res.json({ ok: true, total_invites: totalInvites, qualified_invites: qualifiedInvites });
  } catch (error) {
    console.error('invite stats error:', error);
    return res.status(500).json({ ok: false, message: error.message });
  }
});

app.get('/api/invite/leaderboard', async (req, res) => {

  const auth = requireUserFromInitData(req);
  if (!auth.ok) return res.status(auth.status).json({ ok: false, message: auth.message });

  try {
    await initDatabase();

    const topReferrers = await pool.query(`
      SELECT telegram_id, username, first_name, coins_invite
      FROM fraud_users
      WHERE status <> 'banned'
      ORDER BY coins_invite DESC
      LIMIT 10
    `);

    const topEarners = await pool.query(`
      SELECT telegram_id, username, first_name, (coins_ads + coins_task + coins_invite) AS coins_total
      FROM fraud_users
      WHERE status <> 'banned'
      ORDER BY coins_total DESC
      LIMIT 15
    `);

    return res.json({
      ok: true,
      top_referrers: topReferrers.rows,
      top_earners: topEarners.rows
    });
  } catch (error) {
    console.error('invite leaderboard error:', error);
    return res.status(500).json({ ok: false, message: error.message });
  }
});


// =========================================================
// USER — PROMO CODE REDEMPTION
// =========================================================

app.post('/api/promo/redeem', async (req, res) => {

  const auth = requireUserFromInitData(req);
  if (!auth.ok) return res.status(auth.status).json({ ok: false, message: auth.message });

  try {
    await initDatabase();
    const telegramId = Number(auth.user.id);
    const code = String(req.body?.code || '').trim().toUpperCase();
    if (!code) return res.status(400).json({ ok: false, message: 'Promo code is required.' });

    const promoRes = await pool.query(
      `SELECT * FROM promo_codes WHERE code = $1 AND active = TRUE`,
      [code]
    );
    const promo = promoRes.rows[0];
    if (!promo) return res.status(404).json({ ok: false, message: 'Invalid or expired promo code.' });

    if (promo.used_count >= promo.max_uses) {
      return res.status(400).json({ ok: false, message: 'This promo code has reached its limit.' });
    }

    const already = await pool.query(
      `SELECT 1 FROM promo_redemptions WHERE code = $1 AND telegram_id = $2`,
      [code, telegramId]
    );
    if (already.rows.length > 0) {
      return res.status(400).json({ ok: false, message: 'You already used this promo code.' });
    }

    await pool.query(
      `INSERT INTO promo_redemptions (code, telegram_id) VALUES ($1, $2)`,
      [code, telegramId]
    );
    await pool.query(`UPDATE promo_codes SET used_count = used_count + 1 WHERE code = $1`, [code]);
    await addCoins(telegramId, 'coins_task', promo.reward_coins);

    return res.json({ ok: true, rewarded: promo.reward_coins });
  } catch (error) {
    console.error('promo redeem error:', error);
    return res.status(500).json({ ok: false, message: error.message });
  }
});


// =========================================================
// USER — WITHDRAWALS
// =========================================================

app.get('/api/withdraw/eligibility', async (req, res) => {

  const auth = requireUserFromInitData(req);
  if (!auth.ok) return res.status(auth.status).json({ ok: false, message: auth.message });

  try {
    await initDatabase();
    const telegramId = Number(auth.user.id);
    const settings = await getSettings();

    const qualifiedInvites = await countQualifiedInvites(telegramId, settings.minActiveDaysPerReferral);
    const eligible = qualifiedInvites >= settings.minInvitesForWithdraw;

    return res.json({
      ok: true,
      eligible,
      qualified_invites: qualifiedInvites,
      required_invites: settings.minInvitesForWithdraw,
      required_active_days: settings.minActiveDaysPerReferral
    });
  } catch (error) {
    console.error('withdraw eligibility error:', error);
    return res.status(500).json({ ok: false, message: error.message });
  }
});

app.post('/api/withdraw', async (req, res) => {

  const auth = requireUserFromInitData(req);
  if (!auth.ok) return res.status(auth.status).json({ ok: false, message: auth.message });

  try {
    await initDatabase();
    const telegramId = Number(auth.user.id);
    const settings = await getSettings();

    const method = String(req.body?.method || '').toUpperCase();
    const address = String(req.body?.address || '').trim();

    if (!['BEP20', 'TON'].includes(method)) {
      return res.status(400).json({ ok: false, message: 'Method must be BEP20 or TON.' });
    }
    if (!address) {
      return res.status(400).json({ ok: false, message: 'Wallet address is required.' });
    }

    const qualifiedInvites = await countQualifiedInvites(telegramId, settings.minActiveDaysPerReferral);
    if (qualifiedInvites < settings.minInvitesForWithdraw) {
      return res.status(400).json({
        ok: false,
        message: `You need ${settings.minInvitesForWithdraw} qualified invites to withdraw (you have ${qualifiedInvites}).`
      });
    }

    const row = await getUserRow(telegramId);
    const coins = totalCoins(row);
    if (coins <= 0) {
      return res.status(400).json({ ok: false, message: 'No balance to withdraw.' });
    }

    const birr = +(coins / settings.coinsPerBirr).toFixed(2);

    await pool.query(
      `INSERT INTO withdrawals (telegram_id, method, address, coins, birr, status)
       VALUES ($1, $2, $3, $4, $5, 'pending')`,
      [telegramId, method, address, coins, birr]
    );

    // Zero out the balance now that it's locked into a pending request.
    await pool.query(
      `UPDATE fraud_users SET coins_ads = 0, coins_task = 0, coins_invite = 0,
        bep20_address = CASE WHEN $2 = 'BEP20' THEN $3 ELSE bep20_address END,
        ton_address = CASE WHEN $2 = 'TON' THEN $3 ELSE ton_address END
       WHERE telegram_id = $1`,
      [telegramId, method, address]
    );

    for (const adminId of ADMIN_IDS) {
      await sendTelegramMessage(
        adminId,
        `💸 New withdrawal request\nUser: ${telegramId}\nMethod: ${method}\nAddress: ${address}\nAmount: ${coins} coins (${birr} ETB)`
      ).catch(() => {});
    }

    return res.json({ ok: true, message: 'Withdrawal request submitted.', coins, birr });
  } catch (error) {
    console.error('withdraw request error:', error);
    return res.status(500).json({ ok: false, message: error.message });
  }
});

app.get('/api/withdraw/history', async (req, res) => {

  const auth = requireUserFromInitData(req);
  if (!auth.ok) return res.status(auth.status).json({ ok: false, message: auth.message });

  try {
    await initDatabase();
    const telegramId = Number(auth.user.id);
    const result = await pool.query(
      `SELECT * FROM withdrawals WHERE telegram_id = $1 ORDER BY created_at DESC LIMIT 20`,
      [telegramId]
    );
    return res.json({ ok: true, withdrawals: result.rows });
  } catch (error) {
    console.error('withdraw history error:', error);
    return res.status(500).json({ ok: false, message: error.message });
  }
});


// =========================================================
// ADMIN — SETTINGS
// =========================================================

app.get('/api/admin/settings', async (req, res) => {
  const auth = requireAdminFromInitData(req);
  if (!auth.ok) return res.status(auth.status).json({ ok: false, message: auth.message });

  try {
    const settings = await getSettings();
    return res.json({ ok: true, settings });
  } catch (error) {
    return res.status(500).json({ ok: false, message: error.message });
  }
});

app.post('/api/admin/settings', async (req, res) => {
  const auth = requireAdminFromInitData(req);
  if (!auth.ok) return res.status(auth.status).json({ ok: false, message: auth.message });

  try {
    const body = req.body || {};
    const map = {
      dailyAdLimit: 'daily_ad_limit',
      coinsPerAd: 'coins_per_ad',
      coinsPerBirr: 'coins_per_birr',
      minInvitesForWithdraw: 'min_invites_for_withdraw',
      minActiveDaysPerReferral: 'min_active_days_per_referral'
    };

    for (const [bodyKey, dbKey] of Object.entries(map)) {
      if (body[bodyKey] !== undefined) {
        await setSetting(dbKey, body[bodyKey]);
      }
    }

    const settings = await getSettings();
    return res.json({ ok: true, settings });
  } catch (error) {
    return res.status(500).json({ ok: false, message: error.message });
  }
});


// =========================================================
// ADMIN — TASK CREATOR
// =========================================================

app.get('/api/admin/tasks', async (req, res) => {
  const auth = requireAdminFromInitData(req);
  if (!auth.ok) return res.status(auth.status).json({ ok: false, message: auth.message });

  try {
    await initDatabase();
    const result = await pool.query(`SELECT * FROM tasks ORDER BY created_at DESC LIMIT 200`);
    return res.json({ ok: true, tasks: result.rows });
  } catch (error) {
    return res.status(500).json({ ok: false, message: error.message });
  }
});

app.post('/api/admin/tasks', async (req, res) => {
  const auth = requireAdminFromInitData(req);
  if (!auth.ok) return res.status(auth.status).json({ ok: false, message: auth.message });

  try {
    await initDatabase();
    const { type, title, description, target, reward_coins, user_limit } = req.body || {};

    if (!['telegram', 'social'].includes(type)) {
      return res.status(400).json({ ok: false, message: "type must be 'telegram' or 'social'." });
    }
    if (!target) {
      return res.status(400).json({ ok: false, message: 'target (channel username or link) is required.' });
    }

    const result = await pool.query(
      `INSERT INTO tasks (type, title, description, target, reward_coins, user_limit)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
      [type, title || '', description || '', target, Number(reward_coins) || 0, Number(user_limit) || 0]
    );

    const task = result.rows[0];

    // Broadcast to all users that a new task is available.
    const users = await pool.query(`SELECT telegram_id FROM fraud_users WHERE status = 'verified'`);
    for (const u of users.rows) {
      await sendTelegramMessage(
        u.telegram_id,
        `🆕 New task available: ${task.title || task.target}\nReward: ${task.reward_coins} coins\nOpen Adewa to complete it!`
      ).catch(() => {});
    }

    return res.json({ ok: true, task });
  } catch (error) {
    return res.status(500).json({ ok: false, message: error.message });
  }
});

app.delete('/api/admin/tasks/:id', async (req, res) => {
  const auth = requireAdminFromInitData(req);
  if (!auth.ok) return res.status(auth.status).json({ ok: false, message: auth.message });

  try {
    await pool.query(`UPDATE tasks SET active = FALSE WHERE id = $1`, [Number(req.params.id)]);
    return res.json({ ok: true, message: 'Task deactivated.' });
  } catch (error) {
    return res.status(500).json({ ok: false, message: error.message });
  }
});


// =========================================================
// ADMIN — PROOF APPROVALS (social-media task submissions)
// =========================================================

app.get('/api/admin/submissions', async (req, res) => {
  const auth = requireAdminFromInitData(req);
  if (!auth.ok) return res.status(auth.status).json({ ok: false, message: auth.message });

  try {
    await initDatabase();
    const status = req.query.status || 'pending';
    const result = await pool.query(
      `
      SELECT tc.*, t.title, t.reward_coins, t.type
      FROM task_completions tc
      JOIN tasks t ON t.id = tc.task_id
      WHERE tc.status = $1
      ORDER BY tc.created_at ASC
      LIMIT 200
      `,
      [status]
    );
    return res.json({ ok: true, submissions: result.rows });
  } catch (error) {
    return res.status(500).json({ ok: false, message: error.message });
  }
});

app.post('/api/admin/submissions/:id/decide', async (req, res) => {
  const auth = requireAdminFromInitData(req);
  if (!auth.ok) return res.status(auth.status).json({ ok: false, message: auth.message });

  try {
    await initDatabase();
    const id = Number(req.params.id);
    const decision = String(req.body?.decision || '').toLowerCase(); // approve | reject

    if (!['approve', 'reject'].includes(decision)) {
      return res.status(400).json({ ok: false, message: "decision must be 'approve' or 'reject'." });
    }

    const subRes = await pool.query(
      `SELECT tc.*, t.reward_coins, t.title FROM task_completions tc
       JOIN tasks t ON t.id = tc.task_id WHERE tc.id = $1`,
      [id]
    );
    const submission = subRes.rows[0];
    if (!submission) return res.status(404).json({ ok: false, message: 'Submission not found.' });

    const newStatus = decision === 'approve' ? 'approved' : 'rejected';

    await pool.query(
      `UPDATE task_completions SET status = $2, decided_at = NOW() WHERE id = $1`,
      [id, newStatus]
    );

    if (decision === 'approve') {
      await pool.query(`UPDATE tasks SET completed_count = completed_count + 1 WHERE id = $1`, [submission.task_id]);
      await addCoins(submission.telegram_id, 'coins_task', submission.reward_coins);
    }

    await sendTelegramMessage(
      submission.telegram_id,
      decision === 'approve'
        ? `✅ Your task "${submission.title}" was approved! +${submission.reward_coins} coins.`
        : `❌ Your task "${submission.title}" submission was rejected.`
    ).catch(() => {});

    return res.json({ ok: true, message: `Submission ${newStatus}.` });
  } catch (error) {
    return res.status(500).json({ ok: false, message: error.message });
  }
});


// =========================================================
// ADMIN — PROMO CODES
// =========================================================

app.get('/api/admin/promo', async (req, res) => {
  const auth = requireAdminFromInitData(req);
  if (!auth.ok) return res.status(auth.status).json({ ok: false, message: auth.message });

  try {
    await initDatabase();
    const result = await pool.query(`SELECT * FROM promo_codes ORDER BY created_at DESC LIMIT 200`);
    return res.json({ ok: true, codes: result.rows });
  } catch (error) {
    return res.status(500).json({ ok: false, message: error.message });
  }
});

app.post('/api/admin/promo', async (req, res) => {
  const auth = requireAdminFromInitData(req);
  if (!auth.ok) return res.status(auth.status).json({ ok: false, message: auth.message });

  try {
    await initDatabase();
    const code = String(req.body?.code || '').trim().toUpperCase() ||
      crypto.randomBytes(4).toString('hex').toUpperCase();
    const rewardCoins = Number(req.body?.reward_coins) || 0;
    const maxUses = Number(req.body?.max_uses) || 1;

    const result = await pool.query(
      `INSERT INTO promo_codes (code, reward_coins, max_uses) VALUES ($1, $2, $3)
       ON CONFLICT (code) DO UPDATE SET reward_coins = EXCLUDED.reward_coins, max_uses = EXCLUDED.max_uses
       RETURNING *`,
      [code, rewardCoins, maxUses]
    );

    return res.json({ ok: true, code: result.rows[0] });
  } catch (error) {
    return res.status(500).json({ ok: false, message: error.message });
  }
});

app.delete('/api/admin/promo/:code', async (req, res) => {
  const auth = requireAdminFromInitData(req);
  if (!auth.ok) return res.status(auth.status).json({ ok: false, message: auth.message });

  try {
    await pool.query(`UPDATE promo_codes SET active = FALSE WHERE code = $1`, [req.params.code.toUpperCase()]);
    return res.json({ ok: true, message: 'Promo code deactivated.' });
  } catch (error) {
    return res.status(500).json({ ok: false, message: error.message });
  }
});


// =========================================================
// ADMIN — WITHDRAWAL REQUESTS
// =========================================================

app.get('/api/admin/withdrawals', async (req, res) => {
  const auth = requireAdminFromInitData(req);
  if (!auth.ok) return res.status(auth.status).json({ ok: false, message: auth.message });

  try {
    await initDatabase();
    const status = req.query.status || 'pending';
    const result = await pool.query(
      `SELECT * FROM withdrawals WHERE status = $1 ORDER BY created_at ASC LIMIT 200`,
      [status]
    );
    return res.json({ ok: true, withdrawals: result.rows });
  } catch (error) {
    return res.status(500).json({ ok: false, message: error.message });
  }
});

app.post('/api/admin/withdrawals/:id/decide', async (req, res) => {
  const auth = requireAdminFromInitData(req);
  if (!auth.ok) return res.status(auth.status).json({ ok: false, message: auth.message });

  try {
    await initDatabase();
    const id = Number(req.params.id);
    const decision = String(req.body?.decision || '').toLowerCase(); // paid | rejected

    if (!['paid', 'rejected'].includes(decision)) {
      return res.status(400).json({ ok: false, message: "decision must be 'paid' or 'rejected'." });
    }

    const result = await pool.query(
      `UPDATE withdrawals SET status = $2, decided_at = NOW() WHERE id = $1 RETURNING *`,
      [id, decision]
    );
    const withdrawal = result.rows[0];
    if (!withdrawal) return res.status(404).json({ ok: false, message: 'Withdrawal not found.' });

    // If rejected, refund the coins back to the user.
    if (decision === 'rejected') {
      await addCoins(withdrawal.telegram_id, 'coins_task', withdrawal.coins);
    }

    await sendTelegramMessage(
      withdrawal.telegram_id,
      decision === 'paid'
        ? `✅ Your withdrawal of ${withdrawal.birr} ETB (${withdrawal.method}) has been paid.`
        : `❌ Your withdrawal request was rejected and your ${withdrawal.coins} coins were refunded.`
    ).catch(() => {});

    return res.json({ ok: true, withdrawal });
  } catch (error) {
    return res.status(500).json({ ok: false, message: error.message });
  }
});


// =========================================================
// ADMIN — BROADCAST
// =========================================================

app.post('/api/admin/broadcast', async (req, res) => {
  const auth = requireAdminFromInitData(req);
  if (!auth.ok) return res.status(auth.status).json({ ok: false, message: auth.message });

  try {
    await initDatabase();
    const text = String(req.body?.text || '').trim();
    if (!text) return res.status(400).json({ ok: false, message: 'text is required.' });

    const users = await pool.query(`SELECT telegram_id FROM fraud_users WHERE status = 'verified'`);

    let sent = 0;
    for (const u of users.rows) {
      const ok = await sendTelegramMessage(u.telegram_id, text);
      if (ok) sent++;
    }

    return res.json({ ok: true, sent, total: users.rows.length });
  } catch (error) {
    return res.status(500).json({ ok: false, message: error.message });
  }
});


// =========================================================
// LOCAL SERVER
// =========================================================

if (
  require.main === module
) {

  initDatabase()

    .then(() =>
      setupWebhook()
    )

    .then(() => {

      app.listen(
        PORT,
        () => {

          console.log(
            `Adewa server running on port ${PORT}`
          );
        }
      );

    })

    .catch((error) => {

      console.error(
        'Startup error:',
        error
      );

      process.exit(1);
    });
}


// =========================================================
// VERCEL
// =========================================================

if (
  process.env.VERCEL ||
  process.env.VERCEL_ENV
) {

  setupWebhook()
    .catch(() => {});
}


module.exports = app;
