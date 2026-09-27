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

const MINI_APP_URL =
  'https://abdulselamahemade608-prog.github.io/Adewa-frontend/';

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


// =========================================================
// BAN / UNBAN (shared by admin API and bot commands)
// =========================================================

async function banUserById(telegramId, reason) {

  await initDatabase();

  const result = await pool.query(
    `
    INSERT INTO fraud_users (
      telegram_id, status, ban_reason, last_seen, request_count
    )
    VALUES ($1, 'banned', $2, NOW(), 1)

    ON CONFLICT (telegram_id)
    DO UPDATE SET
      status = 'banned',
      ban_reason = EXCLUDED.ban_reason,
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


// =====================
