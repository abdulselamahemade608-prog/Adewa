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

// ---------------------------------------------------------
// CHANNELS — configured on Vercel (env var CHANNELS), not
// hardcoded. Set it as a JSON array, e.g.:
//
// [
//   {"id":"@adewa_channel1","url":"https://t.me/adewa_channel1","title":"Adewa Channel 1"},
//   {"id":"@adewa_channel2","url":"https://t.me/adewa_channel2","title":"Adewa Channel 2"},
//   {"id":"-1001234567890","url":"https://t.me/+xxxxxxxx","title":"Adewa VIP Group"}
// ]
//
// "id" is what the bot uses to call getChatMember (public
// channels: @username; private channels/groups: numeric
// chat_id, and the bot MUST be an admin in that channel).
// "url" is only for the join button.
// ---------------------------------------------------------

function parseChannels(raw) {

  if (!raw) {
    console.warn(
      'WARNING: CHANNELS env var is not set — no channels will be enforced.'
    );
    return [];
  }

  try {

    const parsed = JSON.parse(raw);

    if (!Array.isArray(parsed)) {
      throw new Error('CHANNELS must be a JSON array');
    }

    return parsed.filter((c) => c && c.id && c.url && c.title);

  } catch (error) {

    console.error(
      'WARNING: could not parse CHANNELS env var, ignoring it:',
      error.message
    );

    return [];
  }
}

const CHANNELS = parseChannels(process.env.CHANNELS);

// ---------------------------------------------------------
// ADMINS — configured on Vercel (env var ADMIN_IDS), a
// comma-separated list of Telegram numeric user IDs, e.g.
// ADMIN_IDS=111111111,222222222
// ---------------------------------------------------------

function parseAdminIds(raw) {

  if (!raw) {
    console.warn(
      'WARNING: ADMIN_IDS env var is not set — no one can use /ban, /unban.'
    );
    return [];
  }

  return raw
    .split(',')
    .map((v) => Number(v.trim()))
    .filter((v) => Number.isFinite(v));
}

const ADMIN_IDS = parseAdminIds(process.env.ADMIN_IDS);

function isAdmin(userId) {
  return ADMIN_IDS.includes(Number(userId));
}

// ---------------------------------------------------------
// Secret required to call the /api/admin/* HTTP endpoints.
// Set ADMIN_API_SECRET on Vercel and send it as the
// "x-admin-secret" header. Without this, those endpoints
// are open to anyone who finds the URL.
// ---------------------------------------------------------

const ADMIN_API_SECRET = process.env.ADMIN_API_SECRET || '';

if (!ADMIN_API_SECRET) {
  console.warn(
    'WARNING: ADMIN_API_SECRET is not set — /api/admin/* endpoints are UNPROTECTED.'
  );
}

function requireAdminSecret(req, res, next) {

  const provided = req.headers['x-admin-secret'];

  if (!ADMIN_API_SECRET || provided !== ADMIN_API_SECRET) {

    return res.status(401).json({
      ok: false,
      error: 'Unauthorized'
    });
  }

  next();
}


// =========================================================
// BASIC CHECK
// =========================================================

if (!BOT_TOKEN) {
  console.warn('WARNING: BOT_TOKEN is not configured.');
}

if (!DATABASE_URL) {
  console.warn('WARNING: DATABASE_URL is not configured.');
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
    reason.includes('multiple') ||
    reason.includes('multi account') ||
    reason.includes('same device') ||
    reason.includes('same ip')
  ) {
    return 'multi';
  }

  if (
    reason.includes('vpn') ||
    reason.includes('proxy') ||
    reason.includes('tor')
  ) {
    return 'vpn';
  }

  return 'other';
}


// =========================================================
// CHANNEL GATE (mandatory join before the Mini App opens)
// =========================================================

function buildChannelsKeyboard(channels) {

  const rows = channels.map((ch) => ([
    {
      text: `📢 ${ch.title}`,
      url: ch.url
    }
  ]));

  rows.push([
    {
      text: '✅ ተቀላቅያለሁ (Joined)',
      callback_data: 'check_joined'
    }
  ]);

  return rows;
}

function buildWelcomeText(firstName) {

  return (
    `👋 ውድ ${firstName}፣ እንኳን ወደ Adewa Mini App በደህና መጡ!\n\n` +
    `ለመቀጠል እባክዎ ከዚህ በታች ያሉትን ቻናሎች በሙሉ ይቀላቀሉ፣ ከዚያ "✅ ተቀላቅያለሁ" የሚለውን ይጫኑ።`
  );
}

async function sendChannelGate(chatId, firstName, channelsToShow) {

  if (channelsToShow.length === 0) {

    // No channels configured — nothing to gate on.
    return sendTelegramMessage(
      chatId,
      '⚠️ No channels are configured yet. Contact the admin.'
    );
  }

  return sendTelegramMessage(
    chatId,
    buildWelcomeText(firstName),
    {
      reply_markup: {
        inline_keyboard: buildChannelsKeyboard(channelsToShow)
      }
    }
  );
}

async function sendOpenAppMessage(chatId, firstName) {

  return sendTelegramMessage(
    chatId,
    `✅ ${firstName}፣ ተረጋግጠዋል! ወደ Adewa Mini App ለመግባት ከታች ይጫኑ።`,
    {
      reply_markup: {
        inline_keyboard: [
          [
            {
              text: '🚀 OPEN ADEWA',
              web_app: {
                url: MINI_APP_URL
              }
            }
          ]
        ]
      }
    }
  );
}

async function checkChannelMembership(userId) {

  const missing = [];

  for (const channel of CHANNELS) {

    try {

      const result = await telegram(
        'getChatMember',
        {
          chat_id: channel.id,
          user_id: userId
        }
      );

      const status = result.result?.status;

      const isMember = [
        'member',
        'administrator',
        'creator'
      ].includes(status);

      if (!isMember) {
        missing.push(channel);
      }

    } catch (error) {

      // If the bot cannot check (not an admin in that
      // channel, wrong id, etc.) treat it as "not joined"
      // rather than silently letting the user through.
      console.error(
        `getChatMember failed for ${channel.id}:`,
        error.message
      );

      missing.push(channel);
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

    '✅ Your verification was successful.'
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
      'Content-Type, x-init-data, x-device, x-admin-secret'
    );

    res.setHeader(
      'Access-Control-Allow-Methods',
      'GET,POST,OPTIONS'
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
// CALLBACK QUERY HANDLER ("✅ Joined" button)
// =========================================================

async function handleCallbackQuery(callbackQuery) {

  const data = callbackQuery.data;

  const chatId = callbackQuery.message?.chat?.id;

  const userId = callbackQuery.from?.id;

  const firstName =
    callbackQuery.from?.first_name || 'there';

  if (!chatId || !userId) {
    return;
  }

  // Acknowledge the tap right away so the button stops spinning.
  await telegram(
    'answerCallbackQuery',
    { callback_query_id: callbackQuery.id }
  ).catch(() => {});

  if (data !== 'check_joined') {
    return;
  }

  await initDatabase();

  // -------------------------------------------------------
  // 1) Banned users never get past this gate, regardless
  //    of channel membership.
  // -------------------------------------------------------

  const existing = await pool.query(
    `
    SELECT status, ban_reason
    FROM fraud_users
    WHERE telegram_id = $1
    LIMIT 1
    `,
    [userId]
  );

  if (
    existing.rows.length > 0 &&
    existing.rows[0].status === 'banned'
  ) {

    const banType = getBanType(existing.rows[0].ban_reason);

    await sendBanMessage(chatId, banType);

    return;
  }

  // -------------------------------------------------------
  // 2) Channel membership check
  // -------------------------------------------------------

  const membership = await checkChannelMembership(userId);

  if (!membership.allJoined) {

    await sendTelegramMessage(
      chatId,
      '⚠️ ገና ሁሉንም ቻናሎች አልተቀላቀሉም። እባክዎ ከዚህ በታች ያሉትን ይቀላቀሉ፣ ከዚያ ደግመው ይሞክሩ፦',
      {
        reply_markup: {
          inline_keyboard: buildChannelsKeyboard(membership.missing)
        }
      }
    );

    return;
  }

  // -------------------------------------------------------
  // 3) All channels joined and not banned → open Mini App
  // -------------------------------------------------------

  await sendOpenAppMessage(chatId, firstName);
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

      // ===================================================
      // BUTTON TAPS ("✅ Joined")
      // ===================================================

      if (update.callback_query) {

        await handleCallbackQuery(
          update.callback_query
        );

        return res.sendStatus(200);
      }

      if (!update.message) {
        return res.sendStatus(200);
      }

      const message = update.message;

      const chatId = message.chat?.id;

      const fromId = message.from?.id;

      const text =
        typeof message.text === 'string'
          ? message.text.trim()
          : '';

      if (!chatId) {
        return res.sendStatus(200);
      }

      // ===================================================
      // ADMIN: /ban <telegram_id> [reason]
      // ===================================================

      if (text.startsWith('/ban')) {

        if (!isAdmin(fromId)) {
          return res.sendStatus(200);
        }

        await initDatabase();

        const parts = text.split(/\s+/);
        const targetId = Number(parts[1]);

        if (!targetId) {

          await sendTelegramMessage(
            chatId,
            'Usage: /ban <telegram_id> [reason]'
          );

          return res.sendStatus(200);
        }

        const reason =
          parts.slice(2).join(' ') || 'Admin ban';

        await pool.query(
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
          `,
          [targetId, reason]
        );

        await sendTelegramMessage(
          chatId,
          `🚫 User ${targetId} has been banned. Reason: ${reason}`
        );

        await sendBanMessage(
          targetId,
          getBanType(reason)
        ).catch(() => {});

        return res.sendStatus(200);
      }

      // ===================================================
      // ADMIN: /unban <telegram_id>
      // ===================================================

      if (text.startsWith('/unban')) {

        if (!isAdmin(fromId)) {
          return res.sendStatus(200);
        }

        await initDatabase();

        const parts = text.split(/\s+/);
        const targetId = Number(parts[1]);

        if (!targetId) {

          await sendTelegramMessage(
            chatId,
            'Usage: /unban <telegram_id>'
          );

          return res.sendStatus(200);
        }

        await pool.query(
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
          `,
          [targetId]
        );

        await sendTelegramMessage(
          chatId,
          `✅ User ${targetId} has been unbanned.`
        );

        // Send them straight to the Mini App.
        await sendOpenAppMessage(targetId, 'there').catch(() => {});

        return res.sendStatus(200);
      }

      // ===================================================
      // /START — always shows the mandatory-channel gate.
      // Ban status is only checked once they tap "Joined"
      // (see handleCallbackQuery above), so banned users
      // never make it past this screen either way.
      // ===================================================

      if (
        text === '/start' ||
        text.startsWith('/start ')
      ) {

        await initDatabase();

        const firstName =
          message.from?.first_name || 'there';

        await sendChannelGate(chatId, firstName, CHANNELS);

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
      // RUN BOTH CHECKS
      // ===================================================

      const networkCheck =
        await detectVPNProxy(ip);

      const multiAccount =
        await detectMultiAccount(
          telegramId,
          ipHash,
          deviceHash
        );

      // ===================================================
      // MULTI ACCOUNT BAN — checked FIRST.
      //
      // A normal user being on a VPN by itself isn't
      // unusual, but a Telegram account sharing a device
      // or IP with another already-verified account is the
      // serious signal, so it takes priority.
      // ===================================================

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

        // -----------------------------------------------
        // Direct Telegram message
        // -----------------------------------------------

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
      // VPN / PROXY BAN — checked SECOND.
      // ===================================================

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

        // -----------------------------------------------
        // Direct Telegram message
        // -----------------------------------------------

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

        message:
          'Your verification was successful.'
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
// ADMIN GET USER  (now requires x-admin-secret header)
// =========================================================

app.get(
  '/api/admin/user/:id',
  requireAdminSecret,
  async (req, res) => {

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
// ADMIN BAN  (now requires x-admin-secret header)
// =========================================================

app.post(
  '/api/admin/ban/:id',
  requireAdminSecret,
  async (req, res) => {

    try {

      await initDatabase();

      const id =
        Number(req.params.id);

      await pool.query(
        `
        UPDATE fraud_users
        SET
          status = 'banned',
          ban_reason = 'Admin ban',
          last_seen = NOW()
        WHERE telegram_id = $1
        `,
        [id]
      );

      return res.json({

        ok: true,

        message:
          'User permanently banned.'
      });

    } catch (error) {

      console.error(
        'Admin ban error:',
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
// ADMIN UNBAN  (now requires x-admin-secret header)
// =========================================================

app.post(
  '/api/admin/unban/:id',
  requireAdminSecret,
  async (req, res) => {

    try {

      await initDatabase();

      const id =
        Number(req.params.id);

      await pool.query(
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
        `,
        [id]
      );

      return res.json({

        ok: true,

        message:
          'User unbanned.'
      });

    } catch (error) {

      console.error(
        'Admin unban error:',
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
