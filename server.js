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

// Comma-separated Telegram user IDs allowed to use /ban, /unban, etc.
// Example: ADMIN_IDS=123456789,987654321
const ADMIN_IDS =
  String(process.env.ADMIN_IDS || '')
    .split(',')
    .map((id) => id.trim())
    .filter(Boolean)
    .map(Number);

function isAdmin(telegramId) {
  return ADMIN_IDS.includes(Number(telegramId));
}

const MINI_APP_URL =
  'https://abdulselamahemade608-prog.github.io/Adewa-frontend/';

const WEBHOOK_URL =
  'https://adewa.vercel.app/telegram/webhook';

const TELEGRAM_API =
  `https://api.telegram.org/bot${BOT_TOKEN}`;


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

    // ---------------------------------------------------
    // GATE CHANNELS (channels users must join before the
    // mini app opens). Admin-managed via /api/admin/channels.
    // ---------------------------------------------------

    await pool.query(`
      CREATE TABLE IF NOT EXISTS gate_channels (
        id SERIAL PRIMARY KEY,

        chat_username TEXT NOT NULL,
        title TEXT NOT NULL DEFAULT '',
        invite_link TEXT NOT NULL DEFAULT '',

        position INTEGER NOT NULL DEFAULT 0,
        active BOOLEAN NOT NULL DEFAULT TRUE,

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

async function sendTelegramMessage(chatId, text) {

  try {

    await telegram(
      'sendMessage',
      {
        chat_id: chatId,
        text
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
// BAN / UNBAN HELPERS (used by the /ban and /unban bot
// commands; the existing /api/admin/ban(unban) HTTP routes
// are left untouched)
// =========================================================

async function banUserRecord(telegramId, reason) {

  return pool.query(
    `
    UPDATE fraud_users
    SET
      status = 'banned',
      ban_reason = $2,
      last_seen = NOW()
    WHERE telegram_id = $1
    `,
    [telegramId, reason || 'Admin ban']
  );
}

async function unbanUserRecord(telegramId) {

  return pool.query(
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
    [telegramId]
  );
}


// =========================================================
// GATE CHANNELS (join-before-entry)
// =========================================================

async function getGateChannels() {

  const result =
    await pool.query(
      `
      SELECT *
      FROM gate_channels
      WHERE active = TRUE
      ORDER BY position ASC, id ASC
      `
    );

  return result.rows;
}

function buildChannelKeyboard(channels) {

  const rows =
    channels.map((ch) => ([
      {
        text:
          `📢 ${ch.title || ch.chat_username}`,

        url:
          ch.invite_link ||
          `https://t.me/${String(ch.chat_username).replace(/^@/, '')}`
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

// Sends the "join all channels" gate message.
// Returns false (and sends nothing) when no channels are
// configured yet, so callers can fall back to the old
// direct-to-mini-app behavior.
async function sendChannelGate(chatId, firstName) {

  const channels =
    await getGateChannels();

  if (channels.length === 0) {
    return false;
  }

  await telegram(
    'sendMessage',
    {
      chat_id: chatId,

      text:
        `👋 Welcome ${firstName}!\n\n` +
        `Please join all the channels below, then tap ✅ Joined to continue.`,

      reply_markup:
        buildChannelKeyboard(channels)
    }
  );

  return true;
}

// Checks Telegram membership for every active gate channel.
async function checkUserJoinedAllChannels(userId) {

  const channels =
    await getGateChannels();

  if (channels.length === 0) {
    return { joined: true, missing: [] };
  }

  const missing = [];

  for (const ch of channels) {

    try {

      const result =
        await telegram(
          'getChatMember',
          {
            chat_id: ch.chat_username,
            user_id: userId
          }
        );

      const status =
        result.result?.status;

      const isMember =
        ['member', 'administrator', 'creator']
          .includes(status);

      if (!isMember) {
        missing.push(ch);
      }

    } catch (error) {

      console.error(
        'getChatMember error:',
        ch.chat_username,
        error.message
      );

      // If we can't verify (bot not admin in the channel,
      // wrong username, etc.) treat as not-joined so the
      // gate never silently lets someone through.
      missing.push(ch);
    }
  }

  return {
    joined: missing.length === 0,
    missing
  };
}


// =========================================================
// SUCCESS MESSAGE
// =========================================================

async function sendVerificationSuccess(
  user
) {

  return sendTelegramMessage(

    user.id,

    '✅ Your verification is successfully.'
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
// CALLBACK QUERY HANDLER ("✅ Joined" button, etc.)
// =========================================================

async function handleCallbackQuery(callbackQuery, res) {

  try {

    await initDatabase();

    const data =
      callbackQuery.data;

    const chatId =
      callbackQuery.message?.chat?.id;

    const userId =
      callbackQuery.from?.id;

    const firstName =
      callbackQuery.from?.first_name ||
      'there';

    if (data === 'check_joined') {

      const membership =
        await checkUserJoinedAllChannels(
          userId
        );

      if (!membership.joined) {

        await telegram(
          'answerCallbackQuery',
          {
            callback_query_id:
              callbackQuery.id,

            text:
              '❌ Please join all the channels first, then tap Joined again.',

            show_alert: true
          }
        );

        return res.sendStatus(200);
      }

      // -----------------------------------------------
      // Joined all channels - but banned accounts still
      // cannot reach the mini app.
      // -----------------------------------------------

      const bannedUser =
        await pool.query(
          `
          SELECT
            status,
            ban_reason
          FROM fraud_users
          WHERE telegram_id = $1
          LIMIT 1
          `,
          [userId]
        );

      const isBanned =
        bannedUser.rows.length > 0 &&
        bannedUser.rows[0].status ===
          'banned';

      if (isBanned) {

        await telegram(
          'answerCallbackQuery',
          {
            callback_query_id:
              callbackQuery.id,

            text:
              '🚫 Your account is permanently banned.',

            show_alert: true
          }
        );

        const banType =
          getBanType(
            bannedUser.rows[0]
              .ban_reason
          );

        await sendBanMessage(
          chatId,
          banType
        );

        return res.sendStatus(200);
      }

      // -----------------------------------------------
      // All good - open the mini app.
      // -----------------------------------------------

      await telegram(
        'answerCallbackQuery',
        { callback_query_id: callbackQuery.id }
      );

      await telegram(
        'sendMessage',
        {
          chat_id: chatId,

          text:
            `✅ Great, ${firstName}! You're all set.`,

          reply_markup: {
            inline_keyboard: [
              [
                {
                  text: '🚀 OPEN ADEWA',
                  web_app: { url: MINI_APP_URL }
                }
              ]
            ]
          }
        }
      );

      return res.sendStatus(200);
    }

    // Unknown callback_data - just clear the loading spinner.

    await telegram(
      'answerCallbackQuery',
      { callback_query_id: callbackQuery.id }
    ).catch(() => {});

    return res.sendStatus(200);

  } catch (error) {

    console.error(
      'Callback query error:',
      error
    );

    await telegram(
      'answerCallbackQuery',
      { callback_query_id: callbackQuery.id }
    ).catch(() => {});

    return res.sendStatus(200);
  }
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

      const update =
        req.body;

      // ===================================================
      // CALLBACK QUERY (e.g. the "✅ Joined" button)
      // ===================================================

      if (update && update.callback_query) {

        return handleCallbackQuery(
          update.callback_query,
          res
        );
      }

      if (
        !update ||
        !update.message
      ) {

        return res.sendStatus(200);
      }

      const message =
        update.message;

      const chatId =
        message.chat?.id;

      const text =
        typeof message.text ===
        'string'
          ? message.text.trim()
          : '';

      const lowerText =
        text.toLowerCase();

      if (!chatId) {
        return res.sendStatus(200);
      }

      // ===================================================
      // /BAN <telegram_id> [reason]   (admin only)
      // ===================================================

      if (
        lowerText === '/ban' ||
        lowerText.startsWith('/ban ')
      ) {

        await initDatabase();

        if (!isAdmin(message.from?.id)) {

          await sendTelegramMessage(
            chatId,
            '⛔ You are not authorized to use this command.'
          );

          return res.sendStatus(200);
        }

        const parts =
          text.split(/\s+/);

        const targetId =
          Number(parts[1]);

        const reason =
          parts.slice(2).join(' ') ||
          'Admin ban';

        if (!targetId) {

          await sendTelegramMessage(
            chatId,
            'Usage: /ban <telegram_id> [reason]'
          );

          return res.sendStatus(200);
        }

        await banUserRecord(
          targetId,
          reason
        );

        await sendTelegramMessage(
          chatId,
          `🚫 User ${targetId} has been banned.`
        );

        await sendBanMessage(
          targetId,
          getBanType(reason)
        ).catch(() => {});

        return res.sendStatus(200);
      }

      // ===================================================
      // /UNBAN <telegram_id>   (admin only)
      // ===================================================

      if (
        lowerText === '/unban' ||
        lowerText.startsWith('/unban ')
      ) {

        await initDatabase();

        if (!isAdmin(message.from?.id)) {

          await sendTelegramMessage(
            chatId,
            '⛔ You are not authorized to use this command.'
          );

          return res.sendStatus(200);
        }

        const parts =
          text.split(/\s+/);

        const targetId =
          Number(parts[1]);

        if (!targetId) {

          await sendTelegramMessage(
            chatId,
            'Usage: /unban <telegram_id>'
          );

          return res.sendStatus(200);
        }

        await unbanUserRecord(targetId);

        await sendTelegramMessage(
          chatId,
          `✅ User ${targetId} has been unbanned.`
        );

        // Let the unbanned user straight back in.
        await telegram(
          'sendMessage',
          {
            chat_id: targetId,

            text:
              '✅ You have been unbanned. Tap below to continue.',

            reply_markup: {
              inline_keyboard: [
                [
                  {
                    text: '🚀 OPEN ADEWA',
                    web_app: { url: MINI_APP_URL }
                  }
                ]
              ]
            }
          }
        ).catch(() => {});

        return res.sendStatus(200);
      }

      // ===================================================
      // /START
      // ===================================================

      if (
        text === '/start' ||
        text.startsWith('/start ')
      ) {

        // -----------------------------------------------
        // IMPORTANT:
        // Check database BEFORE opening Mini App.
        // -----------------------------------------------

        await initDatabase();

        const userId =
          message.from?.id;

        const firstName =
          message.from?.first_name ||
          'there';

        // -----------------------------------------------
        // If Telegram user already has a ban, still show
        // the channel gate (per product decision), but a
        // banned user can never reach the mini app even
        // after joining every channel — that block happens
        // in handleCallbackQuery below.
        // -----------------------------------------------

        if (userId) {

          const bannedUser =
            await pool.query(
              `
              SELECT
                status,
                ban_reason
              FROM fraud_users
              WHERE telegram_id = $1
              LIMIT 1
              `,
              [userId]
            );

          if (
            bannedUser.rows.length > 0 &&
            bannedUser.rows[0].status ===
              'banned'
          ) {

            const shownGate =
              await sendChannelGate(
                chatId,
                firstName
              );

            if (!shownGate) {

              // No gate channels configured yet -
              // fall back to the plain ban message.

              const banType =
                getBanType(
                  bannedUser.rows[0]
                    .ban_reason
                );

              await sendBanMessage(
                chatId,
                banType
              );
            }

            return res.sendStatus(200);
          }
        }

        // -----------------------------------------------
        // Normal (not banned) user - join-channels gate
        // -----------------------------------------------

        const shownGate =
          await sendChannelGate(
            chatId,
            firstName
          );

        if (shownGate) {
          return res.sendStatus(200);
        }

        // No gate channels configured - keep the old
        // direct-to-mini-app behavior as a fallback.

        await telegram(
          'sendMessage',
          {

            chat_id:
              chatId,

            text:
              `👋 Hello ${firstName}!\n\n` +
              `Welcome to Adewa Mini App.`,

            reply_markup: {

              inline_keyboard: [

                [

                  {

                    text:
                      '🚀 OPEN ADEWA',

                    web_app: {

                      url:
                        MINI_APP_URL
                    }
                  }

                ]

              ]
            }
          }
        );
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
      // MULTI ACCOUNT CHECK
      // (checked FIRST: a multi-account match should ban
      // even on a connection that would otherwise just
      // look like a normal VPN)
      // ===================================================

      const multiAccount =
        await detectMultiAccount(
          telegramId,
          ipHash,
          deviceHash
        );

      // ===================================================
      // VPN / PROXY CHECK
      // ===================================================

      const networkCheck =
        await detectVPNProxy(ip);

      // ===================================================
      // MULTI ACCOUNT BAN
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
      // VPN / PROXY BAN
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
          'Your verification is successfully.'
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
// ADMIN GET USER
// =========================================================

app.get(
  '/api/admin/user/:id',
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
// ADMIN BAN
// =========================================================

app.post(
  '/api/admin/ban/:id',
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
// ADMIN UNBAN
// =========================================================

app.post(
  '/api/admin/unban/:id',
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
// ADMIN: LIST GATE CHANNELS
// =========================================================

app.get(
  '/api/admin/channels',
  async (req, res) => {

    try {

      await initDatabase();

      const result =
        await pool.query(
          `
          SELECT *
          FROM gate_channels
          ORDER BY position ASC, id ASC
          `
        );

      return res.json({

        ok: true,

        channels:
          result.rows
      });

    } catch (error) {

      console.error(
        'List channels error:',
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
// ADMIN: ADD GATE CHANNEL
// =========================================================

app.post(
  '/api/admin/channels',
  async (req, res) => {

    try {

      await initDatabase();

      const {
        chat_username,
        title,
        invite_link,
        position
      } = req.body || {};

      if (!chat_username) {

        return res.status(400).json({

          ok: false,

          error:
            'chat_username is required'
        });
      }

      const result =
        await pool.query(
          `
          INSERT INTO gate_channels (
            chat_username,
            title,
            invite_link,
            position
          )
          VALUES ($1,$2,$3,$4)
          RETURNING *
          `,
          [
            chat_username,
            title || '',
            invite_link || '',
            Number(position) || 0
          ]
        );

      return res.json({

        ok: true,

        channel:
          result.rows[0]
      });

    } catch (error) {

      console.error(
        'Add channel error:',
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
// ADMIN: UPDATE GATE CHANNEL (edit fields / toggle active)
// =========================================================

app.post(
  '/api/admin/channels/:id',
  async (req, res) => {

    try {

      await initDatabase();

      const id =
        Number(req.params.id);

      const {
        chat_username,
        title,
        invite_link,
        position,
        active
      } = req.body || {};

      const result =
        await pool.query(
          `
          UPDATE gate_channels
          SET
            chat_username =
              COALESCE($2, chat_username),

            title =
              COALESCE($3, title),

            invite_link =
              COALESCE($4, invite_link),

            position =
              COALESCE($5, position),

            active =
              COALESCE($6, active)
          WHERE id = $1
          RETURNING *
          `,
          [
            id,
            chat_username,
            title,
            invite_link,
            position,
            active
          ]
        );

      return res.json({

        ok: true,

        channel:
          result.rows[0] || null
      });

    } catch (error) {

      console.error(
        'Update channel error:',
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
// ADMIN: DELETE GATE CHANNEL
// =========================================================

app.delete(
  '/api/admin/channels/:id',
  async (req, res) => {

    try {

      await initDatabase();

      const id =
        Number(req.params.id);

      await pool.query(
        `
        DELETE FROM gate_channels
        WHERE id = $1
        `,
        [id]
      );

      return res.json({
        ok: true
      });

    } catch (error) {

      console.error(
        'Delete channel error:',
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
