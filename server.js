'use strict';

const express = require('express');
const crypto = require('crypto');
const { Pool } = require('pg');

const app = express();

app.use(express.json());

/* =========================================================
   CONFIG
========================================================= */

const BOT_TOKEN = process.env.BOT_TOKEN;
const DATABASE_URL = process.env.DATABASE_URL;

const MINI_APP_URL =
  'https://abdulselamahemade608-prog.github.io/Adewa-frontend/';

const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET || 'adewa_webhook_secret';

/* =========================================================
   DATABASE
========================================================= */

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

/* =========================================================
   CORS
========================================================= */

app.use((req, res, next) => {
  res.setHeader(
    'Access-Control-Allow-Origin',
    'https://abdulselamahemade608-prog.github.io'
  );

  res.setHeader(
    'Access-Control-Allow-Headers',
    'Content-Type, x-init-data, x-device'
  );

  res.setHeader(
    'Access-Control-Allow-Methods',
    'GET, POST, OPTIONS'
  );

  if (req.method === 'OPTIONS') {
    return res.sendStatus(204);
  }

  next();
});

/* =========================================================
   TELEGRAM API
========================================================= */

async function telegram(method, data) {
  if (!BOT_TOKEN) {
    throw new Error('BOT_TOKEN is missing');
  }

  const response = await fetch(
    `https://api.telegram.org/bot${BOT_TOKEN}/${method}`,
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
      result.description || 'Telegram API error'
    );
  }

  return result;
}

/* =========================================================
   TELEGRAM INIT DATA VERIFICATION
========================================================= */

function verifyTelegramInitData(initData) {
  if (!initData || !BOT_TOKEN) {
    return null;
  }

  try {
    const params = new URLSearchParams(initData);

    const receivedHash = params.get('hash');

    if (!receivedHash) {
      return null;
    }

    params.delete('hash');

    const dataCheckString = [...params.entries()]
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, value]) => `${key}=${value}`)
      .join('\n');

    const secretKey = crypto
      .createHmac('sha256', 'WebAppData')
      .update(BOT_TOKEN)
      .digest();

    const calculatedHash = crypto
      .createHmac('sha256', secretKey)
      .update(dataCheckString)
      .digest('hex');

    if (calculatedHash !== receivedHash) {
      return null;
    }

    const userRaw = params.get('user');

    if (!userRaw) {
      return null;
    }

    return JSON.parse(userRaw);

  } catch (error) {
    console.error('InitData verification error:', error);
    return null;
  }
}

/* =========================================================
   DATABASE TABLE
========================================================= */

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS fraud_users (
      telegram_id BIGINT PRIMARY KEY,
      username TEXT DEFAULT '',
      first_name TEXT DEFAULT '',
      ip_hash TEXT DEFAULT '',
      device_hash TEXT DEFAULT '',
      vpn_detected BOOLEAN DEFAULT FALSE,
      proxy_detected BOOLEAN DEFAULT FALSE,
      risk_score INTEGER DEFAULT 0,
      status TEXT DEFAULT 'active',
      ban_reason TEXT DEFAULT '',
      first_seen TIMESTAMPTZ DEFAULT NOW(),
      last_seen TIMESTAMPTZ DEFAULT NOW(),
      request_count INTEGER DEFAULT 0
    )
  `);
}

/* =========================================================
   HASH
========================================================= */

function hashValue(value) {
  return crypto
    .createHash('sha256')
    .update(String(value || ''))
    .digest('hex');
}

/* =========================================================
   IP
========================================================= */

function getClientIP(req) {
  const forwarded = req.headers['x-forwarded-for'];

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

/* =========================================================
   HOME
========================================================= */

app.get('/', (req, res) => {
  res.json({
    ok: true,
    app: 'Adewa Telegram Mini App',
    status: 'online'
  });
});

/* =========================================================
   AUTH
========================================================= */

app.post('/api/auth', async (req, res) => {
  try {
    const initData = req.headers['x-init-data'];
    const deviceId = req.headers['x-device'] || '';

    const telegramUser =
      verifyTelegramInitData(initData);

    if (!telegramUser) {
      return res.status(401).json({
        ok: false,
        error: 'Invalid Telegram authentication'
      });
    }

    const telegramId = Number(telegramUser.id);

    if (!telegramId) {
      return res.status(400).json({
        ok: false,
        error: 'Invalid Telegram user'
      });
    }

    const username = telegramUser.username || '';
    const firstName = telegramUser.first_name || '';

    const ip = getClientIP(req);

    const ipHash = hashValue(ip);
    const deviceHash = hashValue(deviceId);

    const existing = await pool.query(
      `
      SELECT *
      FROM fraud_users
      WHERE telegram_id = $1
      `,
      [telegramId]
    );

    let riskScore = 0;

    /* =====================================================
       CHECK SAME IP
    ===================================================== */

    const sameIP = await pool.query(
      `
      SELECT COUNT(*)
      FROM fraud_users
      WHERE ip_hash = $1
      `,
      [ipHash]
    );

    const ipCount = Number(
      sameIP.rows[0].count || 0
    );

    if (ipCount >= 8) {
      riskScore += 30;
    } else if (ipCount >= 3) {
      riskScore += 20;
    }

    /* =====================================================
       CHECK SAME DEVICE
    ===================================================== */

    const sameDevice = await pool.query(
      `
      SELECT COUNT(*)
      FROM fraud_users
      WHERE device_hash = $1
      `,
      [deviceHash]
    );

    const deviceCount = Number(
      sameDevice.rows[0].count || 0
    );

    if (deviceCount >= 4) {
      riskScore += 40;
    } else if (deviceCount >= 2) {
      riskScore += 40;
    }

    /* =====================================================
       STATUS
    ===================================================== */

    let status = 'active';

    if (riskScore >= 80) {
      status = 'banned';
    } else if (riskScore >= 50) {
      status = 'restricted';
    } else if (riskScore >= 30) {
      status = 'review';
    }

    /* =====================================================
       SAVE USER
    ===================================================== */

    await pool.query(
      `
      INSERT INTO fraud_users (
        telegram_id,
        username,
        first_name,
        ip_hash,
        device_hash,
        risk_score,
        status,
        last_seen,
        request_count
      )
      VALUES (
        $1,
        $2,
        $3,
        $4,
        $5,
        $6,
        $7,
        NOW(),
        1
      )
      ON CONFLICT (telegram_id)
      DO UPDATE SET
        username = EXCLUDED.username,
        first_name = EXCLUDED.first_name,
        ip_hash = EXCLUDED.ip_hash,
        device_hash = EXCLUDED.device_hash,
        risk_score = EXCLUDED.risk_score,
        status = EXCLUDED.status,
        last_seen = NOW(),
        request_count =
          fraud_users.request_count + 1
      `,
      [
        telegramId,
        username,
        firstName,
        ipHash,
        deviceHash,
        riskScore,
        status
      ]
    );

    /* =====================================================
       RESPONSE
    ===================================================== */

    return res.json({
      ok: true,
      user: {
        id: telegramId,
        username,
        first_name: firstName
      },
      security: {
        risk_score: riskScore,
        status
      }
    });

  } catch (error) {
    console.error('AUTH ERROR:', error);

    return res.status(500).json({
      ok: false,
      error: 'Server error'
    });
  }
});

/* =========================================================
   TELEGRAM WEBHOOK
========================================================= */

app.post('/telegram/webhook', async (req, res) => {
  try {

    const secret =
      req.headers['x-telegram-bot-api-secret-token'];

    if (secret !== WEBHOOK_SECRET) {
      return res.sendStatus(403);
    }

    const update = req.body;

    const message = update?.message;

    if (!message) {
      return res.sendStatus(200);
    }

    const chatId = message.chat?.id;

    const text =
      message.text || '';

    /* =====================================================
       /START
    ===================================================== */

    if (/^\/start(?:@\w+)?(?:\s.*)?$/i.test(text)) {

      const firstName =
        message.from?.first_name || 'User';

      await telegram('sendMessage', {
        chat_id: chatId,

        text:
          `👋 Hello ${firstName}!\n\n` +
          `💰 Welcome to Adewa.\n\n` +
          `Complete tasks, surveys and ads ` +
          `and earn rewards.\n\n` +
          `👇 Open the Mini App:`,

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
      });
    }

    return res.sendStatus(200);

  } catch (error) {

    console.error(
      'TELEGRAM WEBHOOK ERROR:',
      error
    );

    return res.sendStatus(200);
  }
});

/* =========================================================
   ADMIN USER
========================================================= */

app.get('/api/admin/user/:id', async (req, res) => {
  try {

    const id = req.params.id;

    const result = await pool.query(
      `
      SELECT
        telegram_id,
        username,
        first_name,
        vpn_detected,
        proxy_detected,
        risk_score,
        status,
        ban_reason,
        first_seen,
        last_seen,
        request_count
      FROM fraud_users
      WHERE telegram_id = $1
      `,
      [id]
    );

    if (!result.rows.length) {
      return res.status(404).json({
        ok: false,
        error: 'User not found'
      });
    }

    res.json({
      ok: true,
      user: result.rows[0]
    });

  } catch (error) {

    console.error(error);

    res.status(500).json({
      ok: false,
      error: 'Server error'
    });
  }
});

/* =========================================================
   ADMIN BAN
========================================================= */

app.post('/api/admin/ban/:id', async (req, res) => {

  try {

    const id = req.params.id;

    await pool.query(
      `
      UPDATE fraud_users
      SET
        status = 'banned',
        ban_reason = $2
      WHERE telegram_id = $1
      `,
      [
        id,
        req.body?.reason || 'Manual ban'
      ]
    );

    res.json({
      ok: true,
      message: 'User banned'
    });

  } catch (error) {

    console.error(error);

    res.status(500).json({
      ok: false,
      error: 'Server error'
    });
  }
});

/* =========================================================
   ADMIN UNBAN
========================================================= */

app.post('/api/admin/unban/:id', async (req, res) => {

  try {

    const id = req.params.id;

    await pool.query(
      `
      UPDATE fraud_users
      SET
        status = 'active',
        ban_reason = ''
      WHERE telegram_id = $1
      `,
      [id]
    );

    res.json({
      ok: true,
      message: 'User unbanned'
    });

  } catch (error) {

    console.error(error);

    res.status(500).json({
      ok: false,
      error: 'Server error'
    });
  }
});

/* =========================================================
   START SERVER
========================================================= */

const PORT = process.env.PORT || 3000;

if (require.main === module) {

  initDatabase()
    .then(() => {

      app.listen(PORT, () => {
        console.log(
          `Adewa server running on port ${PORT}`
        );
      });

    })
    .catch((error) => {

      console.error(
        'DATABASE INIT ERROR:',
        error
      );

      process.exit(1);
    });
}

module.exports = app;
