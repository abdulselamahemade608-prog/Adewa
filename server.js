'use strict';

import express from 'express';
import crypto from 'crypto';
import pg from 'pg';

const { Pool } = pg;

const app = express();

app.use(express.json({ limit: '100kb' }));

/*
=========================================================
ENVIRONMENT VARIABLES

BOT_TOKEN=YOUR_TELEGRAM_BOT_TOKEN
DATABASE_URL=YOUR_POSTGRES_CONNECTION_STRING
PORT=3000
=========================================================
*/

const BOT_TOKEN = process.env.BOT_TOKEN;
const DATABASE_URL = process.env.DATABASE_URL;
const PORT = process.env.PORT || 3000;

if (!BOT_TOKEN) {
  throw new Error('BOT_TOKEN is missing');
}

if (!DATABASE_URL) {
  throw new Error('DATABASE_URL is missing');
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

/*
=========================================================
DATABASE
=========================================================
*/

async function createTables() {
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

      status TEXT NOT NULL DEFAULT 'active',

      ban_reason TEXT DEFAULT '',

      first_seen TIMESTAMPTZ DEFAULT NOW(),
      last_seen TIMESTAMPTZ DEFAULT NOW(),

      request_count INTEGER DEFAULT 0
    );
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_fraud_ip
    ON fraud_users(ip_hash);
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_fraud_device
    ON fraud_users(device_hash);
  `);

  console.log('Database ready');
}

/*
=========================================================
HASH
=========================================================
*/

function sha256(value) {
  return crypto
    .createHash('sha256')
    .update(String(value))
    .digest('hex');
}

/*
=========================================================
GET CLIENT IP
=========================================================
*/

function getClientIP(req) {
  const forwarded = req.headers['x-forwarded-for'];

  if (forwarded) {
    return forwarded.split(',')[0].trim();
  }

  return (
    req.headers['x-real-ip'] ||
    req.socket.remoteAddress ||
    ''
  );
}

/*
=========================================================
TELEGRAM INIT DATA VERIFICATION

Telegram Mini App sends:

Authorization: tma <initData>

or

x-init-data: <initData>
=========================================================
*/

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

    const a = Buffer.from(calculatedHash, 'hex');
    const b = Buffer.from(receivedHash, 'hex');

    if (
      a.length !== b.length ||
      !crypto.timingSafeEqual(a, b)
    ) {
      return null;
    }

    const userRaw = params.get('user');

    if (!userRaw) {
      return null;
    }

    const user = JSON.parse(userRaw);

    if (!user.id) {
      return null;
    }

    return user;

  } catch (error) {
    console.error('initData verification error:', error);
    return null;
  }
}

/*
=========================================================
AUTH MIDDLEWARE
=========================================================
*/

async function authenticate(req, res, next) {

  const initData =
    req.headers['x-init-data'] ||
    req.headers.authorization?.replace(/^tma\s+/i, '');

  const user = verifyTelegramInitData(initData);

  if (!user) {
    return res.status(401).json({
      ok: false,
      error: 'Invalid Telegram authentication'
    });
  }

  req.telegramUser = user;

  next();
}

/*
=========================================================
DEVICE HASH

IMPORTANT:
The client should send a random installation ID.

Example:

x-device: random-installation-id
=========================================================
*/

function getDeviceHash(req) {

  const deviceId =
    req.headers['x-device'] ||
    '';

  if (!deviceId) {
    return '';
  }

  return sha256(deviceId);
}

/*
=========================================================
FRAUD ANALYSIS
=========================================================
*/

async function analyzeUser(req, user) {

  const ip = getClientIP(req);

  const ipHash = sha256(ip);

  const deviceHash = getDeviceHash(req);

  let score = 0;

  let reasons = [];

  /*
  -------------------------------------------------------
  CHECK SAME IP
  -------------------------------------------------------
  */

  const sameIP = await pool.query(
    `
    SELECT COUNT(*)::int AS count
    FROM fraud_users
    WHERE ip_hash = $1
    `,
    [ipHash]
  );

  const ipUsers = sameIP.rows[0].count;

  if (ipUsers >= 3) {

    score += 20;

    reasons.push(
      `Multiple accounts from same IP: ${ipUsers}`
    );
  }

  if (ipUsers >= 8) {

    score += 30;

    reasons.push(
      'Very high account concentration on IP'
    );
  }

  /*
  -------------------------------------------------------
  CHECK SAME DEVICE
  -------------------------------------------------------
  */

  if (deviceHash) {

    const sameDevice = await pool.query(
      `
      SELECT COUNT(*)::int AS count
      FROM fraud_users
      WHERE device_hash = $1
      `,
      [deviceHash]
    );

    const deviceUsers =
      sameDevice.rows[0].count;

    if (deviceUsers >= 2) {

      score += 40;

      reasons.push(
        `Multiple accounts from same device: ${deviceUsers}`
      );
    }

    if (deviceUsers >= 4) {

      score += 40;

      reasons.push(
        'Very high account concentration on device'
      );
    }
  }

  /*
  -------------------------------------------------------
  CHECK USER
  -------------------------------------------------------
  */

  const existing = await pool.query(
    `
    SELECT *
    FROM fraud_users
    WHERE telegram_id = $1
    `,
    [user.id]
  );

  /*
  -------------------------------------------------------
  STATUS
  -------------------------------------------------------
  */

  let status = 'active';

  if (score >= 80) {
    status = 'banned';
  } else if (score >= 50) {
    status = 'restricted';
  } else if (score >= 30) {
    status = 'review';
  }

  /*
  -------------------------------------------------------
  SAVE
  -------------------------------------------------------
  */

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
      ban_reason,
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
      $8,
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

      ban_reason = EXCLUDED.ban_reason,

      last_seen = NOW(),

      request_count =
        fraud_users.request_count + 1
    `,
    [
      user.id,
      user.username || '',
      user.first_name || '',
      ipHash,
      deviceHash,
      score,
      status,
      reasons.join('; ')
    ]
  );

  return {
    score,
    status,
    reasons
  };
}

/*
=========================================================
START
=========================================================
*/

app.get('/', (req, res) => {

  res.json({
    ok: true,
    app: 'Telegram Mini App Anti-Fraud'
  });

});

/*
=========================================================
CHECK USER

POST /api/auth
=========================================================
*/

app.post('/api/auth', authenticate, async (req, res) => {

  try {

    const user = req.telegramUser;

    const fraud = await analyzeUser(
      req,
      user
    );

    /*
    -----------------------------------------------------
    BANNED
    -----------------------------------------------------
    */

    if (fraud.status === 'banned') {

      return res.status(403).json({

        ok: false,

        banned: true,

        status: 'banned',

        message:
          'Your account has been blocked because suspicious activity was detected.'
      });

    }

    /*
    -----------------------------------------------------
    RESTRICTED
    -----------------------------------------------------
    */

    if (fraud.status === 'restricted') {

      return res.status(403).json({

        ok: false,

        restricted: true,

        status: 'restricted',

        message:
          'Your account is temporarily restricted for security review.'
      });

    }

    /*
    -----------------------------------------------------
    NORMAL
    -----------------------------------------------------
    */

    return res.json({

      ok: true,

      user: {
        id: user.id,
        username: user.username || '',
        first_name: user.first_name || ''
      },

      security: {

        risk_score: fraud.score,

        status: fraud.status

      }

    });

  } catch (error) {

    console.error(error);

    res.status(500).json({

      ok: false,

      error: 'Internal server error'

    });

  }

});

/*
=========================================================
ADMIN: USER STATUS
=========================================================
*/

app.get('/api/admin/user/:id', async (req, res) => {

  try {

    const id = req.params.id;

    const result = await pool.query(
      `
      SELECT
        telegram_id,
        username,
        first_name,
        risk_score,
        status,
        ban_reason,
        vpn_detected,
        proxy_detected,
        first_seen,
        last_seen,
        request_count
      FROM fraud_users
      WHERE telegram_id = $1
      `,
      [id]
    );

    if (result.rows.length === 0) {

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

      error: 'Internal server error'

    });

  }

});

/*
=========================================================
ADMIN: BAN
=========================================================
*/

app.post('/api/admin/ban/:id', async (req, res) => {

  try {

    const id = req.params.id;

    const reason =
      req.body.reason ||
      'Manual security ban';

    await pool.query(
      `
      UPDATE fraud_users
      SET
        status = 'banned',
        ban_reason = $2
      WHERE telegram_id = $1
      `,
      [id, reason]
    );

    res.json({

      ok: true,

      message: 'User banned'

    });

  } catch (error) {

    console.error(error);

    res.status(500).json({

      ok: false,

      error: 'Internal server error'

    });

  }

});

/*
=========================================================
ADMIN: UNBAN
=========================================================
*/

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

      error: 'Internal server error'

    });

  }

});

/*
=========================================================
SERVER
=========================================================
*/

createTables()
  .then(() => {

    app.listen(PORT, () => {

      console.log(
        `Server running on port ${PORT}`
      );

    });

  })
  .catch(error => {

    console.error(
      'Database startup failed:',
      error
    );

    process.exit(1);

  });
