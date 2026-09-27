'use strict';

const express = require('express');
const crypto = require('crypto');
const { Pool } = require('pg');
const cors = require('cors');

const app = express();

app.use(cors());
app.use(express.json({ limit: '2mb' }));

/* =========================================================
   CONFIG
========================================================= */

const PORT = process.env.PORT || 3000;

const BOT_TOKEN =
  process.env.BOT_TOKEN || '';

const DATABASE_URL =
  process.env.DATABASE_URL || '';

const ADMIN_IDS =
  String(process.env.ADMIN_IDS || '')
    .split(',')
    .map(x => x.trim())
    .filter(Boolean);

const PROOF_CHANNEL =
  process.env.PROOF_CHANNEL ||
  '@proof_chnallel';

const WITHDRAW_CHANNEL =
  process.env.WITHDRAW_CHANNEL ||
  '';

const WEBHOOK_SECRET =
  process.env.WEBHOOK_SECRET ||
  'adewa_webhook_secret';

const CRON_SECRET =
  process.env.CRON_SECRET ||
  '';

const BOT_USERNAME =
  process.env.BOT_USERNAME ||
  '';

const MINI_APP_URL =
  process.env.MINI_APP_URL ||
  'https://abdulselamahemade608-prog.github.io/Adewa-frontend/';

const WEBHOOK_URL =
  'https://adewa.vercel.app/telegram/webhook';

const ANTHROPIC_API_KEY =
  process.env.ANTHROPIC_API_KEY ||
  '';

const CLAUDE_MODEL =
  process.env.CLAUDE_MODEL ||
  'claude-haiku-4-5-20251001';

/* =========================================================
   DEFAULT REQUIRED CHANNELS

   These are fallback channels.

   Admin/database channels can also be used.
========================================================= */

const DEFAULT_GATE_CHANNELS = [
  '@andbndj',
  '@proof_chnallel',
  '@ABDU_CRYPTO',
  '@m_r_work1'
];

/* =========================================================
   DATABASE
========================================================= */

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  },
  max: 5
});

const q = (text, params) =>
  pool.query(text, params);

/* =========================================================
   HELPERS
========================================================= */

const todayStr = () =>
  new Date().toISOString().slice(0, 10);

const fail = (
  res,
  status,
  error,
  extra = {}
) => {
  return res.status(status).json({
    error,
    ...extra
  });
};

const isAdmin = id =>
  ADMIN_IDS.includes(String(id));

function sha256(value) {
  return crypto
    .createHash('sha256')
    .update(String(value || ''))
    .digest('hex');
}

/* =========================================================
   TELEGRAM API
========================================================= */

async function tg(method, body = {}) {

  if (!BOT_TOKEN) {
    return {
      ok: false,
      description: 'BOT_TOKEN missing'
    };
  }

  try {

    const response =
      await fetch(
        `https://api.telegram.org/bot${BOT_TOKEN}/${method}`,
        {
          method: 'POST',

          headers: {
            'Content-Type':
              'application/json'
          },

          body:
            JSON.stringify(body)
        }
      );

    return await response.json();

  } catch (error) {

    console.error(
      'Telegram API error:',
      error
    );

    return {
      ok: false,
      description:
        error.message
    };
  }
}

/* =========================================================
   DATABASE INITIALIZATION
========================================================= */

let databaseReady = null;

async function initDatabase() {

  if (databaseReady) {
    return databaseReady;
  }

  databaseReady =
    (async () => {

      /* ---------------- USERS ---------------- */

      await q(`
        CREATE TABLE IF NOT EXISTS users (
          id BIGINT PRIMARY KEY,

          first_name TEXT NOT NULL DEFAULT '',
          username TEXT NOT NULL DEFAULT '',

          coins NUMERIC NOT NULL DEFAULT 0,
          ads_coins NUMERIC NOT NULL DEFAULT 0,
          invite_coins NUMERIC NOT NULL DEFAULT 0,

          referred_by BIGINT,

          referral_paid BOOLEAN
            NOT NULL DEFAULT FALSE,

          referral_reward_paid NUMERIC
            NOT NULL DEFAULT 0,

          banned BOOLEAN
            NOT NULL DEFAULT FALSE,

          flagged BOOLEAN
            NOT NULL DEFAULT FALSE,

          vip_unlimited_until TIMESTAMPTZ,

          lang VARCHAR(5)
            NOT NULL DEFAULT 'am',

          last_ip TEXT
            NOT NULL DEFAULT '',

          daily_ads INTEGER
            NOT NULL DEFAULT 0,

          daily_invite INTEGER
            NOT NULL DEFAULT 0,

          daily_task INTEGER
            NOT NULL DEFAULT 0,

          daily_earn_day DATE,

          created_at TIMESTAMPTZ
            NOT NULL DEFAULT NOW(),

          updated_at TIMESTAMPTZ
            NOT NULL DEFAULT NOW()
        )
      `);

      /* ---------------- REQUIRED CHANNELS ---------------- */

      await q(`
        CREATE TABLE IF NOT EXISTS required_channels (
          id BIGSERIAL PRIMARY KEY,

          channel_id TEXT NOT NULL,

          username TEXT NOT NULL DEFAULT '',

          title TEXT NOT NULL DEFAULT '',

          invite_url TEXT NOT NULL DEFAULT '',

          enabled BOOLEAN NOT NULL DEFAULT TRUE,

          required BOOLEAN NOT NULL DEFAULT TRUE,

          sort_order INTEGER NOT NULL DEFAULT 0,

          created_at TIMESTAMPTZ
            NOT NULL DEFAULT NOW(),

          updated_at TIMESTAMPTZ
            NOT NULL DEFAULT NOW(),

          UNIQUE(channel_id)
        )
      `);

      /* ---------------- FRAUD USERS ---------------- */

      await q(`
        CREATE TABLE IF NOT EXISTS fraud_users (
          telegram_id BIGINT PRIMARY KEY,

          username TEXT NOT NULL DEFAULT '',

          first_name TEXT NOT NULL DEFAULT '',

          ip_hash TEXT NOT NULL DEFAULT '',

          device_hash TEXT NOT NULL DEFAULT '',

          vpn_detected BOOLEAN
            NOT NULL DEFAULT FALSE,

          proxy_detected BOOLEAN
            NOT NULL DEFAULT FALSE,

          tor_detected BOOLEAN
            NOT NULL DEFAULT FALSE,

          hosting_detected BOOLEAN
            NOT NULL DEFAULT FALSE,

          risk_score INTEGER
            NOT NULL DEFAULT 0,

          status TEXT
            NOT NULL DEFAULT 'pending',

          ban_reason TEXT
            NOT NULL DEFAULT '',

          ban_source TEXT
            NOT NULL DEFAULT '',

          verification_message_sent BOOLEAN
            NOT NULL DEFAULT FALSE,

          ban_message_sent BOOLEAN
            NOT NULL DEFAULT FALSE,

          first_seen TIMESTAMPTZ
            NOT NULL DEFAULT NOW(),

          last_seen TIMESTAMPTZ
            NOT NULL DEFAULT NOW(),

          request_count INTEGER
            NOT NULL DEFAULT 0
        )
      `);

      /* ---------------- AD VIEWS ---------------- */

      await q(`
        CREATE TABLE IF NOT EXISTS ad_views (
          id BIGSERIAL PRIMARY KEY,

          user_id BIGINT NOT NULL,

          nonce TEXT NOT NULL,

          completed BOOLEAN
            NOT NULL DEFAULT FALSE,

          reward NUMERIC
            NOT NULL DEFAULT 0,

          started_at TIMESTAMPTZ
            NOT NULL DEFAULT NOW(),

          completed_at TIMESTAMPTZ
        )
      `);

      /* ---------------- SETTINGS ---------------- */

      await q(`
        CREATE TABLE IF NOT EXISTS settings (
          key TEXT PRIMARY KEY,

          value JSONB NOT NULL DEFAULT '{}'::jsonb,

          updated_at TIMESTAMPTZ
            NOT NULL DEFAULT NOW()
        )
      `);

      /* ---------------- SPINS ---------------- */

      await q(`
        CREATE TABLE IF NOT EXISTS spins (
          id BIGSERIAL PRIMARY KEY,

          user_id BIGINT NOT NULL,

          cost NUMERIC NOT NULL DEFAULT 0,

          reward NUMERIC NOT NULL DEFAULT 0,

          created_at TIMESTAMPTZ
            NOT NULL DEFAULT NOW()
        )
      `);

      /* ---------------- TASKS ---------------- */

      await q(`
        CREATE TABLE IF NOT EXISTS tasks (
          id BIGSERIAL PRIMARY KEY,

          type TEXT NOT NULL DEFAULT 'url',

          title TEXT NOT NULL DEFAULT '',

          chat TEXT NOT NULL DEFAULT '',

          url TEXT NOT NULL DEFAULT '',

          reward NUMERIC NOT NULL DEFAULT 0,

          max_users INTEGER NOT NULL DEFAULT 0,

          completed_users INTEGER NOT NULL DEFAULT 0,

          sponsor TEXT NOT NULL DEFAULT '',

          enabled BOOLEAN NOT NULL DEFAULT TRUE,

          created_at TIMESTAMPTZ
            NOT NULL DEFAULT NOW()
        )
      `);

      /* ---------------- TASK SUBS ---------------- */

      await q(`
        CREATE TABLE IF NOT EXISTS task_subs (
          id BIGSERIAL PRIMARY KEY,

          task_id BIGINT NOT NULL,

          user_id BIGINT NOT NULL,

          completed BOOLEAN NOT NULL DEFAULT FALSE,

          created_at TIMESTAMPTZ
            NOT NULL DEFAULT NOW(),

          UNIQUE(task_id, user_id)
        )
      `);

      /* ---------------- WITHDRAWALS ---------------- */

      await q(`
        CREATE TABLE IF NOT EXISTS withdrawals (
          id BIGSERIAL PRIMARY KEY,

          user_id BIGINT NOT NULL,

          etb NUMERIC NOT NULL DEFAULT 0,

          coins NUMERIC NOT NULL DEFAULT 0,

          method TEXT NOT NULL DEFAULT '',

          account TEXT NOT NULL DEFAULT '',

          holder_name TEXT NOT NULL DEFAULT '',

          from_ads NUMERIC NOT NULL DEFAULT 0,

          from_invite NUMERIC NOT NULL DEFAULT 0,

          fee NUMERIC NOT NULL DEFAULT 0,

          net_etb NUMERIC NOT NULL DEFAULT 0,

          status TEXT NOT NULL DEFAULT 'pending',

          admin_note TEXT NOT NULL DEFAULT '',

          created_at TIMESTAMPTZ
            NOT NULL DEFAULT NOW(),

          updated_at TIMESTAMPTZ
            NOT NULL DEFAULT NOW()
        )
      `);

      /* ---------------- PROMOS ---------------- */

      await q(`
        CREATE TABLE IF NOT EXISTS promos (
          code TEXT PRIMARY KEY,

          reward NUMERIC NOT NULL DEFAULT 0,

          max_uses INTEGER NOT NULL DEFAULT 0,

          uses INTEGER NOT NULL DEFAULT 0,

          enabled BOOLEAN NOT NULL DEFAULT TRUE,

          created_at TIMESTAMPTZ
            NOT NULL DEFAULT NOW()
        )
      `);

      /* ---------------- PROMO USES ---------------- */

      await q(`
        CREATE TABLE IF NOT EXISTS promo_uses (
          id BIGSERIAL PRIMARY KEY,

          code TEXT NOT NULL,

          user_id BIGINT NOT NULL,

          reward NUMERIC NOT NULL DEFAULT 0,

          created_at TIMESTAMPTZ
            NOT NULL DEFAULT NOW(),

          UNIQUE(code, user_id)
        )
      `);

      /* ---------------- TASK BROADCASTS ---------------- */

      await q(`
        CREATE TABLE IF NOT EXISTS task_broadcasts (
          id BIGSERIAL PRIMARY KEY,

          task_id BIGINT NOT NULL,

          message_id BIGINT,

          created_at TIMESTAMPTZ
            NOT NULL DEFAULT NOW()
        )
      `);

      /* ---------------- DEFAULT SETTINGS ---------------- */

      const defaults = {

        coin_per_etb: 100,

        withdraw_fee_percent: 3,

        min_withdraw_etb: 10,

        withdraw_interval_hours: 48,

        referral_reward: 1,

        free_spins: 5,

        spin_cost: 20,

        daily_ads_limit: 10,

        daily_task_limit: 20,

        ad_reward: 1,

        faq_knowledge: `
App name: Adewa.

Adewa is a Telegram Mini App where users earn coins.

Earning sources:
- Watching advertisements
- Completing tasks
- Inviting friends

Coins can be converted to ETB.

Withdraw methods:
- Telebirr
- CBE
- M-Pesa

Withdrawals are manually reviewed by administrators.

Never invent exact fees, rewards, limits or payment times if they are not available in the settings.
`
      };

      for (const [key, value] of Object.entries(defaults)) {

        await q(
          `
          INSERT INTO settings(key,value)
          VALUES($1,$2::jsonb)
          ON CONFLICT(key)
          DO NOTHING
          `,
          [
            key,
            JSON.stringify(value)
          ]
        );
      }

      /* ---------------- DEFAULT CHANNELS ---------------- */

      for (
        let i = 0;
        i < DEFAULT_GATE_CHANNELS.length;
        i++
      ) {

        const username =
          DEFAULT_GATE_CHANNELS[i];

        await q(
          `
          INSERT INTO required_channels(
            channel_id,
            username,
            title,
            invite_url,
            enabled,
            required,
            sort_order
          )
          VALUES(
            $1,$2,$2,$3,TRUE,TRUE,$4
          )
          ON CONFLICT(channel_id)
          DO NOTHING
          `,
          [
            username,
            username,
            `https://t.me/${username.replace('@','')}`,
            i
          ]
        );
      }

      console.log(
        'Adewa database initialized.'
      );

    })()
    .catch(error => {

      databaseReady = null;

      console.error(
        'Database initialization error:',
        error
      );

      throw error;
    });

  return databaseReady;
}

/* =========================================================
   SETTINGS
========================================================= */

let settingsCache = {
  time: 0,
  data: {}
};

async function getSettings() {

  if (
    Date.now() -
      settingsCache.time <
    30000
  ) {
    return settingsCache.data;
  }

  const result =
    await q(
      `
      SELECT key,value
      FROM settings
      `
    );

  const data = {};

  for (const row of result.rows) {
    data[row.key] = row.value;
  }

  settingsCache = {
    time: Date.now(),
    data
  };

  return data;
}

async function getSetting(
  key,
  fallback = null
) {

  const settings =
    await getSettings();

  return settings[key] ??
    fallback;
}

/* =========================================================
   TELEGRAM INIT DATA
========================================================= */

function verifyInitData(
  initData
) {

  if (
    !initData ||
    !BOT_TOKEN
  ) {
    return null;
  }

  try {

    const params =
      new URLSearchParams(
        initData
      );

    const hash =
      params.get('hash');

    if (!hash) {
      return null;
    }

    params.delete('hash');

    const dataCheckString =
      [...params.entries()]
        .sort(
          ([a], [b]) =>
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

    if (
      calculatedHash !== hash
    ) {
      return null;
    }

    const authDate =
      Number(
        params.get('auth_date') ||
        0
      );

    if (!authDate) {
      return null;
    }

    const now =
      Math.floor(
        Date.now() / 1000
      );

    if (
      now - authDate >
      86400
    ) {
      return null;
    }

    const userJSON =
      params.get('user');

    if (!userJSON) {
      return null;
    }

    const user =
      JSON.parse(userJSON);

    if (!user.id) {
      return null;
    }

    return {
      user,

      start:
        params.get(
          'start_param'
        ) || ''
    };

  } catch (error) {

    console.error(
      'InitData error:',
      error
    );

    return null;
  }
}

/* =========================================================
   CLIENT IP
========================================================= */

function getClientIP(req) {

  const forwarded =
    req.headers[
      'x-forwarded-for'
    ];

  if (forwarded) {

    return String(
      forwarded
    )
      .split(',')[0]
      .trim();
  }

  return String(
    req.headers[
      'x-real-ip'
    ] ||
    req.socket?.remoteAddress ||
    ''
  ).trim();
}

/* =========================================================
   VPN / PROXY / TOR DETECTION
========================================================= */

async function detectVPNProxy(
  ip
) {

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
      .replace(
        /^::ffff:/,
        ''
      )
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
            Accept:
              'application/json'
          },

          signal:
            AbortSignal.timeout(
              5000
            )
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

/* =========================================================
   MULTI ACCOUNT DETECTION

   ORDER:
   1. SAME DEVICE
   2. SAME IP + DIFFERENT DEVICE
========================================================= */

async function detectMultiAccount(
  telegramId,
  ipHash,
  deviceHash
) {

  if (
    !ipHash &&
    !deviceHash
  ) {
    return {
      detected: false,
      reason: ''
    };
  }

  /* ---------- SAME DEVICE ---------- */

  if (deviceHash) {

    const result =
      await q(
        `
        SELECT telegram_id
        FROM fraud_users
        WHERE device_hash=$1
          AND telegram_id<>$2
          AND status='verified'
        LIMIT 1
        `,
        [
          deviceHash,
          telegramId
        ]
      );

    if (
      result.rows.length
    ) {

      return {
        detected: true,

        reason:
          'Multiple Telegram accounts detected on the same device.'
      };
    }
  }

  /* ---------- SAME IP + DIFFERENT DEVICE ---------- */

  if (ipHash) {

    const result =
      await q(
        `
        SELECT
          telegram_id,
          device_hash
        FROM fraud_users
        WHERE ip_hash=$1
          AND telegram_id<>$2
          AND status='verified'
        LIMIT 1
        `,
        [
          ipHash,
          telegramId
        ]
      );

    if (
      result.rows.length
    ) {

      const oldDevice =
        result.rows[0]
          .device_hash;

      if (
        oldDevice &&
        deviceHash &&
        oldDevice !==
          deviceHash
      ) {

        return {
          detected: true,

          reason:
            'Multiple Telegram accounts detected from the same IP address.'
        };
      }
    }
  }

  return {
    detected: false,
    reason: ''
  };
}

/* =========================================================
   BAN MESSAGES
========================================================= */

function getBanType(
  reason
) {

  const r =
    String(
      reason || ''
    ).toLowerCase();

  if (
    r.includes('vpn') ||
    r.includes('proxy') ||
    r.includes('tor')
  ) {
    return 'vpn';
  }

  if (
    r.includes('multi') ||
    r.includes('multiple') ||
    r.includes('same device') ||
    r.includes('same ip')
  ) {
    return 'multi';
  }

  return 'other';
}

async function sendBanMessage(
  chatId,
  reason
) {

  const type =
    getBanType(reason);

  if (type === 'multi') {

    return tg(
      'sendMessage',
      {
        chat_id: chatId,

        text:
          '🚫 Multiple accounts detected.\n\n' +
          'Your account has been permanently banned from Adewa.'
      }
    );
  }

  if (type === 'vpn') {

    return tg(
      'sendMessage',
      {
        chat_id: chatId,

        text:
          '🚫 VPN/Proxy detected.\n\n' +
          'Your account has been permanently banned from Adewa.'
      }
    );
  }

  return tg(
    'sendMessage',
    {
      chat_id: chatId,

      text:
        '🚫 Your account has been permanently banned from Adewa.'
    }
  );
}

/* =========================================================
   REQUIRED CHANNELS
========================================================= */

async function getRequiredChannels() {

  const result =
    await q(
      `
      SELECT
        id,
        channel_id,
        username,
        title,
        invite_url,
        enabled,
        required,
        sort_order
      FROM required_channels
      WHERE enabled=TRUE
        AND required=TRUE
      ORDER BY sort_order ASC,id ASC
      `
    );

  return result.rows;
}

/* =========================================================
   CHECK CHANNEL MEMBERSHIP
========================================================= */

async function checkChannelMembership(
  userId,
  channel
) {

  const target =
    channel.channel_id ||
    channel.username;

  const result =
    await tg(
      'getChatMember',
      {
        chat_id: target,
        user_id: userId
      }
    );

  if (!result.ok) {

    console.error(
      'getChatMember failed:',
      target,
      result.description
    );

    return {
      ok: false,
      joined: false,
      error:
        result.description ||
        'membership_check_failed'
    };
  }

  const member =
    result.result;

  const status =
    member?.status;

  const joined =
    status === 'member' ||
    status === 'administrator' ||
    status === 'creator' ||
    (
      status === 'restricted' &&
      member?.is_member === true
    );

  return {
    ok: true,
    joined
  };
}

async function checkAllRequiredChannels(
  userId
) {

  const channels =
    await getRequiredChannels();

  const missing = [];

  for (const channel of channels) {

    const check =
      await checkChannelMembership(
        userId,
        channel
      );

    if (!check.ok) {

      missing.push({
        id: channel.id,
        username:
          channel.username,
        title:
          channel.title ||
          channel.username,
        invite_url:
          channel.invite_url,
        error:
          check.error
      });

      continue;
    }

    if (!check.joined) {

      missing.push({
        id: channel.id,
        username:
          channel.username,
        title:
          channel.title ||
          channel.username,
        invite_url:
          channel.invite_url
      });
    }
  }

  return {
    ok: missing.length === 0,
    channels,
    missing
  };
}

/* =========================================================
   CHANNEL GATE KEYBOARD
========================================================= */

function buildChannelKeyboard(
  channels
) {

  const rows = [];

  for (const channel of channels) {

    const url =
      channel.invite_url ||
      (
        channel.username
          ? `https://t.me/${String(
              channel.username
            ).replace('@','')}`
          : ''
      );

    if (!url) {
      continue;
    }

    rows.push([
      {
        text:
          channel.title ||
          channel.username ||
          'Join Channel',

        url
      }
    ]);
  }

  rows.push([
    {
      text:
        '✅ Joined',
      callback_data:
        'gate_joined'
    }
  ]);

  return {
    inline_keyboard:
      rows
  };
}

async function sendChannelGate(
  chatId
) {

  const channels =
    await getRequiredChannels();

  if (!channels.length) {

    return tg(
      'sendMessage',
      {
        chat_id: chatId,

        text:
          'Welcome to Adewa.',

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

  return tg(
    'sendMessage',
    {
      chat_id: chatId,

      text:
        '👋 Welcome to Adewa!\n\n' +
        'Before opening Adewa, please join all required channels below.\n\n' +
        'After joining all channels, press "Joined".',

      reply_markup:
        buildChannelKeyboard(
          channels
        )
    }
  );
}

/* =========================================================
   ENSURE USER
========================================================= */

async function ensureUser(
  user,
  referralId = null
) {

  if (!user?.id) {
    return;
  }

  const existing =
    await q(
      `
      SELECT id
      FROM users
      WHERE id=$1
      LIMIT 1
      `,
      [user.id]
    );

  if (
    existing.rows.length
  ) {

    await q(
      `
      UPDATE users
      SET
        first_name=$2,
        username=$3,
        updated_at=NOW()
      WHERE id=$1
      `,
      [
        user.id,
        user.first_name || '',
        user.username || ''
      ]
    );

    return;
  }

  let referredBy =
    null;

  if (
    referralId &&
    /^\d+$/.test(
      String(referralId)
    ) &&
    String(referralId) !==
      String(user.id)
  ) {

    const ref =
      await q(
        `
        SELECT id
        FROM users
        WHERE id=$1
        LIMIT 1
        `,
        [referralId]
      );

    if (
      ref.rows.length
    ) {
      referredBy =
        referralId;
    }
  }

  await q(
    `
    INSERT INTO users(
      id,
      first_name,
      username,
      referred_by
    )
    VALUES($1,$2,$3,$4)
    ON CONFLICT(id)
    DO NOTHING
    `,
    [
      user.id,
      user.first_name || '',
      user.username || '',
      referredBy
    ]
  );
}

/* =========================================================
   SECURITY VERIFICATION
========================================================= */

async function runSecurityVerification(
  user,
  req
) {

  const telegramId =
    Number(user.id);

  const username =
    user.username || '';

  const firstName =
    user.first_name || '';

  const ip =
    getClientIP(req);

  const ipHash =
    sha256(ip);

  const deviceId =
    String(
      req.headers[
        'x-device'
      ] || ''
    ).trim();

  const deviceHash =
    sha256(deviceId);

  await q(
    `
    INSERT INTO fraud_users(
      telegram_id,
      username,
      first_name,
      ip_hash,
      device_hash,
      last_seen,
      request_count
    )
    VALUES(
      $1,$2,$3,$4,$5,NOW(),1
    )
    ON CONFLICT(telegram_id)
    DO UPDATE SET
      username=$2,
      first_name=$3,
      ip_hash=$4,
      device_hash=$5,
      last_seen=NOW(),
      request_count=
        fraud_users.request_count+1
    `,
    [
      telegramId,
      username,
      firstName,
      ipHash,
      deviceHash
    ]
  );

  /* =======================================================
     1. MULTI ACCOUNT FIRST
  ======================================================= */

  const multi =
    await detectMultiAccount(
      telegramId,
      ipHash,
      deviceHash
    );

  if (multi.detected) {

    await q(
      `
      UPDATE fraud_users
      SET
        status='banned',
        ban_reason='multi',
        ban_source='automatic',
        risk_score=100,
        last_seen=NOW()
      WHERE telegram_id=$1
      `,
      [telegramId]
    );

    await q(
      `
      UPDATE users
      SET banned=TRUE
      WHERE id=$1
      `,
      [telegramId]
    );

    return {
      ok: false,
      status: 'banned',
      reason: 'multi',
      message:
        'Multiple accounts detected.'
    };
  }

  /* =======================================================
     2. VPN / PROXY / TOR SECOND
  ======================================================= */

  const network =
    await detectVPNProxy(ip);

  await q(
    `
    UPDATE fraud_users
    SET
      vpn_detected=$2,
      proxy_detected=$3,
      tor_detected=$4,
      hosting_detected=$5
    WHERE telegram_id=$1
    `,
    [
      telegramId,
      network.vpn,
      network.proxy,
      network.tor,
      network.hosting
    ]
  );

  if (network.detected) {

    await q(
      `
      UPDATE fraud_users
      SET
        status='banned',
        ban_reason='vpn',
        ban_source='automatic',
        risk_score=100,
        last_seen=NOW()
      WHERE telegram_id=$1
      `,
      [telegramId]
    );

    await q(
      `
      UPDATE users
      SET banned=TRUE
      WHERE id=$1
      `,
      [telegramId]
    );

    return {
      ok: false,
      status: 'banned',
      reason: 'vpn',
      message:
        'VPN/Proxy detected.'
    };
  }

  /* =======================================================
     3. VERIFIED
  ======================================================= */

  await q(
    `
    UPDATE fraud_users
    SET
      status='verified',
      ban_reason='',
      ban_source='',
      risk_score=0,
      last_seen=NOW()
    WHERE telegram_id=$1
    `,
    [telegramId]
  );

  return {
    ok: true,
    status: 'verified',

    checks: {
      multi_account: 'NO',
      vpn_proxy: 'YES'
    }
  };
}

/* =========================================================
   AUTH MIDDLEWARE
========================================================= */

async function auth(
  req,
  res,
  next
) {

  try {

    await initDatabase();

    const initData =
      req.headers[
        'x-init-data'
      ];

    const verified =
      verifyInitData(
        initData
      );

    if (!verified) {

      return fail(
        res,
        401,
        'invalid_init_data'
      );
    }

    req.tgUser =
      verified.user;

    next();

  } catch (error) {

    console.error(
      'auth error:',
      error
    );

    return fail(
      res,
      500,
      'server'
    );
  }
}

/* =========================================================
   ADMIN MIDDLEWARE
========================================================= */

function adminOnly(
  req,
  res,
  next
) {

  if (
    !isAdmin(
      req.tgUser?.id
    )
  ) {

    return fail(
      res,
      403,
      'admin_only'
    );
  }

  next();
}

/* =========================================================
   ROOT
========================================================= */

app.get(
  '/',
  async (req, res) => {

    await initDatabase();

    res.json({
      ok: true,

      app:
        'Adewa Telegram Mini App',

      status:
        'online'
    });
  }
);

/* =========================================================
   WEBHOOK STATUS
========================================================= */

app.get(
  '/api/webhook-status',
  async (req, res) => {

    const result =
      await tg(
        'getWebhookInfo'
      );

    res.json(result);
  }
);

/* =========================================================
   SET WEBHOOK
========================================================= */

let webhookPromise = null;

async function setupWebhook() {

  if (webhookPromise) {
    return webhookPromise;
  }

  webhookPromise =
    tg(
      'setWebhook',
      {
        url:
          WEBHOOK_URL,

        secret_token:
          WEBHOOK_SECRET,

        allowed_updates: [
          'message',
          'callback_query'
        ],

        drop_pending_updates:
          false
      }
    )
    .catch(error => {

      webhookPromise = null;

      console.error(
        'Webhook setup error:',
        error
      );

      throw error;
    });

  return webhookPromise;
}

/* =========================================================
   CHANNEL API
========================================================= */

app.get(
  '/api/gate/channels',
  async (req, res) => {

    await initDatabase();

    const channels =
      await getRequiredChannels();

    res.json({
      ok: true,
      channels
    });
  }
);

/* =========================================================
   CHANNEL CHECK API
========================================================= */

app.post(
  '/api/gate/check',
  auth,
  async (req, res) => {

    const user =
      req.tgUser;

    const result =
      await checkAllRequiredChannels(
        user.id
      );

    if (!result.ok) {

      return res.status(403).json({
        ok: false,

        status:
          'channels_required',

        missing:
          result.missing
      });
    }

    res.json({
      ok: true,
      status:
        'channels_joined'
    });
  }
);

/* =========================================================
   MINI APP AUTH

   This is the final server-side protection.

   Even if someone directly opens the Mini App,
   they still cannot bypass the security.
========================================================= */

app.post(
  '/api/auth',
  async (req, res) => {

    try {

      await initDatabase();

      const initData =
        req.headers[
          'x-init-data'
        ];

      const verified =
        verifyInitData(
          initData
        );

      if (!verified) {

        return res.status(401).json({
          ok: false,
          status: 'invalid',
          message:
            'Invalid Telegram authentication.'
        });
      }

      const user =
        verified.user;

      await ensureUser(
        user,
        null
      );

      /* ---------- CHANNEL GATE ---------- */

      const channelCheck =
        await checkAllRequiredChannels(
          user.id
        );

      if (!channelCheck.ok) {

        return res.status(403).json({

          ok: false,

          status:
            'channels_required',

          message:
            'Please join all required channels.',

          missing:
            channelCheck.missing
        });
      }

      /* ---------- EXISTING BAN ---------- */

      const existing =
        await q(
          `
          SELECT
            status,
            ban_reason
          FROM fraud_users
          WHERE telegram_id=$1
          LIMIT 1
          `,
          [user.id]
        );

      if (
        existing.rows.length &&
        existing.rows[0].status ===
          'banned'
      ) {

        return res.status(403).json({

          ok: false,

          status:
            'banned',

          reason:
            existing.rows[0]
              .ban_reason || 'other'
        });
      }

      /* ---------- SECURITY ---------- */

      const security =
        await runSecurityVerification(
          user,
          req
        );

      if (!security.ok) {

        return res.status(403).json(
          security
        );
      }

      /* ---------- SUCCESS ---------- */

      await q(
        `
        UPDATE users
        SET
          last_ip=$2,
          updated_at=NOW()
        WHERE id=$1
        `,
        [
          user.id,
          getClientIP(req)
        ]
      );

      res.json({
        ok: true,

        status:
          'verified',

        user: {
          id: user.id,

          first_name:
            user.first_name || '',

          username:
            user.username || ''
        },

        checks: {
          multi_account:
            'NO',

          vpn_proxy:
            'YES'
        }
      });

    } catch (error) {

      console.error(
        '/api/auth error:',
        error
      );

      res.status(500).json({
        ok: false,
        status:
          'error',

        message:
          'Server error.'
      });
    }
  }
);

/* =========================================================
   ADMIN OVERVIEW
========================================================= */

app.get(
  '/api/admin/overview',
  auth,
  adminOnly,
  async (req, res) => {

    const settings =
      await getSettings();

    const users =
      await q(
        `
        SELECT COUNT(*)::int AS count
        FROM users
        `
      );

    const banned =
      await q(
        `
        SELECT COUNT(*)::int AS count
        FROM fraud_users
        WHERE status='banned'
        `
      );

    const withdrawals =
      await q(
        `
        SELECT COUNT(*)::int AS count
        FROM withdrawals
        WHERE status='pending'
        `
      );

    const channels =
      await getRequiredChannels();

    res.json({

      ok: true,

      users:
        users.rows[0].count,

      banned_users:
        banned.rows[0].count,

      pending_withdrawals:
        withdrawals.rows[0].count,

      channels,

      settings
    });
  }
);

/* =========================================================
   ADMIN: ADD REQUIRED CHANNEL
========================================================= */

app.post(
  '/api/admin/channel',
  auth,
  adminOnly,
  async (req, res) => {

    const {
      channel_id,
      username,
      title,
      invite_url,
      enabled = true,
      required = true,
      sort_order = 0
    } = req.body || {};

    if (
      !channel_id
    ) {

      return fail(
        res,
        400,
        'channel_id_required'
      );
    }

    await q(
      `
      INSERT INTO required_channels(
        channel_id,
        username,
        title,
        invite_url,
        enabled,
        required,
        sort_order
      )
      VALUES($1,$2,$3,$4,$5,$6,$7)
      ON CONFLICT(channel_id)
      DO UPDATE SET
        username=$2,
        title=$3,
        invite_url=$4,
        enabled=$5,
        required=$6,
        sort_order=$7,
        updated_at=NOW()
      `,
      [
        String(channel_id),
        username || '',
        title || '',
        invite_url || '',
        Boolean(enabled),
        Boolean(required),
        Number(sort_order) || 0
      ]
    );

    res.json({
      ok: true
    });
  }
);

/* =========================================================
   ADMIN: DELETE CHANNEL
========================================================= */

app.delete(
  '/api/admin/channel/:id',
  auth,
  adminOnly,
  async (req, res) => {

    await q(
      `
      DELETE FROM required_channels
      WHERE id=$1
      `,
      [req.params.id]
    );

    res.json({
      ok: true
    });
  }
);

/* =========================================================
   ADMIN: TOGGLE CHANNEL
========================================================= */

app.post(
  '/api/admin/channel/:id/toggle',
  auth,
  adminOnly,
  async (req, res) => {

    await q(
      `
      UPDATE required_channels
      SET
        enabled=NOT enabled,
        updated_at=NOW()
      WHERE id=$1
      `,
      [req.params.id]
    );

    res.json({
      ok: true
    });
  }
);

/* =========================================================
   ADMIN: BAN USER
========================================================= */

app.post(
  '/api/admin/ban',
  auth,
  adminOnly,
  async (req, res) => {

    const {
      id,
      reason = 'manual'
    } = req.body || {};

    if (
      !/^\d+$/.test(
        String(id || '')
      )
    ) {

      return fail(
        res,
        400,
        'bad_user_id'
      );
    }

    await q(
      `
      INSERT INTO fraud_users(
        telegram_id,
        status,
        ban_reason,
        ban_source,
        risk_score
      )
      VALUES(
        $1,
        'banned',
        $2,
        'manual',
        100
      )
      ON CONFLICT(telegram_id)
      DO UPDATE SET
        status='banned',
        ban_reason=$2,
        ban_source='manual',
        risk_score=100,
        last_seen=NOW()
      `,
      [
        id,
        String(reason)
      ]
    );

    await q(
      `
      UPDATE users
      SET banned=TRUE
      WHERE id=$1
      `,
      [id]
    );

    await sendBanMessage(
      id,
      reason
    );

    res.json({
      ok: true
    });
  }
);

/* =========================================================
   ADMIN: UNBAN USER
========================================================= */

app.post(
  '/api/admin/unban',
  auth,
  adminOnly,
  async (req, res) => {

    const {
      id
    } = req.body || {};

    if (
      !/^\d+$/.test(
        String(id || '')
      )
    ) {

      return fail(
        res,
        400,
        'bad_user_id'
      );
    }

    await q(
      `
      UPDATE fraud_users
      SET
        status='pending',
        ban_reason='',
        ban_source='',
        risk_score=0,
        ban_message_sent=FALSE,
        verification_message_sent=FALSE,
        last_seen=NOW()
      WHERE telegram_id=$1
      `,
      [id]
    );

    await q(
      `
      UPDATE users
      SET banned=FALSE
      WHERE id=$1
      `,
      [id]
    );

    res.json({
      ok: true
    });
  }
);

/* =========================================================
   ADMIN: BANNED USERS
========================================================= */

app.get(
  '/api/admin/banned-users',
  auth,
  adminOnly,
  async (req, res) => {

    const result =
      await q(
        `
        SELECT
          telegram_id,
          username,
          first_name,
          ban_reason,
          ban_source,
          risk_score,
          first_seen,
          last_seen
        FROM fraud_users
        WHERE status='banned'
        ORDER BY last_seen DESC
        LIMIT 500
        `
      );

    res.json({
      ok: true,
      users:
        result.rows
    });
  }
);

/* =========================================================
   ADMIN: SETTING
========================================================= */

app.post(
  '/api/admin/setting',
  auth,
  adminOnly,
  async (req, res) => {

    const {
      key,
      value
    } = req.body || {};

    if (!key) {

      return fail(
        res,
        400,
        'key_required'
      );
    }

    await q(
      `
      INSERT INTO settings(
        key,
        value,
        updated_at
      )
      VALUES(
        $1,
        $2::jsonb,
        NOW()
      )
      ON CONFLICT(key)
      DO UPDATE SET
        value=$2::jsonb,
        updated_at=NOW()
      `,
      [
        key,
        JSON.stringify(value)
      ]
    );

    settingsCache.time = 0;

    res.json({
      ok: true
    });
  }
);

/* =========================================================
   ADMIN: USER ACTION
========================================================= */

app.post(
  '/api/admin/user',
  auth,
  adminOnly,
  async (req, res) => {

    const {
      id,
      action
    } = req.body || {};

    if (
      !/^\d+$/.test(
        String(id || '')
      )
    ) {

      return fail(
        res,
        400,
        'bad_user_id'
      );
    }

    if (
      action === 'ban'
    ) {

      await q(
        `
        UPDATE users
        SET banned=TRUE
        WHERE id=$1
        `,
        [id]
      );

      await q(
        `
        INSERT INTO fraud_users(
          telegram_id,
          status,
          ban_reason,
          ban_source,
          risk_score
        )
        VALUES(
          $1,
          'banned',
          'manual',
          'manual',
          100
        )
        ON CONFLICT(telegram_id)
        DO UPDATE SET
          status='banned',
          ban_reason='manual',
          ban_source='manual',
          risk_score=100
        `,
        [id]
      );

    } else if (
      action === 'unban'
    ) {

      await q(
        `
        UPDATE users
        SET banned=FALSE
        WHERE id=$1
        `,
        [id]
      );

      await q(
        `
        UPDATE fraud_users
        SET
          status='pending',
          ban_reason='',
          ban_source='',
          risk_score=0
        WHERE telegram_id=$1
        `,
        [id]
      );

    } else if (
      action === 'unflag'
    ) {

      await q(
        `
        UPDATE users
        SET flagged=FALSE
        WHERE id=$1
        `,
        [id]
      );

    } else {

      return fail(
        res,
        400,
        'bad_action'
      );
    }

    res.json({
      ok: true
    });
  }
);

/* =========================================================
   TELEGRAM WEBHOOK
========================================================= */

async function handleTelegramUpdate(
  update
) {

  /* =======================================================
     CALLBACK QUERY
  ======================================================= */

  if (
    update.callback_query
  ) {

    const callback =
      update.callback_query;

    const data =
      callback.data || '';

    const user =
      callback.from;

    const chatId =
      callback.message?.chat?.id ||
      user?.id;

    if (
      data ===
      'gate_joined'
    ) {

      await initDatabase();

      const check =
        await checkAllRequiredChannels(
          user.id
        );

      if (!check.ok) {

        const names =
          check.missing
            .map(
              x =>
                x.title ||
                x.username ||
                'channel'
            )
            .join(', ');

        await tg(
          'answerCallbackQuery',
          {
            callback_query_id:
              callback.id,

            text:
              '❌ You have not joined all required channels.',

            show_alert: true
          }
        );

        await tg(
          'sendMessage',
          {
            chat_id: chatId,

            text:
              '❌ Please join all required channels first.\n\n' +
              `Missing: ${names}`,

            reply_markup:
              buildChannelKeyboard(
                await getRequiredChannels()
              )
          }
        );

        return;
      }

      /* ---------- EXISTING BAN ---------- */

      const banned =
        await q(
          `
          SELECT
            status,
            ban_reason
          FROM fraud_users
          WHERE telegram_id=$1
          LIMIT 1
          `,
          [user.id]
        );

      if (
        banned.rows.length &&
        banned.rows[0].status ===
          'banned'
      ) {

        await sendBanMessage(
          chatId,
          banned.rows[0]
            .ban_reason
        );

        await tg(
          'answerCallbackQuery',
          {
            callback_query_id:
              callback.id,

            text:
              'Account banned.',

            show_alert: true
          }
        );

        return;
      }

      /* ---------- SECURITY ---------- */

      const fakeReq = {
        headers: {},
        socket: {
          remoteAddress: ''
        }
      };

      /*
       * Bot-side callback does not expose the same
       * browser IP/device headers as the Mini App.
       *
       * Full security verification is therefore also
       * enforced again by /api/auth when the Mini App opens.
       */

      await tg(
        'answerCallbackQuery',
        {
          callback_query_id:
            callback.id,

          text:
            '✅ Channels verified.'
        }
      );

      await tg(
        'sendMessage',
        {
          chat_id: chatId,

          text:
            '🔐 Channels verified.\n\n' +
            'Open Adewa to complete security verification.',

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

      return;
    }

    return;
  }

  /* =======================================================
     MESSAGE
  ======================================================= */

  if (
    !update.message
  ) {
    return;
  }

  const message =
    update.message;

  const user =
    message.from;

  const chatId =
    message.chat?.id;

  if (!user || !chatId) {
    return;
  }

  const text =
    typeof message.text ===
    'string'
      ? message.text.trim()
      : '';

  await initDatabase();

  /* =======================================================
     /START
  ======================================================= */

  if (
    text === '/start' ||
    text.startsWith('/start ')
  ) {

    const parts =
      text.split(' ');

    let referralId =
      null;

    const startParam =
      parts[1] || '';

    const match =
      /^ref_(\d+)$/.exec(
        startParam
      );

    if (match) {
      referralId =
        match[1];
    }

    await ensureUser(
      user,
      referralId
    );

    /*
     * IMPORTANT:
     *
     * Even banned users receive the channel gate first.
     *
     * Ban is checked AFTER "Joined".
     */

    await sendChannelGate(
      chatId
    );

    return;
  }

  /* =======================================================
     /BAN
  ======================================================= */

  if (
    text.startsWith('/ban')
  ) {

    if (
      !isAdmin(user.id)
    ) {

      await tg(
        'sendMessage',
        {
          chat_id: chatId,
          text:
            '❌ Admin only.'
        }
      );

      return;
    }

    const parts =
      text.split(/\s+/);

    const targetId =
      parts[1];

    const reason =
      parts
        .slice(2)
        .join(' ') ||
      'manual';

    if (
      !/^\d+$/.test(
        targetId || ''
      )
    ) {

      await tg(
        'sendMessage',
        {
          chat_id: chatId,

          text:
            'Usage:\n/ban <telegram_id> [reason]'
        }
      );

      return;
    }

    await q(
      `
      INSERT INTO fraud_users(
        telegram_id,
        status,
        ban_reason,
        ban_source,
        risk_score
      )
      VALUES(
        $1,
        'banned',
        $2,
        'manual',
        100
      )
      ON CONFLICT(telegram_id)
      DO UPDATE SET
        status='banned',
        ban_reason=$2,
        ban_source='manual',
        risk_score=100,
        last_seen=NOW()
      `,
      [
        targetId,
        reason
      ]
    );

    await q(
      `
      UPDATE users
      SET banned=TRUE
      WHERE id=$1
      `,
      [targetId]
    );

    await sendBanMessage(
      targetId,
      reason
    );

    await tg(
      'sendMessage',
      {
        chat_id: chatId,

        text:
          `✅ User ${targetId} has been banned.`
      }
    );

    return;
  }

  /* =======================================================
     /UNBAN
  ======================================================= */

  if (
    text.startsWith('/unban')
  ) {

    if (
      !isAdmin(user.id)
    ) {

      await tg(
        'sendMessage',
        {
          chat_id: chatId,
          text:
            '❌ Admin only.'
        }
      );

      return;
    }

    const parts =
      text.split(/\s+/);

    const targetId =
      parts[1];

    if (
      !/^\d+$/.test(
        targetId || ''
      )
    ) {

      await tg(
        'sendMessage',
        {
          chat_id: chatId,

          text:
            'Usage:\n/unban <telegram_id>'
        }
      );

      return;
    }

    await q(
      `
      UPDATE fraud_users
      SET
        status='pending',
        ban_reason='',
        ban_source='',
        risk_score=0,
        ban_message_sent=FALSE,
        verification_message_sent=FALSE,
        last_seen=NOW()
      WHERE telegram_id=$1
      `,
      [targetId]
    );

    await q(
      `
      UPDATE users
      SET banned=FALSE
      WHERE id=$1
      `,
      [targetId]
    );

    await tg(
      'sendMessage',
      {
        chat_id: chatId,

        text:
          `✅ User ${targetId} has been unbanned.\n\n` +
          'They must join the required channels and complete security verification again.'
      }
    );

    return;
  }
}

/* =========================================================
   TELEGRAM WEBHOOK ENDPOINT
========================================================= */

app.post(
  '/telegram/webhook',
  async (req, res) => {

    const incomingSecret =
      req.headers[
        'x-telegram-bot-api-secret-token'
      ];

    if (
      incomingSecret !==
      WEBHOOK_SECRET
    ) {

      return res.sendStatus(
        403
      );
    }

    try {

      await handleTelegramUpdate(
        req.body || {}
      );

    } catch (error) {

      console.error(
        'Telegram webhook error:',
        error
      );
    }

    res.sendStatus(200);
  }
);

/* =========================================================
   COMPATIBILITY WEBHOOK
========================================================= */

app.post(
  '/api/webhook',
  async (req, res) => {

    const incomingSecret =
      req.headers[
        'x-telegram-bot-api-secret-token'
      ];

    if (
      WEBHOOK_SECRET &&
      incomingSecret !==
        WEBHOOK_SECRET
    ) {

      return res.sendStatus(
        403
      );
    }

    try {

      await handleTelegramUpdate(
        req.body || {}
      );

    } catch (error) {

      console.error(
        'Compatibility webhook error:',
        error
      );
    }

    res.sendStatus(200);
  }
);

/* =========================================================
   HEALTH / WEBHOOK SETUP
========================================================= */

app.get(
  '/setup-webhook',
  async (req, res) => {

    try {

      const result =
        await setupWebhook();

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

/* =========================================================
   AUTO WEBHOOK SETUP ON ROOT
========================================================= */

app.get(
  '/health',
  async (req, res) => {

    try {

      await initDatabase();
      await setupWebhook();

      res.json({
        ok: true,
        app: 'Adewa',
        status: 'online'
      });

    } catch (error) {

      res.status(500).json({
        ok: false,
        error:
          error.message
      });
    }
  }
);

/* =========================================================
   STARTUP
========================================================= */

async function startup() {

  try {

    await initDatabase();

    await setupWebhook();

    console.log(
      'Adewa backend started.'
    );

  } catch (error) {

    console.error(
      'Startup error:',
      error
    );
  }
}

startup();

/* =========================================================
   EXPORT
========================================================= */

module.exports = app;

if (
  require.main === module
) {

  app.listen(
    PORT,
    () => {

      console.log(
        `Adewa server running on port ${PORT}`
      );
    }
  );
}
