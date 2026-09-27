'use strict';

const express = require('express');

const app = express();
app.use(express.json());

const BOT_TOKEN = process.env.BOT_TOKEN;

// GitHub Pages frontend — ይህን አትቀይር
const MINI_APP_URL =
  'https://abdulselamahemade608-prog.github.io/Adewa-frontend/';

const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET || 'adewa_webhook_2026';

/*
|--------------------------------------------------------------------------
| Telegram API
|--------------------------------------------------------------------------
*/

async function telegram(method, data) {
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

  return response.json();
}

/*
|--------------------------------------------------------------------------
| START COMMAND
|--------------------------------------------------------------------------
*/

async function handleStart(msg) {
  if (!msg || !msg.chat) return;

  const chatId = msg.chat.id;
  const firstName = msg.from?.first_name || 'User';

  await telegram('sendMessage', {
    chat_id: chatId,

    text:
      `👋 Hello ${firstName}!\n\n` +
      `💰 Welcome to Adewa.\n\n` +
      `Complete tasks, ads and surveys\n` +
      `and earn rewards.\n\n` +
      `👇 Tap the button below to open Adewa:`,

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

/*
|--------------------------------------------------------------------------
| WEBHOOK
|--------------------------------------------------------------------------
*/

app.post('/telegram/webhook', async (req, res) => {
  try {

    // Security check
    const secret =
      req.headers['x-telegram-bot-api-secret-token'];

    if (secret !== WEBHOOK_SECRET) {
      return res.sendStatus(403);
    }

    const update = req.body;

    if (update?.message?.text) {

      const text = update.message.text.trim();

      // /start
      if (/^\/start(?:\s.*)?$/i.test(text)) {
        await handleStart(update.message);
      }

    }

    return res.sendStatus(200);

  } catch (error) {

    console.error('Telegram webhook error:', error);

    // Telegram should still receive 200
    return res.sendStatus(200);
  }
});

/*
|--------------------------------------------------------------------------
| TEST
|--------------------------------------------------------------------------
*/

app.get('/', (req, res) => {
  res.json({
    ok: true,
    app: 'Adewa Telegram Bot',
    bot: 'webhook',
    mini_app: MINI_APP_URL
  });
});

/*
|--------------------------------------------------------------------------
| HEALTH
|--------------------------------------------------------------------------
*/

app.get('/api/health', (req, res) => {
  res.json({
    ok: true,
    bot: true
  });
});

/*
|--------------------------------------------------------------------------
| LOCAL SERVER
|--------------------------------------------------------------------------
*/

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Adewa bot running on port ${PORT}`);
});
