'use strict';

const TelegramBot = require('node-telegram-bot-api');

const BOT_TOKEN = process.env.BOT_TOKEN;

const MINI_APP_URL =
  'https://abdulselamahemade608-prog.github.io/Adewa-frontend/';

if (!BOT_TOKEN) {
  throw new Error('BOT_TOKEN is missing');
}

const bot = new TelegramBot(
  BOT_TOKEN,
  { polling: true }
);


/*
=========================================================
/START
=========================================================
*/

bot.onText(/^\/start(?:\s+.*)?$/i, async (msg) => {

  const chatId = msg.chat.id;

  const firstName =
    msg.from?.first_name || 'there';

  try {

    await bot.sendMessage(
      chatId,

      `👋 Hello ${firstName}!

💰 Welcome to Adewa.

Complete ads, tasks and surveys
and earn rewards.

👇 Tap the button below to open Adewa Mini App.`,

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

  } catch (error) {

    console.error(
      'START ERROR:',
      error
    );

  }

});


/*
=========================================================
OPTIONAL /HELP
=========================================================
*/

bot.onText(/^\/help$/i, async (msg) => {

  await bot.sendMessage(
    msg.chat.id,

    `ℹ️ Adewa Help

Open the Mini App using:

🚀 OPEN ADEWA

Inside the Mini App you can access
your available tasks and rewards.`
  );

});


console.log(
  'Adewa Telegram bot is running...'
);
