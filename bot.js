'use strict';

const TelegramBot = require('node-telegram-bot-api');

const BOT_TOKEN = process.env.BOT_TOKEN;

const MINI_APP_URL =
  'https://abdulselamahemade608-prog.github.io/Adewa-frontend/';

if (!BOT_TOKEN) {
  throw new Error('BOT_TOKEN is missing');
}

const bot = new TelegramBot(BOT_TOKEN, {
  polling: true
});


/*
=========================================================
START COMMAND
=========================================================
*/

bot.onText(/^\/start(?:\s.*)?$/i, async (msg) => {

  const chatId = msg.chat.id;

  const firstName =
    msg.from?.first_name || 'User';

  try {

    await bot.sendMessage(
      chatId,

      `👋 Hello ${firstName}!

💰 Welcome to Adewa.

Complete tasks, surveys and ads
and earn rewards.

👇 Open the Mini App below:`,

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
      'Telegram /start error:',
      error
    );

  }

});


/*
=========================================================
BOT STATUS
=========================================================
*/

bot.getMe()
  .then((me) => {

    console.log(
      `Bot connected: @${me.username}`
    );

    console.log(
      'Mini App:',
      MINI_APP_URL
    );

  })
  .catch((error) => {

    console.error(
      'Bot connection error:',
      error
    );

  });
