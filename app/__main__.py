#!/usr/bin/env python
import logging.handlers

import builtins
import hashlib
import simplejson as json
import time
import threading

from collections import deque
from pathlib import Path
from simplejson.scanner import JSONDecodeError
from zmq.error import ZMQError, ContextTerminated

import os.path

# setup builtins used by pylib init
from . import APP_NAME
builtins.SENTRY_EXTRAS = []


class CredsConfig:
    sentry_dsn: f'opitem:"Sentry" opfield:{APP_NAME}.dsn' = None  # type: ignore
    cronitor_token: f'opitem:"cronitor" opfield:.password' = None  # type: ignore
    telegram_bot_api_token: f'opitem:"Telegram" opfield:{APP_NAME}.token' = None # type: ignore
    pocket_api_consumer_key: f'opitem:"Pocket" opfield:.credential' = None # type: ignore
    pocket_api_access_token: f'opitem:"Pocket" opfield:user.token' = None # type: ignore


# instantiate class
builtins.creds_config = CredsConfig()

from pylib import app_config, \
    creds, \
    device_name_base, \
    log

from pylib.process import SignalHandler
from pylib import threads
from pylib.threads import thread_nanny, bye, die
from pylib.app import AppThread
from pylib.zmq import zmq_term, Closable
from pylib.handler import exception_handler

from pocket import Pocket

from requests.adapters import ConnectionError
from requests.exceptions import RequestException

from telegram import ForceReply, Update
from telegram.ext import Application, CommandHandler, ContextTypes, MessageHandler, filters


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Send a message when the command /start is issued."""
    user = update.effective_user
    await update.message.reply_html(
        rf"Hi {user.mention_html()}!",
        reply_markup=ForceReply(selective=True),
    )


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Send a message when the command /help is issued."""
    await update.message.reply_text("Help!")


async def echo(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Echo the user message."""
    await update.message.reply_text(update.message.text)


def main():
    log.setLevel(logging.INFO)
    # ensure proper signal handling; must be main thread
    #signal_handler = SignalHandler()
    # start the nanny
    #nanny = threading.Thread(
    #    daemon=True,
    #    name='nanny',
    #    target=thread_nanny,
    #    args=(signal_handler,))
    # startup completed
    # back to INFO logging
    log.setLevel(logging.INFO)
    try:
        #log.info(f'Starting {APP_NAME} threads...')
        #nanny.start()
        log.info('Startup complete.')

        pocket_access_token = creds.pocket_api_access_token
        consumer_key = creds.pocket_api_consumer_key
        if pocket_access_token is None:
            r_url = 'http://t.me/PocketLintBot'
            log.info(f'Fetching request token for {consumer_key=}')
            request_token = Pocket.get_request_token(consumer_key=consumer_key, redirect_uri=r_url)
            log.info(f'Using request token for to get auth URL...')
            auth_url = Pocket.get_auth_url(code=request_token, redirect_uri=r_url)
            log.info(f'{auth_url=}')
            time.sleep(30)
            user_credentials = Pocket.get_credentials(consumer_key=consumer_key, code=request_token)
            access_token = user_credentials['access_token']
            username = user_credentials['username']
            log.info(f'User {username} access token is {access_token}')
            pocket_access_token = access_token
        log.info(f'Creating Pocket instance {consumer_key=}, {pocket_access_token=}')
        pocket_instance = Pocket(consumer_key, pocket_access_token)
        log.info(f'Fetching items...')
        items = pocket_instance.get(count=10, detailType='complete')
        log.info(f'Items are {items!s}')

        """Start the bot."""
        # Create the Application and pass it your bot's token.
        application = Application.builder().token(creds.telegram_bot_api_token).build()

        # on different commands - answer in Telegram
        application.add_handler(CommandHandler("start", start))
        application.add_handler(CommandHandler("help", help_command))

        # on non command i.e message - echo the message on Telegram
        application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, echo))
        # Run the bot until the user presses Ctrl-C
        application.run_polling()

        # hang around until something goes wrong
        #threads.interruptable_sleep.wait()
    finally:
        die()
        zmq_term()
    bye()


if __name__ == "__main__":
    main()