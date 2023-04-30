#!/usr/bin/env python
import logging.handlers

import asyncio
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
    aes_sym_key: f'opitem:"AES.{APP_NAME}" opfield:.password' = None # type: ignore


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

from base64 import b64encode, b64decode

from pocket import Pocket

from requests.adapters import ConnectionError
from requests.exceptions import RequestException

from telegram import ForceReply, Update
from telegram.ext import Application, CommandHandler, ContextTypes, MessageHandler, filters

# https://www.pycryptodome.org/src/hash/hash
from Crypto.Hash import SHA384
# https://www.pycryptodome.org/src/cipher/modern#gcm-mode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import unpad


from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import declarative_base, sessionmaker, Session


db_tablespace = app_config.get('sqlite', 'tablespace_path')
dburl = f'sqlite+aiosqlite:///{db_tablespace}'
engine = create_async_engine(dburl)
async_session = sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
Base = declarative_base()


from typing import List, Optional
from sqlalchemy import Column, Integer, String


from sqlalchemy import update
from sqlalchemy.future import select


class Book(Base):
    __tablename__ = 'books'

    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)


class BookDAL():
    def __init__(self, db_session: Session):
        self.db_session = db_session

    async def create_book(self, name):
        new_book = Book(name=name)
        self.db_session.add(new_book)
        await self.db_session.flush()

    async def get_all_books(self) -> List[Book]:
        q = await self.db_session.execute(select(Book).order_by(Book.id))
        return q.scalars().all()

    async def update_book(self, book_id: int, name: Optional[str]):
        q = update(Book).where(Book.id == book_id)
        if name:
            q = q.values(name=name)
        q.execution_options(synchronize_session="fetch")
        await  self.db_session.execute(q)


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

    async with async_session() as session:
        async with session.begin():
            book_dal = BookDAL(session)
            book_name = str(time.time())
            await book_dal.create_book(name=f'time is {book_name}')

    await update.message.reply_text(update.message.text)


async def startup():
    # create db tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)


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
    loop = asyncio.new_event_loop()
    log.setLevel(logging.INFO)
    try:
        #log.info(f'Starting {APP_NAME} threads...')
        #nanny.start()
        log.info(f'Starting database at {db_tablespace}...')
        asyncio.set_event_loop(loop)
        asyncio.run_coroutine_threadsafe(startup(), loop)
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
        items = pocket_instance.get(count=1, detailType='simple')
        real_items = items[0]['list']
        log.info(f'{real_items}')
        for item_key, item_data in real_items.items():
            log.info(f'{item_key=}: {item_data!s}')
            item_url = item_data['given_url']

        hash_object = SHA384.new(data=bytearray(item_url, encoding='utf-8'))
        log.info(f'Digest for {item_url} is {hash_object.hexdigest()}')

        header = b"testheader"
        data = bytearray(item_url, encoding='utf-8')
        key = b64decode(creds.aes_sym_key)
        cipher = AES.new(key, AES.MODE_GCM)
        cipher.update(header)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        json_k = [ 'nonce', 'header', 'ciphertext', 'tag' ]
        json_v = [ b64encode(x).decode('utf-8') for x in (cipher.nonce, header, ciphertext, tag) ]
        result = json.dumps(dict(zip(json_k, json_v)))
        log.info(f'Encrypted {result=}')

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
        loop.close()
    bye()


if __name__ == "__main__":
    main()