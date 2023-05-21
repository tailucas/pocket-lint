#!/usr/bin/env python
import logging.handlers

import asyncio
import builtins
import emoji
import hashlib
import requests
import simplejson as json
import time
import threading
import urllib.parse

from collections import deque
from dataclasses import dataclass
from pathlib import Path
from simplejson.scanner import JSONDecodeError
from uvicorn.server import Server as BaseServer
from uvicorn.config import Config as ServerConfig
from zmq.error import ZMQError, ContextTerminated

import os.path

# setup builtins used by pylib init
from . import APP_NAME
builtins.SENTRY_EXTRAS = []
influx_creds_section = 'local'

class CredsConfig:
    sentry_dsn: f'opitem:"Sentry" opfield:{APP_NAME}.dsn' = None  # type: ignore
    cronitor_token: f'opitem:"cronitor" opfield:.password' = None  # type: ignore
    telegram_bot_api_token: f'opitem:"Telegram" opfield:{APP_NAME}.token' = None # type: ignore
    pocket_api_consumer_key: f'opitem:"Pocket" opfield:{APP_NAME}.consumer_key' = None # type: ignore
    aes_sym_key: f'opitem:"AES.{APP_NAME}" opfield:.password' = None # type: ignore
    influxdb_org: f'opitem:"InfluxDB" opfield:{influx_creds_section}.org' = None # type: ignore
    influxdb_token: f'opitem:"InfluxDB" opfield:{APP_NAME}.token' = None # type: ignore
    influxdb_url: f'opitem:"InfluxDB" opfield:{influx_creds_section}.url' = None # type: ignore


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

from telegram import (
    ForceReply,
    Update,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    User as TelegramUser,
    ChatMember as TelegramChatMember
)
from telegram.constants import ParseMode
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
    ConversationHandler,
    MessageHandler,
    filters,
    CallbackContext,
    ExtBot,
    TypeHandler
)

# https://www.pycryptodome.org/src/hash/hash
from Crypto.Hash import SHA384
# https://www.pycryptodome.org/src/cipher/modern#gcm-mode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import unpad


from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import declarative_base, sessionmaker, Session

from http import HTTPStatus

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response, RedirectResponse
from starlette.routing import Route

db_tablespace = app_config.get('sqlite', 'tablespace_path')
dburl = f'sqlite+aiosqlite:///{db_tablespace}'
engine = create_async_engine(dburl)
async_session = sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
Base = declarative_base()

from typing import List, Optional
from sqlalchemy import Column, Integer, String, JSON

from sqlalchemy import update, ForeignKey, UniqueConstraint
from sqlalchemy.future import select
from sqlalchemy.orm import relationship

from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import WriteApi, ASYNCHRONOUS

influxdb_bucket = None
influxdb_rw: WriteApi = None

START_ACTIVITY = 100
ACTION_AUTHORIZE = 2
ACTION_NONE = 0


def influxdb_write(point_name, field_name, field_value):
    try:
        log.debug(f'Writing InfluxDB point {point_name=}, application={APP_NAME}, device={device_name_base}: {field_name}={field_value!s}')
        influxdb_rw.write(
            bucket=influxdb_bucket,
            record=Point(point_name).tag("application", APP_NAME).tag("device", device_name_base).field(field_name, field_value))
    except Exception:
        log.warning(f'Unable to post to InfluxDB.', exc_info=True)


def digest(payload):
    log.debug(f'Digesting {len(payload)} bytes.')
    return SHA384.new(data=bytearray(payload, encoding='utf-8')).hexdigest()


def encrypt(header, payload):
    log.debug(f'Encrypting {len(payload)} bytes.')
    header = bytearray(header, encoding='utf-8')
    data = bytearray(payload, encoding='utf-8')
    key = b64decode(creds.aes_sym_key)
    cipher = AES.new(key, AES.MODE_GCM)
    cipher.update(header)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    json_k = [ 'nonce', 'header', 'ciphertext', 'tag' ]
    json_v = [ b64encode(x).decode('utf-8') for x in (cipher.nonce, header, ciphertext, tag) ]
    return json.dumps(dict(zip(json_k, json_v)))


def decrypt(payload):
    if payload is None:
        return
    log.debug(f'Decrypting {len(payload)} bytes.')
    b64 = json.loads(payload)
    json_k = [ 'nonce', 'header', 'ciphertext', 'tag' ]
    jv = {k:b64decode(b64[k]) for k in json_k}
    key = b64decode(creds.aes_sym_key)
    cipher = AES.new(key, AES.MODE_GCM, nonce=jv['nonce'])
    cipher.update(jv['header'])
    plaintext = cipher.decrypt_and_verify(jv['ciphertext'], jv['tag'])
    return plaintext.decode('utf-8')


class DbUser(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True, autoincrement=True)
    telegram_user_id = Column(Integer, index=True, unique=True, nullable=False)
    pocket_request_token = Column(JSON)
    pocket_request_token_digest = Column(String(96), index=True)
    pocket_username = Column(JSON)
    pocket_username_digest = Column(String(96))
    pocket_access_token = Column(JSON)
    pocket_access_token_digest = Column(String(96), unique=True)
    UniqueConstraint(telegram_user_id, pocket_access_token_digest)
    links_items = relationship('Item', backref='items', cascade='all, delete-orphan', lazy='dynamic')


class User(object):
    def __init__(self, db_user: DbUser) -> None:
        self.telegram_user_id = db_user.telegram_user_id
        log.debug(f'Decrypting database details for Telegram user {self.telegram_user_id}.')
        self.pocket_request_token = decrypt(db_user.pocket_request_token)
        self.pocket_request_token_digest = db_user.pocket_request_token_digest
        self.pocket_access_token = decrypt(db_user.pocket_access_token)
        self.pocket_access_token_digest = db_user.pocket_access_token_digest
        self.pocket_username = decrypt(db_user.pocket_username)
        self.pocket_username_digest = db_user.pocket_username_digest


class Item(Base):
    __tablename__ = 'items'
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    item_url_digest = Column(String(96), index=True, unique=True, nullable=False)


class PocketDB():
    def __init__(self, db_session: Session):
        self.db_session = db_session
        self.loop = asyncio.get_event_loop()

    async def insert_request_token(self, telegram_user_id, pocket_request_token):
        log.debug(f'Inserting REQUEST token for Telegram user {telegram_user_id}.')
        db_user = await self._get_db_user(telegram_user_id=telegram_user_id)
        if db_user is None:
            log.debug(f'Adding new database user information.')
            db_user = DbUser(
                telegram_user_id=telegram_user_id,
                pocket_request_token=encrypt(str(telegram_user_id), pocket_request_token),
                pocket_request_token_digest=digest(pocket_request_token))
        else:
            log.debug(f'Updating database with new token.')
            db_user.pocket_request_token = encrypt(str(telegram_user_id), pocket_request_token)
            db_user.pocket_request_token_digest = digest(pocket_request_token)
        self.db_session.add(db_user)
        await self.db_session.flush()

    async def insert_access_token(self, telegram_user_id, pocket_username, pocket_access_token):
        log.debug(f'Inserting ACCESS token for Telegram user {telegram_user_id}.')
        q = update(DbUser).where(DbUser.telegram_user_id == telegram_user_id)
        q = q.values(pocket_username=encrypt(str(telegram_user_id), pocket_username))
        q = q.values(pocket_username_digest=digest(pocket_username))
        q = q.values(pocket_access_token=encrypt(str(telegram_user_id), pocket_access_token))
        q = q.values(pocket_access_token_digest=digest(pocket_access_token))
        q.execution_options(synchronize_session="fetch")
        return await self.db_session.execute(q)

    async def insert_item(self, telegram_user_id, item_url):
        log.debug(f'Inserting item for Telegram user {telegram_user_id}.')
        db_user = await self._get_db_user(telegram_user_id=telegram_user_id)
        if db_user is not None:
            log.debug(f'Fetched DB user ID {db_user.id} for new item.')
            new_item = Item(
                user_id=db_user.id,
                item_url_digest=digest(item_url))
            self.db_session.add(new_item)
            await self.db_session.flush()

    async def _get_db_user(self, telegram_user_id) -> DbUser:
        q = await self.db_session.execute(select(DbUser).where(DbUser.telegram_user_id==telegram_user_id))
        return q.scalars().one_or_none()

    async def get_user_registration(self, telegram_user_id) -> User:
        log.debug(f'Fetching user information for Telegram user {telegram_user_id}.')
        db_user = await self._get_db_user(telegram_user_id=telegram_user_id)
        if db_user is None:
            return None
        else:
            return User(db_user=db_user)


class CustomServer(BaseServer):
    def install_signal_handlers(self) -> None:
        log.warning(f'Server not installing signal handlers.')
        pass


@dataclass
class WebhookUpdate:
    """Simple dataclass to wrap a custom update type"""
    user_id: int


class CustomContext(CallbackContext[ExtBot, dict, dict, dict]):
    """
    Custom CallbackContext class that makes `user_data` available for updates of type
    `WebhookUpdate`.
    """
    @classmethod
    def from_update(
        cls,
        update: object,
        application: "Application",
    ) -> "CustomContext":
        if isinstance(update, WebhookUpdate):
            return cls(application=application, user_id=update.user_id)
        return super().from_update(update, application)


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Send a message when the command /start is issued."""
    user: TelegramUser = update.effective_user
    if user.is_bot:
        log.warning(f'Ignoring bot user {user.id}.')
        return
    log.info(f'Fetching registration data for Telegram user ID {user.id}...')
    pocket_user: User = await get_user_registration(telegram_user_id=user.id)
    user_response = None
    user_keyboard = []
    if pocket_user is None or pocket_user.pocket_access_token is None:
        log.info(f'No database registration found for Telegram user ID {user.id}.')
        user_response = rf'{emoji.emojize(":passport_control:")} {user.first_name}, authorization with your Pocket account is needed.'
        user_keyboard = [
            [
                InlineKeyboardButton("Authorize", callback_data=str(ACTION_AUTHORIZE)),
                InlineKeyboardButton("Cancel", callback_data=str(ACTION_NONE))
            ]
        ]
    else:
        log.info(f'Found database registration for Telegram user ID {user.id}.')
        user_response = rf'{emoji.emojize(":check_box_with_check:")} {user.first_name}, you are authorized as Pocket user "{pocket_user.pocket_username}".'
        user_keyboard = [
            [
                InlineKeyboardButton("Reauthorize", callback_data=str(ACTION_AUTHORIZE)),
                InlineKeyboardButton("Cancel", callback_data=str(ACTION_NONE))
            ]
        ]
    reply_markup = InlineKeyboardMarkup(user_keyboard)
    await update.message.reply_html(
        text=user_response,
        disable_web_page_preview=True,
        reply_markup=reply_markup
    )
    return START_ACTIVITY


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Send a message when the command /help is issued."""
    await update.message.reply_text("Help!")


async def echo(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Echo the user message."""
    log.info(f'Incoming message from Telegram user ID {update.effective_user.id}.')
    await update.message.reply_text(update.message.text)


async def button(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Parses the CallbackQuery and updates the message text."""
    query = update.callback_query
    # CallbackQueries need to be answered, even if no notification to the user is needed
    # Some clients may have trouble otherwise. See https://core.telegram.org/bots/api#callbackquery
    await query.answer()
    await query.edit_message_text(text=f"Selected option: {query.data}")


async def registration(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Parses the CallbackQuery and updates the message text."""
    user: TelegramUser = update.effective_user
    log.info(f'Registration request from Telegram user ID {user.id}.')
    query = update.callback_query
    # CallbackQueries need to be answered, even if no notification to the user is needed
    # Some clients may have trouble otherwise. See https://core.telegram.org/bots/api#callbackquery
    await query.answer()
    # fetch request token
    callback_url_base = app_config.get('telegram', 'bot_link')
    log.info(f'Fetching Pocket API request token using callback {callback_url_base}.')
    pocket_request_token = Pocket.get_request_token(consumer_key=creds.pocket_api_consumer_key, redirect_uri=callback_url_base)
    log.info(f'Storing pocket request token for Telegram user ID {user.id}.')
    await store_request_token(telegram_user_id=user.id, pocket_request_token=pocket_request_token)
    callback_url_base = context.bot_data["callback_url"]
    log.info(f'Request token stored. Using request token for to get the auth URL using callback {callback_url_base}.')
    redirect_params = urllib.parse.urlencode({'user_id': str(user.id)})
    redirect_url = f'{callback_url_base}/submit?{redirect_params}'
    pocket_auth_url = Pocket.get_auth_url(code=pocket_request_token, redirect_uri=redirect_url)
    log.info(f'Returning pocket authorization URL to Telegram user ID {user.id}.')
    influxdb_write('bot', 'registration_oauth', 1)
    # send acknowledgement to customer
    await query.edit_message_text(
        text=f'Use [this link]({pocket_auth_url}) to authorize with Pocket.',
        parse_mode='Markdown')


async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Parses the CallbackQuery and updates the message text."""
    query = update.callback_query
    # CallbackQueries need to be answered, even if no notification to the user is needed
    # Some clients may have trouble otherwise. See https://core.telegram.org/bots/api#callbackquery
    await query.answer()
    await query.edit_message_text(text=f"No changes made.")


async def telegram_error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    # do not capture because there's nothing to handle
    log.warning(msg="Telegram Bot Exception while handling an update:", exc_info=context.error)


async def webhook_update(update: WebhookUpdate, context: CustomContext) -> None:
    """Callback that handles the custom updates."""
    chat_member: TelegramChatMember = await context.bot.get_chat_member(chat_id=update.user_id, user_id=update.user_id)
    telegram_user: TelegramUser = chat_member.user
    log.debug(f'Incoming oauth callback for Telegram user ID {update.user_id}.')
    pocket_user: User = await get_user_registration(telegram_user_id=update.user_id)
    pocket_username = None
    response_message = None
    if pocket_user is None:
        log.warning(f'Unexpected registration completion for Telegram user ID {update.user_id}.')
    elif pocket_user.pocket_request_token is None:
        log.warning(f'Missing stored pocket request token for Telegram user ID {update.user_id}.')
    else:
        if pocket_user.pocket_access_token is None:
            log.info(f'Completing registration for Telegram user ID {update.user_id}. Fetching user access token.')
            user_credentials = Pocket.get_credentials(consumer_key=creds.pocket_api_consumer_key, code=pocket_user.pocket_request_token)
            access_token = user_credentials['access_token']
            pocket_username = user_credentials['username']
            log.info(f'Storing Pocket username and access token for Telegram user ID {update.user_id}.')
            await store_access_token(telegram_user_id=update.user_id, pocket_username=pocket_username, pocket_access_token=access_token)
            response_message = rf'{emoji.emojize(":check_box_with_check:")} {telegram_user.first_name}, you are now authorized as Pocket user "{pocket_username}".'
        else:
            response_message = rf'{emoji.emojize(":check_box_with_check:")} {telegram_user.first_name}, you are already authorized as Pocket user "{pocket_user.pocket_username}".'
    influxdb_write('bot', 'registration_callback', 1)
    if response_message is not None:
        await context.bot.send_message(
            chat_id=update.user_id,
            text=response_message,
            parse_mode=ParseMode.HTML
        )


async def startup():
    # create db tables
    async with engine.begin() as conn:
        #log.debug('Dropping database all schema...')
        #await conn.run_sync(Base.metadata.drop_all)
        log.debug('Creating database schema...')
        await conn.run_sync(Base.metadata.create_all)


async def run(webserver):
    await webserver.serve()


async def get_user_registration(telegram_user_id):
    async with async_session() as session:
        async with session.begin():
            pdb = PocketDB(session)
            return await pdb.get_user_registration(telegram_user_id=telegram_user_id)


async def store_request_token(telegram_user_id, pocket_request_token):
    async with async_session() as session:
        async with session.begin():
            pocket_db = PocketDB(session)
            await pocket_db.insert_request_token(telegram_user_id=telegram_user_id, pocket_request_token=pocket_request_token)


async def store_access_token(telegram_user_id, pocket_username, pocket_access_token):
    async with async_session() as session:
        async with session.begin():
            pocket_db = PocketDB(session)
            await pocket_db.insert_access_token(telegram_user_id=telegram_user_id, pocket_username=pocket_username, pocket_access_token=pocket_access_token)


async def store_item(telegram_user_id, item_url):
    async with async_session() as session:
        async with session.begin():
            pocket_db = PocketDB(session)
            await pocket_db.insert_item(telegram_user_id=telegram_user_id, item_url=item_url)


def main():
    global influxdb_bucket
    global influxdb_rw
    log.setLevel(logging.DEBUG)
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        influxdb_bucket = app_config.get('influxdb', 'bucket')
        log.info(f'Starting InfluxDB client to {creds.influxdb_url} using bucket {creds.influxdb_org}::{influxdb_bucket}...')
        influxdb = InfluxDBClient(
            url=creds.influxdb_url,
            token=creds.influxdb_token,
            org=creds.influxdb_org)
        influxdb_rw = influxdb.write_api(write_options=ASYNCHRONOUS)
        log.info('Discovering ngrok tunnel URL...')
        while True:
            try:
                ngrok_tunnel_url = requests.get('http://127.0.0.1:4040/api/tunnels/oauth_callback').json()['public_url']
            except (KeyError, ConnectionError) as e:
                log.debug('Still attempting to discover ngrok tunnel URL ({})...'.format(repr(e)))
                threads.interruptable_sleep.wait(1)
                continue
            log.info('External call-back URL is {}'.format(ngrok_tunnel_url))
            break
        log.info(f'Database startup {db_tablespace}...')
        loop.run_until_complete(startup())
        """Start the bot."""
        # Create the Application and pass it your bot's token.
        context_types = ContextTypes(context=CustomContext)
        application = Application.builder().token(creds.telegram_bot_api_token).context_types(context_types).build()
        application.bot_data["callback_url"] = ngrok_tunnel_url
        # on different commands - answer in Telegram
        application.add_handler(CommandHandler("start", start))
        application.add_handler(CallbackQueryHandler(callback=registration, pattern="^" + str(ACTION_AUTHORIZE) + "$"))
        application.add_handler(CallbackQueryHandler(callback=cancel, pattern="^" + str(ACTION_NONE) + "$"))
        application.add_handler(CommandHandler("help", help_command))

        # on non command i.e message - echo the message on Telegram
        application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, echo))
        application.add_handler(TypeHandler(type=WebhookUpdate, callback=webhook_update))

        # error handling
        application.add_error_handler(callback=telegram_error_handler)


        async def oauth_callback(request: Request) -> PlainTextResponse:
            """
            Handle incoming webhook updates by also putting them into the `update_queue` if
            the required parameters were passed correctly.
            """
            influxdb_write('web', 'registration_callback', 1)
            log.info(f'{request.method} request, headers: {request.headers}, {request.query_params=}, {request.path_params=}')
            try:
                user_id = int(request.query_params["user_id"])
            except KeyError:
                return PlainTextResponse(
                    status_code=HTTPStatus.BAD_REQUEST,
                    content="Please pass `user_id` as query parameter.",
                )
            except ValueError:
                return PlainTextResponse(
                    status_code=HTTPStatus.BAD_REQUEST,
                    content="The `user_id` must be an integer!",
                )
            log.debug(f'Invoking custom update {user_id=}')
            await application.update_queue.put(WebhookUpdate(user_id=user_id))
            return RedirectResponse(url=app_config.get('telegram', 'bot_link'))


        async def health(_: Request) -> PlainTextResponse:
            """For the health endpoint, reply with a simple plain text message."""
            return PlainTextResponse(content="The bot is still running fine :)")


        # block until exit
        log.info('Setting up web server...')
        starlette_app = Starlette(
            routes=[
                Route("/ping", health, methods=["GET"]),
                Route("/submit", oauth_callback, methods=["POST", "GET"])
            ]
        )
        webserver = CustomServer(
            config=ServerConfig(
                app=starlette_app,
                port=8080,
                use_colors=False,
                host="127.0.0.1",
            )
        )
        log.info('Starting web server...')
        asyncio.run_coroutine_threadsafe(webserver.serve(), loop)
        influxdb_write('app', 'startup', 1)
        log.info('Starting Telegram Bot...')
        application.run_polling()
        log.info('Shutting down...')
        webserver.shutdown()
        log.info('Web server shut down...')
    finally:
        die()
        zmq_term()
        loop.close()
    bye()


if __name__ == "__main__":
    main()