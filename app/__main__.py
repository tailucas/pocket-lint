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
    pocket_api_consumer_key: f'opitem:"Pocket" opfield:.credential' = None # type: ignore
    aes_sym_key: f'opitem:"AES.{APP_NAME}" opfield:.password' = None # type: ignore
    influxdb_org: f'opitem:"InfluxDB" opfield:{influx_creds_section}.org' = None # type: ignore
    influxdb_token: f'opitem:"InfluxDB" opfield:{APP_NAME}.token' = None # type: ignore
    influxdb_url: f'opitem:"InfluxDB" opfield:{influx_creds_section}.url' = None # type: ignore
    # FIXME: remove
    pocket_api_access_token: f'opitem:"Pocket" opfield:user.token' = None # type: ignore
    pocket_api_request_token: f'opitem:"Pocket" opfield:user.request_token' = None # type: ignore
    pocket_username: f'opitem:"Pocket" opfield:user.username' = None # type: ignore

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
    User as TelegramUser
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
from starlette.responses import PlainTextResponse, Response
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
    log.info(f'Digest request {payload=}')
    return SHA384.new(data=bytearray(payload, encoding='utf-8')).hexdigest()


def encrypt(header, payload):
    log.info(f'Encryption request {header=}, {payload=}')
    header = bytearray(header, encoding='utf-8')
    data = bytearray(payload, encoding='utf-8')
    key = b64decode(creds.aes_sym_key)
    cipher = AES.new(key, AES.MODE_GCM)
    cipher.update(header)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    json_k = [ 'nonce', 'header', 'ciphertext', 'tag' ]
    json_v = [ b64encode(x).decode('utf-8') for x in (cipher.nonce, header, ciphertext, tag) ]
    log.info(f'Encryption complete {json_k=}, {json_v=}')
    return json.dumps(dict(zip(json_k, json_v)))


def decrypt(payload):
    if payload is None:
        return
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
    pocket_request_token_digest = Column(String(96))
    pocket_user_name = Column(JSON)
    pocket_user_name_digest = Column(String(96))
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
        self.pocket_user_name = decrypt(db_user.pocket_user_name)
        self.pocket_user_name_digest = db_user.pocket_user_name_digest


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

    async def insert_access_token(self, telegram_user_id, pocket_user_name, pocket_access_token):
        log.debug(f'Inserting ACCESS token for Telegram user {telegram_user_id}.')
        q = update(DbUser).where(DbUser.telegram_user_id == telegram_user_id)
        q = q.values(pocket_user_name=encrypt(str(telegram_user_id), pocket_user_name))
        q = q.values(pocket_user_name_digest=digest(pocket_user_name))
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


class Book(Base):
    __tablename__ = 'books'
    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)


class BookDAL():
    def __init__(self, db_session: Session):
        self.db_session = db_session

    async def create_book(self, name):
        log.info(f'Creating book...')
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


class CustomServer(BaseServer):
    def install_signal_handlers(self) -> None:
        log.warning(f'Server not installing signal handlers.')
        pass


@dataclass
class WebhookUpdate:
    """Simple dataclass to wrap a custom update type"""
    user_id: int
    payload: str


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
    log.debug(f'Fetching registration data for Telegram user ID {user.id}...')
    pocket_user: User = None
    async with async_session() as session:
        async with session.begin():
            pdb = PocketDB(session)
            pocket_user = await pdb.get_user_registration(telegram_user_id=user.id)
    user_response = None
    user_keyboard = []
    if pocket_user is None:
        log.debug(f'No database registration found for Telegram user ID {user.id}.')
        user_response = rf'{emoji.emojize(":passport_control:")} {user.first_name}, authorization with your Pocket account is needed.'
        user_keyboard = [
            [
                InlineKeyboardButton("Authorize", callback_data=str(ACTION_AUTHORIZE)),
                InlineKeyboardButton("Cancel", callback_data=str(ACTION_NONE))
            ]
        ]
    else:
        log.debug(f'Found database registration for Telegram user ID {user.id}.')
        user_response = rf'{emoji.emojize(":check_box_with_check:")} {user.first_name}, you are authorized as Pocket user {pocket_user.pocket_user_name}.'
        user_keyboard = [
            [
                InlineKeyboardButton("Reauthorize", callback_data=str(ACTION_AUTHORIZE)),
                InlineKeyboardButton("Cancel", callback_data=str(ACTION_NONE))
            ]
        ]
    reply_markup = InlineKeyboardMarkup(user_keyboard)
    await update.message.reply_html(
        text=user_response,
        reply_markup=reply_markup
    )
    return START_ACTIVITY


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Send a message when the command /help is issued."""
    await update.message.reply_text("Help!")


async def echo(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Echo the user message."""
    log.info(f'Incoming message from user ID {update.effective_user.id}.')
    async with async_session() as session:
        async with session.begin():
            book_dal = BookDAL(session)
            book_name = str(time.time())
            await book_dal.create_book(name=f'time is {book_name}')

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
    log.info(f'Registration request from user ID {user.id}.')
    query = update.callback_query
    # CallbackQueries need to be answered, even if no notification to the user is needed
    # Some clients may have trouble otherwise. See https://core.telegram.org/bots/api#callbackquery
    await query.answer()
    log.info(f'Fetching Pocket API request token.')
    # TODO
    callback_url_base = context.bot_data["callback_url"]
    # fetch request token
    log.info(f'Fetching Pocket API request token, using callback {callback_url_base}.')
    pocket_request_token = creds.pocket_api_request_token
    #pocket_request_token = Pocket.get_request_token(consumer_key=consumer_key, redirect_uri=r_url)
    log.info(f'Storing request token.')
    await store_request_token(telegram_user_id=user.id, pocket_request_token=pocket_request_token)
    log.info(f'Using request token for to get the auth URL, using callback {callback_url_base}.')
    #pocket_auth_url = Pocket.get_auth_url(code=request_token, redirect_uri=redirect_url)
    redirect_params = urllib.parse.urlencode({'user_id': str(user.id), 'payload': digest(pocket_request_token)})
    redirect_url = f'{callback_url_base}/oauth_callback?{redirect_params}'
    # send acknowledgement to customer
    await query.edit_message_text(
        text=f'Use [this link]({redirect_url}) to authorize with Pocket.',
        parse_mode='MarkdownV2')


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
    log.info(f'{update=}: {context=}')
    chat_member = await context.bot.get_chat_member(chat_id=update.user_id, user_id=update.user_id)
    payloads = context.user_data.setdefault("payloads", [])
    payloads.append(update.payload)
    combined_payloads = "</code>\n• <code>".join(payloads)
    text = (
        f"The user {chat_member.user.mention_html()} has sent a new payload. "
        f"So far they have sent the following payloads: \n\n• <code>{combined_payloads}</code>"
    )
    await context.bot.send_message(
        #chat_id=context.bot_data["admin_chat_id"], text=text, parse_mode=ParseMode.HTML
        chat_id=update.user_id, text=text, parse_mode=ParseMode.HTML
    )


async def startup():
    log.info('Database startup, creating schema...')
    # create db tables
    async with engine.begin() as conn:
        #await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    log.info('Schema created.')


async def run(webserver):
    await webserver.serve()


async def store_book():
    async with async_session() as session:
        async with session.begin():
            book_dal = BookDAL(session)
            book_name = str(time.time())
            await book_dal.create_book(name=f'time is {book_name}')


async def store_request_token(telegram_user_id, pocket_request_token):
    async with async_session() as session:
        async with session.begin():
            pocket_db = PocketDB(session)
            await pocket_db.insert_request_token(telegram_user_id=telegram_user_id, pocket_request_token=pocket_request_token)


async def store_access_token(telegram_user_id, pocket_user_name, pocket_access_token):
    async with async_session() as session:
        async with session.begin():
            pocket_db = PocketDB(session)
            await pocket_db.insert_access_token(telegram_user_id=telegram_user_id, pocket_user_name=pocket_user_name, pocket_access_token=pocket_access_token)


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
        log.info(f'Starting database at {db_tablespace}...')
        loop.run_until_complete(startup())
        log.info('Setting up Pocket connection...')
        pocket_request_token = creds.pocket_api_request_token
        pocket_access_token = creds.pocket_api_access_token
        username = creds.pocket_username
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
        real_data = None
        item_url = None
        for item_key, item_data in real_items.items():
            log.info(f'{item_key=}: {item_data!s}')
            item_url = item_data['given_url']
            real_data = item_data

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

        telegram_user_id=123456
        log.info(f'Storing request token...')
        loop.run_until_complete(store_request_token(telegram_user_id=telegram_user_id, pocket_request_token=pocket_request_token))
        log.info(f'Adding book...')
        loop.run_until_complete(store_book())
        log.info(f'Storing access token...')
        username='foobar'
        loop.run_until_complete(store_access_token(telegram_user_id=telegram_user_id, pocket_user_name=username, pocket_access_token=pocket_access_token))
        log.info(f'Storing item...')
        loop.run_until_complete(store_item(telegram_user_id=telegram_user_id, item_url=item_url))

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


        async def custom_updates(request: Request) -> PlainTextResponse:
            """
            Handle incoming webhook updates by also putting them into the `update_queue` if
            the required parameters were passed correctly.
            """
            log.info(f'Got custom update {request=}')
            try:
                user_id = int(request.query_params["user_id"])
                payload = request.query_params["payload"]
            except KeyError:
                return PlainTextResponse(
                    status_code=HTTPStatus.BAD_REQUEST,
                    content="Please pass both `user_id` and `payload` as query parameters.",
                )
            except ValueError:
                return PlainTextResponse(
                    status_code=HTTPStatus.BAD_REQUEST,
                    content="The `user_id` must be a string!",
                )
            log.info(f'Invoking custom update {user_id=}, {payload=}')
            await application.update_queue.put(WebhookUpdate(user_id=user_id, payload=payload))
            return PlainTextResponse("Thank you for the submission! It's being forwarded.")


        async def health(_: Request) -> PlainTextResponse:
            """For the health endpoint, reply with a simple plain text message."""
            return PlainTextResponse(content="The bot is still running fine :)")


        async def oauth_callback(request: Request) -> PlainTextResponse:
            """
            Handle incoming webhook updates by also putting them into the `update_queue` if
            the required parameters were passed correctly.
            """
            log.info(f'Got custom update {request=}')
            try:
                user_id = int(request.query_params["user_id"])
                payload = request.query_params["payload"]
            except KeyError:
                return PlainTextResponse(
                    status_code=HTTPStatus.BAD_REQUEST,
                    content="Please pass both `user_id` and `payload` as query parameters.",
                )
            except ValueError:
                return PlainTextResponse(
                    status_code=HTTPStatus.BAD_REQUEST,
                    content="The `user_id` must be a string!",
                )
            log.info(f'Invoking custom update {user_id=}, {payload=}')
            await application.update_queue.put(WebhookUpdate(user_id=user_id, payload=payload))
            return PlainTextResponse("Thank you for the submission! It's being forwarded.")


        # block until exit
        log.info('Setting up web server...')
        starlette_app = Starlette(
            routes=[
                Route("/ping", health, methods=["GET"]),
                Route("/submit", custom_updates, methods=["POST", "GET"]),
                Route("/oauth_callback", oauth_callback, methods=["POST", "GET"]),
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