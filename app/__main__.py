#!/usr/bin/env python
import logging.handlers

import asyncio
import builtins
import emoji
import requests
import simplejson as json
import string
import urllib.parse

from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional, Sequence, Tuple, Union
from uvicorn.server import Server as BaseServer
from uvicorn.config import Config as ServerConfig

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

from pylib import threads
from pylib.threads import bye, die
from pylib.zmq import zmq_term

from base64 import b64encode, b64decode

from pocket import Pocket

from requests.adapters import ConnectionError
from telegram import (
    Update,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    User as TelegramUser,
    ChatMember as TelegramChatMember,
)
from telegram.constants import ParseMode, ChatAction
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

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import declarative_base, sessionmaker, Session

from http import HTTPStatus

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import PlainTextResponse, RedirectResponse
from starlette.routing import Route

db_tablespace = app_config.get('sqlite', 'tablespace_path')
dburl = f'sqlite+aiosqlite:///{db_tablespace}'
engine = create_async_engine(dburl)
async_session = sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
Base = declarative_base()

from sqlalchemy import Column, Integer, String, JSON

from sqlalchemy import update, ForeignKey, UniqueConstraint
from sqlalchemy.future import select
from sqlalchemy.orm import relationship

from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import WriteApi, ASYNCHRONOUS

influxdb_bucket = None
influxdb_rw: WriteApi = None

ACTION_POCKET_PREFIX = "pocket"
ACTION_POCKET_ARCHIVE = f'{ACTION_POCKET_PREFIX}_archive'
ACTION_POCKET_TAG = f'{ACTION_POCKET_PREFIX}_tag'
ACTION_SETTINGS_PREFIX = "settings"
SORT_NEWEST = 1
ACTION_SETTINGS_SORT_NEWEST = f'{ACTION_SETTINGS_PREFIX}_sort_{SORT_NEWEST}'
SORT_OLDEST = 0
ACTION_SETTINGS_SORT_OLDEST = f'{ACTION_SETTINGS_PREFIX}_sort_{SORT_OLDEST}'
ACTION_SETTINGS_AUTO_ARCHIVE_ON = f'{ACTION_SETTINGS_PREFIX}_autoarchive_on'
ACTION_SETTINGS_AUTO_ARCHIVE_OFF = f'{ACTION_SETTINGS_PREFIX}_autoarchive_off'
ACTION_RESET_PICK_OFFSET = "reset_pick_offset"

ACTION_TAG = 3
ACTION_AUTHORIZE = 2
ACTION_NONE = 0

DEFAULT_SORT = SORT_NEWEST
DEFAULT_AUTO_ARCHIVE = False
DEFAULT_TAG_UNTAGGED = '_untagged_'

PICK_TYPE_UNREAD = 0
PICK_TYPE_ARCHIVED = 1
PICK_TYPE_FAVORITE = 2
PICK_TYPE_TAGGING = 4


def influxdb_write(point_name: str, field_name: str, field_value):
    try:
        log.debug(f'Writing InfluxDB point {point_name=}, application={APP_NAME}, device={device_name_base}: {field_name}={field_value!s}')
        influxdb_rw.write(
            bucket=influxdb_bucket,
            record=Point(point_name).tag("application", APP_NAME).tag("device", device_name_base).field(field_name, field_value))
    except Exception:
        log.warning(f'Unable to post to InfluxDB.', exc_info=True)


def digest(payload: str):
    log.debug(f'Digesting {len(payload)} bytes.')
    return SHA384.new(data=bytearray(payload, encoding='utf-8')).hexdigest()


def encrypt(header: str, payload: str):
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


def decrypt(payload: str):
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
    links_items = relationship('DbItem', backref='items', cascade='all, delete-orphan', lazy='dynamic')


class User(object):
    def __init__(self, db_user: DbUser) -> None:
        self.id = db_user.id
        self.telegram_user_id = db_user.telegram_user_id
        log.debug(f'Decrypting database details for Telegram user {self.telegram_user_id}.')
        self.pocket_request_token = decrypt(db_user.pocket_request_token)
        self.pocket_request_token_digest = db_user.pocket_request_token_digest
        self.pocket_access_token = decrypt(db_user.pocket_access_token)
        self.pocket_access_token_digest = db_user.pocket_access_token_digest
        self.pocket_username = decrypt(db_user.pocket_username)
        self.pocket_username_digest = db_user.pocket_username_digest


class DbUserPref(Base):
    __tablename__ = 'user_prefs'
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id'), index=True)
    sort_order = Column(Integer, default=SORT_NEWEST)
    auto_archive = Column(Integer, default=0)


class UserPref(object):
    def __init__(self, user_id: int, db_user_pref: DbUserPref) -> None:
        self.user_id = user_id
        self.sort_order = db_user_pref.sort_order
        if db_user_pref.auto_archive == 1:
            self.auto_archive = True
        else:
            self.auto_archive = False


class DbItem(Base):
    __tablename__ = 'items'
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id'), index=True)
    url_digest = (Column(String(96), index=True))


class DbPickOffset(Base):
    __tablename__ = 'pick_offsets'
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id'), index=True)
    pick_type = Column(Integer, default=0, index=True)
    tag_digest = Column(String(96), index=True)
    offset = Column(Integer, default=0)
    UniqueConstraint(user_id, pick_type, tag_digest)


class PocketDB(object):
    def __init__(self, db_session: Session):
        self.db_session = db_session
        self.loop = asyncio.get_event_loop()

    async def insert_request_token(self, telegram_user_id: int, pocket_request_token: str):
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

    async def insert_access_token(self, telegram_user_id: str, pocket_username: str, pocket_access_token: str):
        log.debug(f'Inserting ACCESS token for Telegram user {telegram_user_id}.')
        q = update(DbUser).where(DbUser.telegram_user_id == telegram_user_id)
        q = q.values(pocket_username=encrypt(str(telegram_user_id), pocket_username))
        q = q.values(pocket_username_digest=digest(pocket_username))
        q = q.values(pocket_access_token=encrypt(str(telegram_user_id), pocket_access_token))
        q = q.values(pocket_access_token_digest=digest(pocket_access_token))
        q.execution_options(synchronize_session="fetch")
        return await self.db_session.execute(q)

    async def get_pick_offset(self, user_id: int, pick_type: str, tag_digest: str) -> int:
        db_offset: DbPickOffset = await self._get_db_pick_offset(user_id=user_id, pick_type=pick_type, tag_digest=tag_digest)
        if db_offset is None:
            return 0
        return db_offset.offset

    async def update_pick_offset(self, user_id: int, pick_type: str, tag: str, offset: int):
        if offset < 0:
            offset = 0
        log.debug(f'Updating pick offset for DB user {user_id}: {pick_type=}, {offset=}. tag? {tag is not None}')
        tag_digest = None
        if tag is not None:
            tag_digest = digest(payload=tag)
        db_offset = await self._get_db_pick_offset(user_id=user_id, pick_type=pick_type, tag_digest=tag_digest)
        if db_offset is None:
            db_offset = DbPickOffset(user_id=user_id, pick_type=pick_type, tag_digest=tag_digest, offset=offset)
        else:
            db_offset.offset = offset
        self.db_session.add(db_offset)
        await self.db_session.flush()

    async def update_user_pref(self, telegram_user_id: int, sort_order: int, auto_archive: bool):
        if sort_order is None and auto_archive is None:
            log.warning(f'No preference specified for Telegram user {telegram_user_id}')
            return
        log.debug(f'Updating preference for Telegram user {telegram_user_id}: {sort_order=}.')
        db_user = await self._get_db_user(telegram_user_id=telegram_user_id)
        if db_user is not None:
            log.debug(f'Fetched DB user ID {db_user.id} for preference update {sort_order=}.')
            db_pref = await self._get_db_user_pref(user_id=db_user.id)
            if db_pref is None:
                if sort_order is None:
                    sort_order = DEFAULT_SORT
                if auto_archive is None:
                    auto_archive = DEFAULT_AUTO_ARCHIVE
                db_pref = DbUserPref(user_id=db_user.id, sort_order=sort_order, auto_archive=auto_archive)
            else:
                if sort_order is not None:
                    db_pref.sort_order = sort_order
                if auto_archive is not None:
                    if auto_archive:
                        db_pref.auto_archive = 1
                    else:
                        db_pref.auto_archive = 0
            self.db_session.add(db_pref)
            await self.db_session.flush()
            # reset offsets
            await self._reset_pick_offset(user_id=db_user.id)
        else:
            log.warning(f'No DB user to support item for Telegram user ID {telegram_user_id}, {sort_order=}')

    async def _get_db_item(self, user_id: int) -> DbItem:
        q = await self.db_session.execute(select(DbItem).where(DbItem.user_id==user_id))
        return q.scalars().one_or_none()

    async def _reset_pick_offset(self, user_id: int) -> None:
        log.debug(f'Resetting pick offsets for DB user {user_id}')
        q = update(DbPickOffset).where(DbPickOffset.user_id == user_id)
        q = q.values(offset=0)
        q.execution_options(synchronize_session="fetch")
        return await self.db_session.execute(q)

    async def _get_db_pick_offset(self, user_id: int, pick_type: int, tag_digest: str) -> DbPickOffset:
        where_condition = (
            (DbPickOffset.user_id==user_id) &
            (DbPickOffset.pick_type==pick_type) &
            (DbPickOffset.tag_digest==tag_digest)
        )
        log.debug(f'Fetching {pick_type=} offset for DB user {user_id} with tag digest {tag_digest}')
        q = await self.db_session.execute(select(DbPickOffset).where(where_condition))
        return q.scalars().one_or_none()

    async def _get_db_user_pref(self, user_id: int) -> DbUserPref:
        log.debug(f'Fetching preference for DB user {user_id}')
        q = await self.db_session.execute(select(DbUserPref).where(DbUserPref.user_id==user_id))
        return q.scalars().one_or_none()

    async def _get_db_user(self, telegram_user_id: int) -> DbUser:
        q = await self.db_session.execute(select(DbUser).where(DbUser.telegram_user_id==telegram_user_id))
        return q.scalars().one_or_none()

    async def get_user_registration(self, telegram_user_id: int) -> User:
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


async def validate(command_name: str, update: Update) -> User:
    user: TelegramUser = update.effective_user
    if user.is_bot:
        log.warning(f'{command_name}: ignoring bot user {user.id}.')
        return
    log.info(f'{command_name}: Telegram user ID {user.id} (language {user.language_code}).')
    influxdb_write('command', f'{command_name}', 1)
    db_user: User = await get_user_registration(telegram_user_id=user.id)
    if db_user is None or db_user.pocket_access_token is None:
        log.info(f'No database registration found for Telegram user ID {user.id}.')
        user_response = rf'{emoji.emojize(":passport_control:")} {user.first_name}, authorization with your Pocket account is needed.'
        user_keyboard = [
            [
                InlineKeyboardButton("Authorize", callback_data=str(ACTION_AUTHORIZE)),
                InlineKeyboardButton("Cancel", callback_data=str(ACTION_NONE))
            ]
        ]
        reply_markup = InlineKeyboardMarkup(user_keyboard)
        await update.message.reply_html(
            text=user_response,
            reply_markup=reply_markup
        )
    return db_user


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user: TelegramUser = update.effective_user
    db_user: User = await validate(command_name='start', update=update)
    if db_user is None:
        return
    user_response = rf'{emoji.emojize(":check_box_with_check:")} {user.first_name}, you are authorized as Pocket user "{db_user.pocket_username}".'
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
    return ConversationHandler.END


async def settings(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user: TelegramUser = update.effective_user
    db_user: User = await validate(command_name='settings', update=update)
    if db_user is None:
        return
    response_message = rf'<tg-emoji emoji-id="1">{emoji.emojize(":gear:")}</tg-emoji> ' \
        f'{user.first_name}, hanging sort order will reset your pick positions. ' \
        'Auto-archive updates Pocket when picking a link to archive the item.'
    user_keyboard = [
        [
            InlineKeyboardButton("Sort Newest", callback_data=ACTION_SETTINGS_SORT_NEWEST),
            InlineKeyboardButton("Sort Oldest", callback_data=ACTION_SETTINGS_SORT_OLDEST)
        ],
        [
            InlineKeyboardButton("Auto-archive on", callback_data=ACTION_SETTINGS_AUTO_ARCHIVE_ON),
            InlineKeyboardButton("Auto-archive off", callback_data=ACTION_SETTINGS_AUTO_ARCHIVE_OFF)
        ],
        [
            InlineKeyboardButton("Cancel", callback_data=str(ACTION_NONE))
        ]
    ]
    reply_markup = InlineKeyboardMarkup(user_keyboard)
    await update.message.reply_html(
        text=response_message,
        reply_markup=reply_markup
    )
    return ConversationHandler.END


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user: TelegramUser = update.effective_user
    db_user: User = await validate(command_name='help', update=update)
    if db_user is None:
        return
    help_url = app_config.get('telegram', 'help_url')
    message = rf'{emoji.emojize(":light_bulb:")} {user.first_name}, the documentation is [here]({help_url}).'
    await update.message.reply_text(
        text=message,
        parse_mode=ParseMode.MARKDOWN
    )
    return ConversationHandler.END


async def echo(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    log.info(f'Incoming message from Telegram user ID {update.effective_user.id}.')
    await update.message.reply_text(update.message.text)
    return ConversationHandler.END


async def pick_from_pocket(db_user: User, update: Update, context: ContextTypes.DEFAULT_TYPE, pick_type=PICK_TYPE_UNREAD, tag=None) -> String:
    user: TelegramUser = update.effective_user
    await context.bot.send_chat_action(chat_id=update.effective_message.chat_id, action=ChatAction.TYPING)
    user_follow_up = None
    user_keyboard = None
    item_id = None
    offset = await get_offset(user_id=db_user.id, pick_type=pick_type, tag=tag)
    user_prefs = await get_user_prefs(db_user=db_user)
    if user_prefs is None:
        log.debug(f'No user preferences found for Telegram user ID {user.id}.')
        sort_order = DEFAULT_SORT
        auto_archive = DEFAULT_AUTO_ARCHIVE
    else:
        sort_order = user_prefs.sort_order
        auto_archive = user_prefs.auto_archive
    if sort_order == SORT_NEWEST:
        sort_order = 'newest'
    else:
        sort_order = 'oldest'
    log.debug(f'Fetching item {pick_type=} using {offset=}, {sort_order=}, {auto_archive=}')
    pocket_instance = Pocket(creds.pocket_api_consumer_key, db_user.pocket_access_token)
    log.info(f'Fetching Pocket item for Telegram user ID {user.id} (with auto-archive? {auto_archive}).')
    # FIXME: bit masking
    if pick_type == PICK_TYPE_ARCHIVED:
        items = pocket_instance.get(state='archive', sort=sort_order, detailType='complete', count=1, offset=offset)
    elif pick_type == PICK_TYPE_FAVORITE:
        items = pocket_instance.get(favorite=1, sort=sort_order, detailType='complete', count=1, offset=offset)
    elif pick_type == PICK_TYPE_TAGGING:
        items = pocket_instance.get(tag=tag, sort=sort_order, detailType='complete', count=1, offset=offset)
        if tag == DEFAULT_TAG_UNTAGGED:
            user_follow_up = rf'<tg-emoji emoji-id="1">{emoji.emojize(":light_bulb:")}</tg-emoji> Send a space-separated list of words to use as tags, if you want to tag this.'
    elif pick_type == PICK_TYPE_UNREAD:
        items = pocket_instance.get(sort=sort_order, detailType='complete', count=1, offset=offset)
        if not auto_archive:
            user_follow_up = rf'<tg-emoji emoji-id="1">{emoji.emojize(":bookmark_tabs:")}</tg-emoji> Update Pocket?'
            user_keyboard = [
                [
                    InlineKeyboardButton("Archive", callback_data=ACTION_POCKET_ARCHIVE),
                    InlineKeyboardButton("Cancel", callback_data=str(ACTION_NONE))
                ],
            ]
    else:
        log.warning(f'No valid pick type selected: {pick_type}.')
        return
    status: str = None
    # extract and log headers
    if len(items) == 2:
        h: dict = items[1]
        log.debug(f'Pocket response headers ({len(h)}): {h.keys()}')
        source = h['X-Source']
        status = h['Status']
        server = h['Server']
        cache = h['X-Cache']
        cdn_pop = h['X-Amz-Cf-Pop']
        limit_user = h['X-Limit-User-Limit']
        limit_user_remain = h['X-Limit-User-Remaining']
        limit_user_reset = h['X-Limit-User-Reset']
        limit_key = h['X-Limit-Key-Limit']
        limit_key_remain = h['X-Limit-Key-Remaining']
        limit_key_reset = h['X-Limit-Key-Reset']
        log.debug(f'{status} from {source} served by {server} ({cache} via {cdn_pop}). ' \
                    f'User limits: {limit_user_remain} of {limit_user} (resets {limit_user_reset}). ' \
                    f'Key limits: {limit_key_remain} of {limit_key} (resets {limit_key_reset}).')
        for k,v in h.items():
            if k.startswith('X-Limit'):
                influxdb_write(point_name='pocket', field_name=k, field_value=int(v))
    if status.startswith('200'):
        if len(items) == 0 or len(items[0]['list']) == 0:
            response_message = rf'<tg-emoji emoji-id="1">{emoji.emojize(":floppy_disk:")}</tg-emoji> No links found, sorry.'
            if offset > 0:
                user_follow_up = rf'<tg-emoji emoji-id="1">{emoji.emojize(":light_bulb:")}</tg-emoji> Try resetting the index for this pick type.'
                user_keyboard = [
                    [
                        InlineKeyboardButton("Reset", callback_data=ACTION_RESET_PICK_OFFSET),
                        InlineKeyboardButton("Cancel", callback_data=str(ACTION_NONE))
                    ],
                ]
                context.user_data['user_id'] = db_user.id
                context.user_data['pick_type'] = pick_type
                context.user_data['tag'] = tag
        else:
            log.debug(f'Pocket response items {items[0]!s}')
            real_items = items[0]['list']
            item_url = None
            item_title = None
            item_detail = None
            item_read_time = None
            item_tags = None
            for item_key, item_data in real_items.items():
                log.debug(f'{item_key=}: {item_data!s}')
                item_id = item_data['item_id']
                context.user_data['pocket_item_id'] = item_id
                item_url = item_data['given_url']
                if 'given_title' in item_data.keys():
                    item_title = item_data['given_title']
                if 'excerpt' in item_data.keys():
                    item_detail = item_data['excerpt']
                if 'time_to_read' in item_data.keys():
                    item_read_time = item_data['time_to_read']
                if 'tags' in item_data.keys():
                    item_tags = item_data['tags'].keys()
            if item_title:
                response_message = rf'<a href="{item_url}">{item_title}</a>'
                if item_detail:
                    response_message += rf': <i>{item_detail}</i>'
                if item_read_time:
                    response_message += rf' ({item_read_time} minute read)'
            else:
                response_message = rf'{item_url}'
            if item_tags:
                tag_list = ', '.join(sorted(item_tags))
                response_message += rf' tags: <b>{tag_list}</b>'
            offset += 1
            log.debug(f'Saving updated {pick_type=} offset to DB {offset=}, tagged? {tag is not None}')
            await update_offset(user_id=db_user.id, pick_type=pick_type, tag=tag, offset=offset)
    else:
        log.warning(f'Bad status from Pocket {status}.')
        response_message = rf'<tg-emoji emoji-id="1">{emoji.emojize(":stop_sign:")}</tg-emoji> Sorry, please try again later.'
        # https://getpocket.com/developer/docs/errors
        if status.startswith('401'):
            response_message = rf'<tg-emoji emoji-id="1">{emoji.emojize(":stop_sign:")}</tg-emoji> Permissions problem. Try /start command.'
        elif status.startswith('503'):
            response_message = rf'<tg-emoji emoji-id="1">{emoji.emojize(":construction:")}</tg-emoji> Pocket server is down for maintenance.'
    await update.message.reply_text(
        text=response_message,
        parse_mode=ParseMode.HTML
    )
    if user_follow_up and user_keyboard is None:
        await update.message.reply_html(
            text=user_follow_up,
        )
    elif user_keyboard is not None:
        reply_markup = InlineKeyboardMarkup(user_keyboard)
        await update.message.reply_html(
            text=user_follow_up,
            reply_markup=reply_markup
        )
    # auto-archive if not already archived
    if pick_type != PICK_TYPE_ARCHIVED and item_id and user_prefs.auto_archive:
        log.debug(f'Auto-archive of Pocket item {item_id} based on user-preference.')
        pocket_instance.archive(item_id=item_id).commit()
    return item_id


async def pick(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    db_user: User = await validate(command_name='pick', update=update)
    if db_user is None:
        return
    await pick_from_pocket(db_user=db_user, update=update, context=context)
    return ConversationHandler.END


async def archived(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    db_user: User = await validate(command_name='archived', update=update)
    if db_user is None:
        return
    await pick_from_pocket(db_user=db_user, update=update, context=context, pick_type=PICK_TYPE_ARCHIVED)
    return ConversationHandler.END


async def favorite(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    db_user: User = await validate(command_name='favorite', update=update)
    if db_user is None:
        return
    await pick_from_pocket(db_user=db_user, update=update, context=context, pick_type=PICK_TYPE_FAVORITE)
    return ConversationHandler.END


async def untagged(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    db_user: User = await validate(command_name='untagged', update=update)
    if db_user is None:
        return
    item_id = await pick_from_pocket(db_user=db_user, update=update, context=context, pick_type=PICK_TYPE_TAGGING, tag=DEFAULT_TAG_UNTAGGED)
    log.debug(f'Returned untagged Pocket item ID {item_id} for tagging context handler.')
    context.user_data['pocket_item_id'] = item_id
    return ACTION_TAG


async def tagged(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    db_user: User = await validate(command_name='tagged', update=update)
    if db_user is None:
        return
    if len(context.args) == 1:
        await pick_from_pocket(db_user=db_user, update=update, context=context, pick_type=PICK_TYPE_TAGGING, tag=str(context.args[0]))
    else:
        await update.message.reply_html(
            text=rf'<tg-emoji emoji-id="1">{emoji.emojize(":light_bulb:")}</tg-emoji> Add a tag to this command like <pre>/tagged fun</pre>.',
        )
    return ConversationHandler.END


async def button(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    # CallbackQueries need to be answered, even if no notification to the user is needed
    # Some clients may have trouble otherwise. See https://core.telegram.org/bots/api#callbackquery
    await query.answer()
    await query.edit_message_text(text=f"Selected option: {query.data}")
    return ConversationHandler.END


async def configure(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user: TelegramUser = update.effective_user
    db_user: User = await validate(command_name='configure', update=update)
    if db_user is None:
        return
    query = update.callback_query
    # CallbackQueries need to be answered, even if no notification to the user is needed
    # Some clients may have trouble otherwise. See https://core.telegram.org/bots/api#callbackquery
    await query.answer()
    user_selection = query.data
    log.debug(f'Telegram user ID {user.id} preference update {user_selection=}')
    if user_selection == ACTION_SETTINGS_SORT_NEWEST:
        await update_user_pref(telegram_user_id=user.id, sort_order=SORT_NEWEST)
    elif user_selection == ACTION_SETTINGS_SORT_OLDEST:
        await update_user_pref(telegram_user_id=user.id, sort_order=SORT_OLDEST)
    elif user_selection == ACTION_SETTINGS_AUTO_ARCHIVE_ON:
        await update_user_pref(telegram_user_id=user.id, auto_archive=True)
    elif user_selection == ACTION_SETTINGS_AUTO_ARCHIVE_OFF:
        await update_user_pref(telegram_user_id=user.id, auto_archive=False)
    else:
        log.warning(f'Telegram user ID {user.id} has specified an invalid preference {user_selection=}')
    influxdb_write('bot', 'settings_updated', 1)
    await query.edit_message_text(
        text=f'{emoji.emojize(":check_mark_button:")} Settings updated.',
        parse_mode=ParseMode.MARKDOWN)
    return ConversationHandler.END


async def registration(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user: TelegramUser = update.effective_user
    db_user: User = await validate(command_name='registration', update=update)
    if db_user is None:
        return
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
    await query.edit_message_text(
        text=f'Use [this link]({pocket_auth_url}) to authorize with Pocket. ' \
            'Please ensure that your mobile browser is already logged into ' \
            'Pocket before using this link due to a bug in the Pocket web authorization ' \
            'workflow.',
        parse_mode=ParseMode.MARKDOWN)
    return ConversationHandler.END


async def pocket(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user: TelegramUser = update.effective_user
    db_user: User = await validate(command_name='pocket', update=update)
    if db_user is None:
        return
    query = update.callback_query
    # CallbackQueries need to be answered, even if no notification to the user is needed
    # Some clients may have trouble otherwise. See https://core.telegram.org/bots/api#callbackquery
    await query.answer()
    if 'pocket_item_id' not in context.user_data.keys():
        log.warning(f'Unable to tag without an item ID present.')
        return ConversationHandler.END
    item_id = int(context.user_data['pocket_item_id'])
    pocket_instance = Pocket(creds.pocket_api_consumer_key, db_user.pocket_access_token)
    pocket_instance.archive(item_id=item_id).commit()
    await query.edit_message_text(
        text=f'{emoji.emojize(":check_mark_button:")} Item archived.',
        parse_mode=ParseMode.MARKDOWN)
    return ConversationHandler.END


async def reset_pick_offset(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    db_user: User = await validate(command_name='reset_pick_offset', update=update)
    if db_user is None:
        return
    query = update.callback_query
    # CallbackQueries need to be answered, even if no notification to the user is needed
    # Some clients may have trouble otherwise. See https://core.telegram.org/bots/api#callbackquery
    await query.answer()
    if 'user_id' not in context.user_data.keys():
        log.warning(f'Unable to reset without an user ID present.')
        return ConversationHandler.END
    await context.bot.send_chat_action(chat_id=update.effective_message.chat_id, action=ChatAction.TYPING)
    user_id = int(context.user_data['user_id'])
    pick_type = int(context.user_data['pick_type'])
    tag = context.user_data['tag']
    await update_offset(user_id=user_id, pick_type=pick_type, tag=tag, offset=0)
    await query.edit_message_text(
        text=f'{emoji.emojize(":check_mark_button:")} Index reset.',
        parse_mode=ParseMode.MARKDOWN)
    return ConversationHandler.END


async def tag(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    user: TelegramUser = update.effective_user
    db_user: User = await validate(command_name='tag', update=update)
    if db_user is None:
        return
    if 'pocket_item_id' not in context.user_data.keys():
        log.warning(f'Unable to tag without an item ID present.')
        return ConversationHandler.END
    await context.bot.send_chat_action(chat_id=update.effective_message.chat_id, action=ChatAction.TYPING)
    tag_string: str = update.message.text
    for mark in string.punctuation:
        if mark in tag_string:
            await update.message.reply_text(f'Do not include symbols like "{mark}". Just a list of words separated by spaces.')
            return ACTION_TAG
    tag_words = tag_string.split(' ')
    tags = []
    for tag_word in tag_words:
        tags.append(tag_word.strip())
    item_id = int(context.user_data['pocket_item_id'])
    log.debug(f'Telegram user ID {user.id} adds {len(tags)} tags to item {item_id}.')
    pocket_instance = Pocket(creds.pocket_api_consumer_key, db_user.pocket_access_token)
    pocket_instance.tags_add(item_id=item_id, tags=','.join(tags)).commit()
    await update.message.reply_text(f'{len(tags)} tag(s) added to this Pocket link.')
    offset = await get_offset(user_id=db_user.id, pick_type=PICK_TYPE_TAGGING, tag=DEFAULT_TAG_UNTAGGED)
    log.debug(f'Correcting untagged offset {offset} for Telegram user ID {user.id}.')
    await update_offset(user_id=db_user.id, pick_type=PICK_TYPE_TAGGING, tag=DEFAULT_TAG_UNTAGGED, offset=offset-1)
    return ConversationHandler.END


async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    db_user: User = await validate(command_name='cancel', update=update)
    if db_user is None:
        return
    query = update.callback_query
    # CallbackQueries need to be answered, even if no notification to the user is needed
    # Some clients may have trouble otherwise. See https://core.telegram.org/bots/api#callbackquery
    await query.answer()
    await query.edit_message_text(text=f"No changes made.")
    return ConversationHandler.END


async def telegram_error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    # do not capture because there's nothing to handle
    log.warning(msg="Telegram Bot Exception while handling an update:", exc_info=context.error)
    return ConversationHandler.END


async def webhook_update(update: WebhookUpdate, context: CustomContext) -> None:
    chat_member: TelegramChatMember = await context.bot.get_chat_member(chat_id=update.user_id, user_id=update.user_id)
    telegram_user: TelegramUser = chat_member.user
    log.debug(f'Incoming oauth callback for Telegram user ID {update.user_id}.')
    db_user: User = await get_user_registration(telegram_user_id=update.user_id)
    pocket_username = None
    response_message = None
    if db_user is None:
        log.warning(f'Unexpected registration completion for Telegram user ID {update.user_id}.')
    elif db_user.pocket_request_token is None:
        log.warning(f'Missing stored pocket request token for Telegram user ID {update.user_id}.')
    else:
        if db_user.pocket_access_token is None:
            log.info(f'Completing registration for Telegram user ID {update.user_id}. Fetching user access token.')
            user_credentials = Pocket.get_credentials(consumer_key=creds.pocket_api_consumer_key, code=db_user.pocket_request_token)
            access_token = user_credentials['access_token']
            pocket_username = user_credentials['username']
            log.info(f'Storing Pocket username and access token for Telegram user ID {update.user_id}.')
            await store_access_token(telegram_user_id=update.user_id, pocket_username=pocket_username, pocket_access_token=access_token)
            response_message = rf'{emoji.emojize(":check_box_with_check:")} {telegram_user.first_name}, you are now authorized as Pocket user "{pocket_username}".'
        else:
            response_message = rf'{emoji.emojize(":check_box_with_check:")} {telegram_user.first_name}, you are already authorized as Pocket user "{db_user.pocket_username}".'
    influxdb_write('bot', 'registration_callback', 1)
    if response_message is not None:
        await context.bot.send_message(
            chat_id=update.user_id,
            text=response_message,
            parse_mode=ParseMode.MARKDOWN
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


async def get_user_registration(telegram_user_id: int) -> User:
    async with async_session() as session:
        async with session.begin():
            pdb = PocketDB(session)
            return await pdb.get_user_registration(telegram_user_id=telegram_user_id)


async def get_item(user_id: int) -> DbItem:
    async with async_session() as session:
        async with session.begin():
            pdb = PocketDB(session)
            return await pdb._get_db_item(user_id=user_id)


async def store_request_token(telegram_user_id: int, pocket_request_token: str):
    async with async_session() as session:
        async with session.begin():
            pocket_db = PocketDB(session)
            await pocket_db.insert_request_token(telegram_user_id=telegram_user_id, pocket_request_token=pocket_request_token)


async def store_access_token(telegram_user_id: int, pocket_username: str, pocket_access_token: str):
    async with async_session() as session:
        async with session.begin():
            pocket_db = PocketDB(session)
            await pocket_db.insert_access_token(telegram_user_id=telegram_user_id, pocket_username=pocket_username, pocket_access_token=pocket_access_token)


async def get_offset(user_id: int, pick_type: int, tag: str=None) -> int:
    async with async_session() as session:
        async with session.begin():
            pdb = PocketDB(session)
            tag_digest = None
            if tag is not None:
                tag_digest = digest(tag)
            return await pdb.get_pick_offset(user_id=user_id, pick_type=pick_type, tag_digest=tag_digest)


async def update_offset(user_id: int, pick_type: str, tag: str, offset: int):
    async with async_session() as session:
        async with session.begin():
            pocket_db = PocketDB(session)
            await pocket_db.update_pick_offset(user_id=user_id, pick_type=pick_type, tag=tag, offset=offset)


async def get_user_prefs(db_user: User) -> UserPref:
    async with async_session() as session:
        async with session.begin():
            pdb = PocketDB(session)
            db_user_pref = await pdb._get_db_user_pref(user_id=db_user.id)
            if db_user_pref is None:
                return None
            return UserPref(user_id=db_user.id, db_user_pref=db_user_pref)


async def update_user_pref(telegram_user_id: int, sort_order: int = None, auto_archive: bool = None):
    async with async_session() as session:
        async with session.begin():
            pocket_db = PocketDB(session)
            await pocket_db.update_user_pref(telegram_user_id=telegram_user_id, sort_order=sort_order, auto_archive=auto_archive)


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
        # pocket commands
        command_handlers = [
            CommandHandler("start", start),
            CommandHandler("settings", settings),
            CommandHandler("help", help_command),
            CommandHandler("pick", pick),
            CommandHandler("archived", archived),
            CommandHandler("favorite", favorite),
            CommandHandler("tagged", tagged),
            CallbackQueryHandler(callback=configure, pattern=f'^{ACTION_SETTINGS_PREFIX}.*$'),
            CallbackQueryHandler(callback=registration, pattern="^" + str(ACTION_AUTHORIZE) + "$"),
            CallbackQueryHandler(callback=pocket, pattern=f'^{ACTION_POCKET_PREFIX}.*$'),
            CallbackQueryHandler(callback=reset_pick_offset, pattern=f'^{ACTION_RESET_PICK_OFFSET}$'),
            CallbackQueryHandler(callback=cancel, pattern="^" + str(ACTION_NONE) + "$")
        ]
        tag_handler = ConversationHandler(
            allow_reentry=True,
            entry_points=[CommandHandler("untagged", untagged)],
            states={
                ACTION_TAG: [MessageHandler(filters.TEXT & ~filters.COMMAND, tag)],
            },
            fallbacks=command_handlers
        )
        application.add_handler(tag_handler)
        for handler in command_handlers:
            application.add_handler(handler)
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