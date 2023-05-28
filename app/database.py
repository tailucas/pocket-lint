import asyncio

from pylib import (
    app_config,
    log
)

from .crypto import encrypt, decrypt, digest

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import declarative_base, sessionmaker, Session

db_tablespace = app_config.get('sqlite', 'tablespace_path')
dburl = f'sqlite+aiosqlite:///{db_tablespace}'
engine = create_async_engine(dburl)
async_session = sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
Base = declarative_base()

from sqlalchemy import Column, Integer, String, JSON

from sqlalchemy import update, ForeignKey, UniqueConstraint
from sqlalchemy.future import select
from sqlalchemy.orm import relationship


SORT_NEWEST = 1
SORT_OLDEST = 0
DEFAULT_SORT = SORT_NEWEST
DEFAULT_AUTO_ARCHIVE = False


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
        

async def get_user_registration(telegram_user_id: int) -> User:
    async with async_session() as session:
        async with session.begin():
            pdb = PocketDB(session)
            return await pdb.get_user_registration(telegram_user_id=telegram_user_id)


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


async def db_startup():
    log.info(f'Database startup {db_tablespace}...')
    # create db tables
    async with engine.begin() as conn:
        log.debug('Creating database schema...')
        await conn.run_sync(Base.metadata.create_all)
