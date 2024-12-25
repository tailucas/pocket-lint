#!/usr/bin/env python
import logging.handlers

import asyncio
import builtins
import ngrok

# setup builtins used by pylib init
from . import APP_NAME
builtins.SENTRY_EXTRAS = []
influx_creds_section = 'local'

class CredsConfig:
    sentry_dsn: f'opitem:"Sentry" opfield:{APP_NAME}.dsn' = None  # type: ignore
    cronitor_token: f'opitem:"cronitor" opfield:.password' = None  # type: ignore
    telegram_bot_api_token: f'opitem:"Telegram" opfield:{APP_NAME}.token' = None # type: ignore
    pocket_api_consumer_key: f'opitem:"Pocket" opfield:{APP_NAME}.consumer_key' = None # type: ignore
    ngrok_token: f'opitem:"ngrok" opfield:{APP_NAME}.token' = None  # type: ignore
    aes_sym_key: f'opitem:"AES.{APP_NAME}" opfield:.password' = None # type: ignore
    influxdb_org: f'opitem:"InfluxDB" opfield:{influx_creds_section}.org' = None # type: ignore
    influxdb_token: f'opitem:"InfluxDB" opfield:{APP_NAME}.token' = None # type: ignore
    influxdb_url: f'opitem:"InfluxDB" opfield:{influx_creds_section}.url' = None # type: ignore


# instantiate class
builtins.creds_config = CredsConfig()

from tailucas_pylib import (
    app_config,
    creds,
    log
)

from tailucas_pylib.threads import bye, die
from tailucas_pylib.zmq import zmq_term

from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
    ConversationHandler,
    MessageHandler,
    filters,
    TypeHandler
)

from http import HTTPStatus

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import PlainTextResponse, RedirectResponse
from starlette.routing import Route

from uvicorn.config import Config as ServerConfig

from .database import SORT_NEWEST
from .database import SORT_OLDEST

ACTION_POCKET_PREFIX = "pocket"
ACTION_POCKET_ARCHIVE = f'{ACTION_POCKET_PREFIX}_archive'
ACTION_POCKET_TAG = f'{ACTION_POCKET_PREFIX}_tag'
ACTION_SETTINGS_PREFIX = "settings"
ACTION_SETTINGS_SORT_NEWEST = f'{ACTION_SETTINGS_PREFIX}_sort_{SORT_NEWEST}'
ACTION_SETTINGS_SORT_OLDEST = f'{ACTION_SETTINGS_PREFIX}_sort_{SORT_OLDEST}'
ACTION_SETTINGS_AUTO_ARCHIVE_ON = f'{ACTION_SETTINGS_PREFIX}_autoarchive_on'
ACTION_SETTINGS_AUTO_ARCHIVE_OFF = f'{ACTION_SETTINGS_PREFIX}_autoarchive_off'
ACTION_RESET_PICK_OFFSET = "reset_pick_offset"

ACTION_TAG = 3
ACTION_AUTHORIZE = 2
ACTION_NONE = 0

PICK_TYPE_UNREAD = 0
PICK_TYPE_ARCHIVED = 1
PICK_TYPE_FAVORITE = 2
PICK_TYPE_TAGGING = 4

DEFAULT_TAG_UNTAGGED = '_untagged_'

from .influx import influxdb

from .database import (
    db_startup,
)

from .oauth import (
    WebhookUpdate,
    CustomContext,
    CustomServer,
    health
)

from .bot import (
    start,
    settings,
    help_command,
    pick,
    archived,
    favorite,
    tagged,
    configure,
    registration,
    pocket,
    reset_pick_offset,
    cancel,
    untagged,
    tag,
    echo,
    webhook_update,
    telegram_error_handler
)

from sentry_sdk.integrations.logging import ignore_logger
# Reduce Sentry noise
ignore_logger('telegram.ext.Updater')
ignore_logger('telegram.ext._updater')


async def create_tunnel():
    session = await ngrok.NgrokSessionBuilder().authtoken(creds.ngrok_token).connect()
    tunnel = await session.http_endpoint().listen()
    tunnel_port = app_config.get('tunnel', 'port_number')
    tunnel.forward_tcp(f'localhost:{tunnel_port}')
    return tunnel


def main():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        log.info('Starting ngrok tunnel...')
        ngrok_tunnel = loop.run_until_complete(create_tunnel())
        ngrok_tunnel_url = ngrok_tunnel.url()
        log.info(f'External call-back URL is {ngrok_tunnel_url}')
        loop.run_until_complete(db_startup())
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
            influxdb.write('web', 'registration_callback', 1)
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
                host='localhost',
                port=app_config.getint('tunnel', 'port_number'),
                use_colors=False,
            )
        )
        log.info('Starting web server...')
        asyncio.run_coroutine_threadsafe(webserver.serve(), loop)
        influxdb.write('app', 'startup', 1)
        log.info('Starting Telegram Bot...')
        application.run_polling()
        log.info('Shutting down...')
        # emulate signal handler latch in server.handle_exit()
        webserver.should_exit = True
        webserver.force_exit = True
        asyncio.run(webserver.shutdown())
        log.info('Web server shut down...')
    finally:
        die()
        zmq_term()
        log.info('Shutting down ngrok...')
        try:
            ngrok.kill()
        except ValueError:
            log.warning('ngrok shutdown issue.', exc_info=True)
        log.info('ngrok shut down...')
        loop.close()
    bye()


if __name__ == "__main__":
    main()