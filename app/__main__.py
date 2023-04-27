#!/usr/bin/env python
import logging.handlers

import builtins
import simplejson as json
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

from requests.adapters import ConnectionError
from requests.exceptions import RequestException


def main():
    log.setLevel(logging.INFO)
    # ensure proper signal handling; must be main thread
    signal_handler = SignalHandler()
    # start the nanny
    nanny = threading.Thread(
        daemon=True,
        name='nanny',
        target=thread_nanny,
        args=(signal_handler,))
    # startup completed
    # back to INFO logging
    log.setLevel(logging.INFO)
    try:
        log.info(f'Starting {APP_NAME} threads...')
        nanny.start()
        log.info('Startup complete.')
        # hang around until something goes wrong
        threads.interruptable_sleep.wait()
    finally:
        die()
        zmq_term()
    bye()


if __name__ == "__main__":
    main()