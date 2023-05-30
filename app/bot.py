import emoji
import string
import urllib

from pylib import (
    app_config,
    creds,
    log,
    threads
)

from pocket import Pocket
from pocket import PocketException, AuthException

from telegram import (
    Update,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    User as TelegramUser,
    ChatMember as TelegramChatMember,
)
from telegram.constants import ParseMode, ChatAction
from telegram.ext import (
    ContextTypes,
    ConversationHandler
)

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
    DEFAULT_SORT,
    DEFAULT_AUTO_ARCHIVE,
    User,
    get_user_registration,
    get_user_prefs,
    get_offset,
    update_offset,
    update_user_pref,
    store_request_token,
    store_access_token
)

from .oauth import (
    WebhookUpdate,
    CustomContext
)


async def pick_from_pocket(db_user: User, update: Update, context: ContextTypes.DEFAULT_TYPE, pick_type=PICK_TYPE_UNREAD, tag=None) -> str:
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
    items = None
    try:
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
    except AuthException as e:
        log.warning(f'Problem with Pocket call for Telegram user ID {user.id}.', exc_info=True)
        response_message = rf'<tg-emoji emoji-id="1">{emoji.emojize(":stop_sign:")}</tg-emoji> Permissions problem. Try /start command.'
    except PocketException as e:
        log.warning(f'Problem with Pocket call for Telegram user ID {user.id}.', exc_info=True)
        response_message = rf'<tg-emoji emoji-id="1">{emoji.emojize(":stop_sign:")}</tg-emoji> Problem with Pocket. Please try again later?'
    if items is not None:
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
            limit_user = None
            if 'X-Limit-User-Limit' in h.keys():
                limit_user = h['X-Limit-User-Limit']
            limit_user_remain = None
            if 'X-Limit-User-Remaining' in h.keys():
                limit_user_remain = h['X-Limit-User-Remaining']
            limit_user_reset = None
            if 'X-Limit-User-Reset' in h.keys():
                limit_user_reset = h['X-Limit-User-Reset']
            limit_key = h['X-Limit-Key-Limit']
            limit_key_remain = h['X-Limit-Key-Remaining']
            limit_key_reset = h['X-Limit-Key-Reset']
            log.info(f'{status} from {source} served by {server} ({cache} via {cdn_pop}). ' \
                        f'User limits: {limit_user_remain} of {limit_user} (resets {limit_user_reset}). ' \
                        f'Key limits: {limit_key_remain} of {limit_key} (resets {limit_key_reset}).')
            for k,v in h.items():
                if k.startswith('X-Limit'):
                    influxdb.write(point_name='pocket', field_name=k, field_value=int(v))
        if status.startswith('200'):
            if len(items) == 0 or len(items[0]['list']) == 0:
                response_message = rf'<tg-emoji emoji-id="1">{emoji.emojize(":floppy_disk:")}</tg-emoji> No links found, sorry.'
                if offset > 0:
                    user_follow_up = rf'<tg-emoji emoji-id="1">{emoji.emojize(":light_bulb:")}</tg-emoji> Try resetting my index for this pick type.'
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
                    user_follow_up = None
                    user_keyboard = None
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
    if pick_type != PICK_TYPE_ARCHIVED and item_id and auto_archive:
        log.debug(f'Auto-archive of Pocket item {item_id} based on user-preference.')
        pocket_instance.archive(item_id=item_id).commit()
    return item_id



async def validate(command_name: str, update: Update, validate_registration=True) -> User:
    user: TelegramUser = update.effective_user
    if user.is_bot:
        log.warning(f'{command_name}: ignoring bot user {user.id}.')
        return
    log.info(f'{command_name}: Telegram user ID {user.id} (language {user.language_code}).')
    influxdb.write('command', f'{command_name}', 1)
    db_user = None
    if validate_registration:
        db_user: User = await get_user_registration(telegram_user_id=user.id)
        if db_user is None or db_user.pocket_username is None or db_user.pocket_access_token is None:
            log.info(f'No database registration found for Telegram user ID {user.id}.')
            if update.message is None:
                log.warning(f'Cannot update null message from Telegram user ID {user.id} with no update message context.')
                return None
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
            return None
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
        f'{user.first_name}, changing sort order will reset your pick positions. ' \
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
    if item_id is not None:
        context.user_data['pocket_item_id'] = item_id
        return ACTION_TAG
    return ConversationHandler.END


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
    influxdb.write('bot', 'settings_updated', 1)
    await query.edit_message_text(
        text=f'{emoji.emojize(":check_mark_button:")} Settings updated.',
        parse_mode=ParseMode.MARKDOWN)
    return ConversationHandler.END


async def registration(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user: TelegramUser = update.effective_user
    await validate(command_name='registration', update=update, validate_registration=False)
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
    influxdb.write('bot', 'registration_oauth', 1)
    await query.edit_message_text(
        text=f'*Step 1*: Visit https://getpocket.com/login to first log in using your mobile browser (necessary to work around a Pocket authorization bug). ' \
            f'*Step 2*: Use [this link]({pocket_auth_url}) to authorize with Pocket.',
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
    if 'pocket_item_id' not in context.user_data.keys() or context.user_data['pocket_item_id'] is None:
        log.warning(f'Unable to archive without a Pocket item ID for Telegram user ID {user.id}.')
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
    if 'pocket_item_id' not in context.user_data.keys() or context.user_data['pocket_item_id'] is None:
        log.warning(f'Unable to tag without an item ID present for Telegram user ID {user.id}.')
        return ConversationHandler.END
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
    query = update.callback_query
    # CallbackQueries need to be answered, even if no notification to the user is needed
    # Some clients may have trouble otherwise. See https://core.telegram.org/bots/api#callbackquery
    await query.answer()
    await query.edit_message_text(text=f"No changes made.")
    return ConversationHandler.END


async def webhook_update(update: WebhookUpdate, context: CustomContext) -> None:
    influxdb.write('bot', 'registration_callback', 1)
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
        log.info(f'Completing registration for Telegram user ID {update.user_id}. Fetching user access token.')
        user_credentials = None
        try:
            user_credentials = Pocket.get_credentials(consumer_key=creds.pocket_api_consumer_key, code=db_user.pocket_request_token)
        except PocketException as e:
            log.warning(f'Pocket error to get access token for Telegram user ID {update.user_id}: {repr(e)}...', exc_info=True)
        if user_credentials is not None:
            access_token = user_credentials['access_token']
            pocket_username = user_credentials['username']
            log.info(f'Storing Pocket username and access token for Telegram user ID {update.user_id}.')
            await store_access_token(telegram_user_id=update.user_id, pocket_username=pocket_username, pocket_access_token=access_token)
            response_message = rf'{emoji.emojize(":check_box_with_check:")} {telegram_user.first_name}, you are now authorized as Pocket user "{pocket_username}".'
            influxdb.write('bot', 'registration_complete', 1)
        else:
            influxdb.write('bot', 'registration_error', 1)
            log.warning(f'No valid user credentials after registration callback for Telegram user ID {update.user_id}')
            response_message = rf'{emoji.emojize(":stop_sign:")} {telegram_user.first_name}, there was a problem authorizing with Pocket. Please try again later?'
    if response_message is not None:
        await context.bot.send_message(
            chat_id=update.user_id,
            text=response_message,
            parse_mode=ParseMode.MARKDOWN
        )

async def telegram_error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    log.warning(msg="Bot error:", exc_info=context.error)
    return ConversationHandler.END
