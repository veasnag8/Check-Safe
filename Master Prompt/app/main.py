from __future__ import annotations

import asyncio
import logging
from contextlib import suppress

from fastapi import FastAPI
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes, MessageHandler, filters

from app.api.routes import create_app
from app.bot.handlers import (
    admin_command,
    block_command,
    check_command,
    handle_document,
    handle_text,
    help_command,
    history_command,
    recent_command,
    start,
    status_command,
    stats_command,
    unblock_command,
)
from app.config import get_settings
from app.database.database import init_db
from app.utils.logging_config import configure_logging

logger = logging.getLogger(__name__)


def create_bot_application() -> Application:
    settings = get_settings()
    application = Application.builder().token(settings.telegram_bot_token).build()
    application.bot_data["settings"] = settings
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CommandHandler("check", check_command))
    application.add_handler(CommandHandler("history", history_command))
    application.add_handler(CommandHandler("status", status_command))
    application.add_handler(CommandHandler("admin", admin_command))
    application.add_handler(CommandHandler("stats", stats_command))
    application.add_handler(CommandHandler("recent", recent_command))
    application.add_handler(CommandHandler("block", block_command))
    application.add_handler(CommandHandler("unblock", unblock_command))
    application.add_handler(MessageHandler(filters.Document.ALL, handle_document))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))
    application.add_error_handler(_on_error)
    return application


async def _on_error(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    logger.exception("Unhandled bot error", exc_info=context.error)


def create_api() -> FastAPI:
    return create_app()


def main() -> None:
    settings = get_settings()
    configure_logging(settings.log_level)
    init_db()
    bot = create_bot_application()
    while True:
        try:
            bot.run_polling(
                close_loop=False,
                drop_pending_updates=True,
                allowed_updates=Update.ALL_TYPES,
            )
            break
        except KeyboardInterrupt:
            break
        except Exception:
            logger.exception("Bot polling stopped unexpectedly; restarting in 5 seconds")
            with suppress(Exception):
                asyncio.run(asyncio.sleep(5))


if __name__ == "__main__":
    main()
