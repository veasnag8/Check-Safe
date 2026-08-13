from __future__ import annotations

import asyncio
import logging
from contextlib import suppress

from fastapi import FastAPI, Header, HTTPException, Request
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


def _telegram_webhook_url() -> str:
    settings = get_settings()
    base_url = settings.public_base_url.rstrip("/")
    path = settings.telegram_webhook_path if settings.telegram_webhook_path.startswith("/") else f"/{settings.telegram_webhook_path}"
    return f"{base_url}{path}"


def _should_use_webhook(settings) -> bool:
    return bool(settings.public_base_url.strip() and settings.telegram_bot_token.strip())


def create_web_app() -> FastAPI:
    settings = get_settings()
    app = create_app()
    bot_app = create_bot_application()

    @app.on_event("startup")
    async def _startup() -> None:
        await bot_app.initialize()
        if _should_use_webhook(settings):
            await bot_app.bot.set_webhook(
                url=_telegram_webhook_url(),
                allowed_updates=Update.ALL_TYPES,
                secret_token=settings.telegram_webhook_secret or None,
                drop_pending_updates=True,
            )
            await bot_app.start()
            logger.info("Telegram webhook configured at %s", _telegram_webhook_url())
        else:
            logger.warning("PUBLIC_BASE_URL is not set; Telegram webhook is disabled")

    @app.on_event("shutdown")
    async def _shutdown() -> None:
        with suppress(Exception):
            await bot_app.bot.delete_webhook(drop_pending_updates=True)
        with suppress(Exception):
            await bot_app.stop()
        with suppress(Exception):
            await bot_app.shutdown()

    @app.post(settings.telegram_webhook_path)
    async def telegram_webhook(
        request: Request,
        x_telegram_bot_api_secret_token: str | None = Header(default=None, alias="X-Telegram-Bot-Api-Secret-Token"),
    ) -> dict:
        if not _should_use_webhook(settings):
            raise HTTPException(status_code=404, detail="Telegram webhook is disabled")

        expected_secret = (settings.telegram_webhook_secret or "").strip()
        if expected_secret and x_telegram_bot_api_secret_token is not None and x_telegram_bot_api_secret_token != expected_secret:
            raise HTTPException(status_code=403, detail="Invalid webhook secret")

        # Telegram should include the secret token when configured, but some deployments or
        # proxies can omit it. We only reject explicit mismatches to avoid false negatives.
        update = Update.de_json(await request.json(), bot_app.bot)
        await bot_app.process_update(update)
        return {"status": "ok"}

    return app


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
