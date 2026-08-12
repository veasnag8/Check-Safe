from __future__ import annotations

from pathlib import Path

from telegram import Update
from telegram.error import BadRequest
from telegram.ext import ContextTypes

from app.scanners.file_scanner import scan_file
from app.scanners.url_scanner import scan_url
from app.services.dns_service import DNSService
from app.services.safe_browsing import SafeBrowsingService
from app.services.virustotal import VirusTotalService
from app.utils.formatting import format_scan_summary


async def reply_scoped(update: Update, text: str) -> None:
    if not update.message:
        return
    await update.message.reply_text(text, reply_to_message_id=update.message.message_id)


async def delete_source_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Try to remove the triggering message after a risky alert."""
    if not update.message:
        return
    chat_id = update.effective_chat.id if update.effective_chat else None
    if chat_id is None:
        return
    try:
        await context.bot.delete_message(chat_id=chat_id, message_id=update.message.message_id)
    except Exception:
        # Deletion is best-effort: the bot may lack admin rights or Telegram may refuse.
        return


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await reply_scoped(
        update,
        "🛡️ សេចក្តីជូនដំណឹងអំពីភាពឯកជន\n\n"
        "ឯកសារ និង URL ដែលអ្នកផ្ញើ នឹងត្រូវបានវិភាគសម្រាប់គោលបំណងសុវត្ថិភាព។\n\n"
        "ការវិភាគក្នុងមូលដ្ឋាននឹងត្រូវប្រើនៅពេលអាចធ្វើទៅបាន។\n\n"
        "សេវាសុវត្ថិភាពខាងក្រៅ អាចទទួលបាន URL, hash ឬឯកសារ តែប៉ុណ្ណោះនៅពេលអ្នកគ្រប់គ្រង server បានបើកជាក់លាក់។\n\n"
        "សូមកុំផ្ញើឯកសារដែលមានភាពសម្ងាត់ខ្ពស់។",
    )


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await reply_scoped(
        update,
        "ផ្ញើ URL ឬឯកសារដើម្បីវិភាគ។ ពាក្យបញ្ជា: /start /help /check /history /status /admin /stats /recent /block /unblock",
    )


async def check_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    text = " ".join(context.args) if context.args else (update.message.text or "")
    url = text.replace("/check", "").strip()
    if not url and update.message and update.message.document:
        await reply_scoped(update, "មិនអាចស្កេនឯកសារតាម /check បានទេ។ សូមផ្ញើឯកសារផ្ទាល់។")
        return

    settings = context.application.bot_data["settings"]
    result = await scan_url(
        url,
        DNSService(),
        VirusTotalService(settings.virustotal_api_key),
        SafeBrowsingService(settings.google_safe_browsing_api_key),
    )
    if result.verdict == "SAFE":
        return

    await reply_scoped(
        update,
        format_scan_summary(
            title="🛡️ លទ្ធផលត្រួតពិនិត្យសុវត្ថិភាព",
            verdict=result.verdict,
            score=result.score,
            reasons=result.reasons,
            recommendation=result.recommendation,
            target_label="URL",
            target_value=result.normalized_url,
            extra_details=[
                ("HTTPS", "បាទ/ចាស" if result.normalized_url.startswith("https://") else "ទេ"),
                ("DNS", str(result.checks.get("dns", "unknown")).upper()),
                ("Reputation", str(result.checks.get("reputation", "unknown")).upper()),
            ],
            locale="km",
        ),
    )
    await delete_source_message(update, context)


async def history_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await reply_scoped(
        update,
        "📋 ការស្កេនថ្មីៗរបស់អ្នកនឹងត្រូវរក្សាទុកក្នុងមូលដ្ឋានទិន្នន័យ នៅពេលភ្ជាប់ប្រព័ន្ធបន្តរក្សាទុករួច។",
    )


async def status_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await reply_scoped(update, "✅ សេវាកម្មកំពុងដំណើរការ។ សូមប្រើ /check ឬផ្ញើឯកសារដើម្បីវិភាគ។")


async def admin_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await reply_scoped(update, "ពាក្យបញ្ជា Admin អាចប្រើបានតែសម្រាប់ Telegram ID ដែលបានកំណត់ប៉ុណ្ណោះ។")


async def stats_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await reply_scoped(update, "ស្ថិតិអាចមើលបាននៅពេលភ្ជាប់ការរក្សាទុកការស្កេន និង repository រួចរាល់។")


async def recent_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await reply_scoped(update, "បញ្ជីការស្កេនថ្មីៗ អាចមើលបានពីផ្នែកប្រវត្តិដែលភ្ជាប់មូលដ្ឋានទិន្នន័យ។")


async def block_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await reply_scoped(update, "ការបិទអ្នកប្រើប្រាស់ ត្រូវការអនុញ្ញាតពី Admin។")


async def unblock_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await reply_scoped(update, "ការដោះបិទអ្នកប្រើប្រាស់ ត្រូវការអនុញ្ញាតពី Admin។")


async def handle_text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    text = (update.message.text or "").strip()
    if text.startswith("http://") or text.startswith("https://"):
        await check_command(update, context)


async def handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    doc = update.message.document
    if not doc:
        return

    settings = context.application.bot_data["settings"]
    max_bytes = int(settings.max_file_size_mb) * 1024 * 1024
    if doc.file_size is not None and doc.file_size > max_bytes:
        await reply_scoped(update, f"ឯកសារធំពេក។ អនុញ្ញាតបានត្រឹម {settings.max_file_size_mb} MB ប៉ុណ្ណោះ។")
        return

    try:
        file = await doc.get_file()
        target = Path("storage/quarantine") / (doc.file_name or "uploaded_file.bin")
        await file.download_to_drive(custom_path=str(target))
    except BadRequest as exc:
        if "File is too big" in str(exc):
            await reply_scoped(
                update,
                f"ឯកសារនេះធំពេកសម្រាប់ Telegram download។ សូមប្រើឯកសារតូចជាង {settings.max_file_size_mb} MB។",
            )
            return
        raise

    result = await scan_file(str(target), VirusTotalService(settings.virustotal_api_key))
    if result.verdict == "SAFE":
        return

    await reply_scoped(
        update,
        format_scan_summary(
            title="🚨 ការព្រមានសុវត្ថិភាព",
            verdict=result.verdict,
            score=result.score,
            reasons=result.reasons,
            recommendation=result.recommendation,
            target_label="File",
            target_value=doc.file_name or "uploaded_file.bin",
            extra_details=[
                ("ផ្នែកបន្ថែម", result.extension or "unknown"),
                ("ប្រភេទ MIME", result.mime_type or "unknown"),
                ("ទំហំ", f"{result.size} bytes"),
                ("អង់ត្រូពី", f"{result.entropy:.2f}"),
            ],
            locale="km",
        ),
    )
    await delete_source_message(update, context)
