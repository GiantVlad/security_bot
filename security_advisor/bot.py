"""Telegram interface and daily digest scheduling."""

import json
import logging
import os
import re
from datetime import datetime, timedelta, timezone
from html import escape

from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.constants import ParseMode
from telegram.error import Forbidden, TelegramError
from telegram.ext import Application, CallbackQueryHandler, CommandHandler, ContextTypes

from .catalog import GROUPS, GROUP_BY_ECOSYSTEM
from .osv import OSVClient
from .store import Store

LOG = logging.getLogger(__name__)
STORE: Store | None = None
OSV: OSVClient | None = None


def store() -> Store:
    assert STORE is not None
    return STORE


def selector(chat_id: int) -> InlineKeyboardMarkup:
    selected = store().selected_groups(chat_id)
    rows = []
    for name in GROUPS:
        mark = "✅ " if name in selected else "▫️ "
        rows.append([InlineKeyboardButton(mark + name, callback_data="group:" + name)])
    return InlineKeyboardMarkup(rows)


def canonical_id(record: dict) -> str:
    aliases = [a for a in json.loads(record["aliases"]) if a]
    identifiers = [record["osv_id"], *aliases]
    # Prefer shared public identifiers; keep every alias in delivery history.
    for prefix in ("CVE-", "GHSA-"):
        matches = sorted(value for value in identifiers if value.startswith(prefix))
        if matches:
            return matches[0]
    return record["osv_id"]


def relevant_groups(record: dict) -> list[str]:
    ecosystems = set(json.loads(record["ecosystems"]))
    return sorted({GROUP_BY_ECOSYSTEM[e] for e in ecosystems if e in GROUP_BY_ECOSYSTEM})


def affected_summary(record: dict) -> str:
    packages: list[str] = []
    for entry in json.loads(record.get("affected_json", "[]")):
        package = entry.get("package") or {}
        name = package.get("name")
        if not name:
            continue
        version_notes: list[str] = []
        for version_range in entry.get("ranges") or []:
            for event in version_range.get("events") or []:
                if "fixed" in event:
                    version_notes.append("fixed in " + str(event["fixed"]))
                elif "introduced" in event and event["introduced"] != "0":
                    version_notes.append("introduced " + str(event["introduced"]))
        if not version_notes and entry.get("versions"):
            versions = entry["versions"]
            version_notes.append("affected versions: " + ", ".join(versions[:4]))
        note = "; ".join(dict.fromkeys(version_notes))
        packages.append(str(name) + (f" ({note})" if note else ""))
    shown = packages[:4]
    if len(packages) > len(shown):
        shown.append(f"and {len(packages) - len(shown)} more")
    return ", ".join(shown) or "Package details unavailable"


def digest_items(chat_id: int, since: str | None = None) -> list[tuple[str, dict]]:
    selected = store().selected_groups(chat_id)
    ecos = {e for group in selected for e in GROUPS.get(group, ())}
    items = store().records_for_groups(ecos, since=since)
    unique: dict[str, dict] = {}
    for item in items:
        key = canonical_id(item)
        unique.setdefault(key, item)
    return list(unique.items())


def format_digest(items: list[tuple[str, dict]]) -> list[str]:
    if not items:
        return []
    sections: list[str] = []
    current = "🛡 <b>Security digest</b>\n\n"
    for key, item in items:
        groups = ", ".join(relevant_groups(item)) or "Open source"
        link = f"https://osv.dev/vulnerability/{escape(item['osv_id'])}"
        text = (f"<b>{escape(item['summary'])}</b>\n"
                f"{escape(key)} · {escape(groups)}\n"
                f"Affects: {escape(affected_summary(item))}\n"
                f"<a href=\"{link}\">Details</a>\n\n")
        if len(current) + len(text) > 3800 and current.strip():
            sections.append(current.rstrip())
            current = "🛡 <b>Security digest (continued)</b>\n\n"
        current += text
    if current.strip():
        sections.append(current.rstrip())
    return sections


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    chat_id = update.effective_chat.id
    store().register(chat_id)
    await update.effective_message.reply_text(
        "Welcome! Choose the broad technology groups you want in your daily OSV digest. "
        f"Your digest time is {store().digest_time(chat_id)} UTC. Use /time HH:MM to change it.",
        reply_markup=selector(chat_id)
    )


async def settings(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    chat_id = update.effective_chat.id
    store().register(chat_id)
    await update.effective_message.reply_text(
        f"Your technology groups. Daily notification time: {store().digest_time(chat_id)} UTC.",
        reply_markup=selector(chat_id),
    )


async def notification_time(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    chat_id = update.effective_chat.id
    store().register(chat_id)
    if not context.args:
        await update.effective_message.reply_text(
            "Enter notification time in UTC (example 14:15). Default: 09:00.\n"
            "Set it with /time HH:MM, for example /time 14:15.\n"
            f"Current time: {store().digest_time(chat_id)} UTC."
        )
        return

    value = context.args[0]
    if len(context.args) != 1 or not re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", value):
        await update.effective_message.reply_text(
            "Use 24-hour UTC time in HH:MM format, for example /time 14:15."
        )
        return
    store().set_digest_time(chat_id, value)
    await update.effective_message.reply_text(f"Daily notification time set to {value} UTC.")


async def toggle_group(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    await query.answer()
    chat_id = query.message.chat_id
    name = query.data.removeprefix("group:")
    if name not in GROUPS:
        return
    store().toggle_group(chat_id, name)
    await query.edit_message_reply_markup(reply_markup=selector(chat_id))


async def stop(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    store().set_active(update.effective_chat.id, False)
    await update.effective_message.reply_text("Daily digests paused. Use /start to resume and edit your groups.")


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.effective_message.reply_text(
        "/start — set up or resume\n/settings — edit technology groups\n"
        "/time — view or set notification time in UTC (use /time HH:MM)\n"
        "/digest — preview recent matching items\n/stop — pause daily digests"
    )


async def send_digest(bot, chat_id: int, since: str | None = None) -> int:
    if not store().is_active(chat_id):
        return 0
    items = digest_items(chat_id, since=since)
    pending = [
        (key, item) for key, item in items
        if not store().record_was_delivered(chat_id, item)
    ]
    if not pending:
        return 0

    chunks: list[tuple[str, list[dict]]] = []
    current = "🛡 <b>Security digest</b>\n\n"
    current_records: list[dict] = []
    for key, item in pending:
        groups = ", ".join(relevant_groups(item)) or "Open source"
        link = f"https://osv.dev/vulnerability/{escape(item['osv_id'])}"
        line = (
            f"<b>{escape(item['summary'])}</b>\n"
            f"{escape(key)} · {escape(groups)}\n"
            f"Affects: {escape(affected_summary(item))}\n"
            f"<a href=\"{link}\">Details</a>\n\n"
        )
        if len(current) + len(line) > 3800 and current_records:
            chunks.append((current.rstrip(), current_records))
            current = "🛡 <b>Security digest (continued)</b>\n\n"
            current_records = []
        current += line
        current_records.append(item)
    if current_records:
        chunks.append((current.rstrip(), current_records))

    for section, records in chunks:
        await bot.send_message(
            chat_id=chat_id, text=section, parse_mode=ParseMode.HTML,
            disable_web_page_preview=True,
        )
        for record in records:
            store().mark_record_delivered(chat_id, record)
    return len(pending)


async def digest_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    chat_id = update.effective_chat.id
    if not store().selected_groups(chat_id):
        await update.effective_message.reply_text("Choose at least one group with /settings first.")
        return
    await update.effective_message.reply_text("Checking recently synced advisories…")
    # OSV ingestion runs in the hourly background job. Avoid blocking this
    # command on a potentially large sequence of one-by-one API requests.
    items = digest_items(chat_id, since=(datetime.now(timezone.utc) - timedelta(days=7)).isoformat())
    sections = format_digest(items)
    if not sections:
        LOG.info("Manual digest preview for chat %s: 0 matching advisory records", chat_id)
        await update.effective_message.reply_text("No matching advisories found in the last 7 days.")
        return
    for section in sections:
        await update.effective_message.reply_text(section, parse_mode=ParseMode.HTML, disable_web_page_preview=True)
    LOG.info("Manual digest preview for chat %s: sent %d advisory records", chat_id, len(items))


async def daily_digest(context: ContextTypes.DEFAULT_TYPE) -> None:
    now = datetime.now(timezone.utc)
    for chat_id in store().due_digest_chats(now):
        try:
            sent = await send_digest(context.bot, chat_id, since=store().digest_since(chat_id))
            store().mark_digest_complete(chat_id)
            LOG.info("Daily digest for chat %s: sent %d advisory records", chat_id, sent)
        except Forbidden:
            store().set_active(chat_id, False)
            LOG.warning("Disabled daily digest for chat %s because Telegram denied delivery", chat_id)
        except TelegramError:
            LOG.exception("Could not send digest to chat %s", chat_id)


async def periodic_sync(context: ContextTypes.DEFAULT_TYPE) -> None:
    if OSV is None:
        return
    try:
        await OSV.sync()
    except Exception:
        LOG.exception("OSV sync failed")


async def post_init(application: Application) -> None:
    queue = application.job_queue
    queue.run_repeating(periodic_sync, interval=3600, first=1, name="osv-sync")
    queue.run_repeating(daily_digest, interval=60, first=1, name="daily-digest")


def main() -> None:
    global STORE, OSV
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    if not token:
        raise SystemExit("Set TELEGRAM_BOT_TOKEN in the environment.")
    database_path = os.getenv("DATABASE_PATH", "./data/security_advisor.sqlite3")
    index_url = os.getenv(
        "OSV_MODIFIED_INDEX",
        "https://storage.googleapis.com/osv-vulnerabilities/modified_id.csv",
    )
    STORE = Store(database_path)
    OSV = OSVClient(STORE, index_url)
    app = Application.builder().token(token).post_init(post_init).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("settings", settings))
    app.add_handler(CommandHandler("stop", stop))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("digest", digest_command))
    app.add_handler(CommandHandler("time", notification_time))
    app.add_handler(CallbackQueryHandler(toggle_group, pattern=r"^group:"))
    app.run_polling()
