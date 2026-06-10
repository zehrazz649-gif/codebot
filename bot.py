import os
import base64
import hashlib
import logging
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    CallbackQueryHandler,
    ConversationHandler,
    filters,
    ContextTypes,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import secrets

# --- Logging ---
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)

# --- Config ---
TOKEN = os.environ.get("BOT_TOKEN", "")
MASTER_KEY = os.environ.get("MASTER_KEY", "default-change-this-in-production-please")

# --- States ---
WAITING_TEXT, WAITING_DECRYPT, WAITING_KEY_ENCRYPT, WAITING_KEY_DECRYPT = range(4)

# ─────────────────────────────────────────────
#   ENCRYPTION CORE  (AES-256-GCM + PBKDF2)
# ─────────────────────────────────────────────

VERSION = b"\x01"   # 1 byte protocol version – for future-proofing


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit AES key from a password using PBKDF2-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600_000,
        backend=default_backend(),
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_text(plaintext: str, password: str) -> str:
    """
    Encrypt using AES-256-GCM.
    Output format (base64url):
        VERSION (1B) | SALT (32B) | NONCE (12B) | CIPHERTEXT+TAG
    """
    salt = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    payload = VERSION + salt + nonce + ct
    return base64.urlsafe_b64encode(payload).decode("ascii")


def decrypt_text(token: str, password: str) -> str:
    """Decrypt a token produced by encrypt_text(). Raises on bad password / tampered data."""
    try:
        payload = base64.urlsafe_b64decode(token.encode("ascii"))
    except Exception:
        raise ValueError("Token formatı yanlışdır.")

    if len(payload) < 1 + 32 + 12 + 16:
        raise ValueError("Token çox qısadır.")

    version = payload[0:1]
    if version != VERSION:
        raise ValueError(f"Dəstəklənməyən versiya: {version!r}")

    salt = payload[1:33]
    nonce = payload[33:45]
    ct = payload[45:]

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    try:
        pt = aesgcm.decrypt(nonce, ct, None)
    except Exception:
        raise ValueError("Şifrə yanlışdır və ya məlumat dəyişdirilib.")

    return pt.decode("utf-8")


def make_fingerprint(token: str) -> str:
    """Short visual fingerprint so user can verify same token."""
    digest = hashlib.sha256(token.encode()).digest()
    return digest[:6].hex().upper()


# ─────────────────────────────────────────────
#   HELPER UI
# ─────────────────────────────────────────────

def main_menu_keyboard():
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("🔒 Şifrələ", callback_data="encrypt"),
            InlineKeyboardButton("🔓 Deşifrələ", callback_data="decrypt"),
        ],
        [InlineKeyboardButton("ℹ️ Haqqında", callback_data="about")],
    ])


def cancel_keyboard():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("❌ Ləğv et", callback_data="cancel")]
    ])


# ─────────────────────────────────────────────
#   HANDLERS
# ─────────────────────────────────────────────

async def start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "👋 *Salam!*\n\n"
        "Bu bot mətnini *AES-256-GCM* ilə güclü şəkildə şifrələyir.\n"
        "Şifrəni yalnız sən bilirsən — heç kim oxuya bilməz.\n\n"
        "Nə etmək istəyirsən?",
        parse_mode="Markdown",
        reply_markup=main_menu_keyboard(),
    )
    return ConversationHandler.END


async def button_handler(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    data = query.data

    if data == "encrypt":
        await query.edit_message_text(
            "🔑 *Şifrə açarı daxil et:*\n\n"
            "Bu açar olmadan heç kim mətnini oxuya bilməz.\n"
            "_(istənilən söz və ya cümlə)_",
            parse_mode="Markdown",
            reply_markup=cancel_keyboard(),
        )
        return WAITING_KEY_ENCRYPT

    elif data == "decrypt":
        await query.edit_message_text(
            "🔑 *Şifrə açarı daxil et:*\n\n"
            "Şifrələmədə istifadə etdiyin açarı yazın.",
            parse_mode="Markdown",
            reply_markup=cancel_keyboard(),
        )
        return WAITING_KEY_DECRYPT

    elif data == "about":
        await query.edit_message_text(
            "ℹ️ *Texniki məlumat*\n\n"
            "🔐 Alqoritm: AES-256-GCM\n"
            "🔑 Açar törəmə: PBKDF2-SHA256 (600,000 iteration)\n"
            "🎲 Salt: 256-bit random\n"
            "📦 Nonce: 96-bit random\n"
            "✅ Authentication: GCM tag (128-bit)\n\n"
            "Hər şifrələmə unikaldır — eyni mətn ikinci dəfə fərqli çıxır.",
            parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("⬅️ Geri", callback_data="back")]
            ]),
        )
        return ConversationHandler.END

    elif data in ("cancel", "back"):
        await query.edit_message_text(
            "Ana menyu:",
            reply_markup=main_menu_keyboard(),
        )
        ctx.user_data.clear()
        return ConversationHandler.END


# --- Encrypt flow ---

async def got_key_for_encrypt(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    key = update.message.text.strip()
    if not key:
        await update.message.reply_text("Açar boş ola bilməz. Yenidən daxil edin:")
        return WAITING_KEY_ENCRYPT

    ctx.user_data["enc_key"] = key
    await update.message.reply_text(
        "✏️ *Şifrələnəcək mətni yazın:*",
        parse_mode="Markdown",
        reply_markup=cancel_keyboard(),
    )
    return WAITING_TEXT


async def got_text_for_encrypt(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    plaintext = update.message.text.strip()
    password = ctx.user_data.get("enc_key", MASTER_KEY)

    if not plaintext:
        await update.message.reply_text("Mətn boş ola bilməz. Yenidən yazın:")
        return WAITING_TEXT

    try:
        token = encrypt_text(plaintext, password)
        fp = make_fingerprint(token)

        # Split into chunks if too long for a code block
        if len(token) <= 3800:
            await update.message.reply_text(
                f"✅ *Şifrələndi!*\n\n"
                f"🔏 *Şifrəli mətn:*\n`{token}`\n\n"
                f"🆔 Barmaq izi: `{fp}`\n\n"
                f"_Bu mətni yalnız eyni açarla deşifrə etmək olar._",
                parse_mode="Markdown",
            )
        else:
            await update.message.reply_text(f"✅ Şifrələndi! Barmaq izi: `{fp}`\n\nŞifrəli mətn (uzundur, aşağıda):", parse_mode="Markdown")
            # Send as file-like chunks
            for i in range(0, len(token), 4000):
                await update.message.reply_text(f"`{token[i:i+4000]}`", parse_mode="Markdown")

    except Exception as e:
        logger.error(f"Encrypt error: {e}")
        await update.message.reply_text("❌ Xəta baş verdi. Yenidən cəhd edin.")

    ctx.user_data.clear()
    await update.message.reply_text("Ana menyu:", reply_markup=main_menu_keyboard())
    return ConversationHandler.END


# --- Decrypt flow ---

async def got_key_for_decrypt(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    key = update.message.text.strip()
    if not key:
        await update.message.reply_text("Açar boş ola bilməz:")
        return WAITING_KEY_DECRYPT

    ctx.user_data["dec_key"] = key
    await update.message.reply_text(
        "📋 *Şifrəli mətni yapışdırın:*",
        parse_mode="Markdown",
        reply_markup=cancel_keyboard(),
    )
    return WAITING_DECRYPT


async def got_token_for_decrypt(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    token = update.message.text.strip()
    password = ctx.user_data.get("dec_key", MASTER_KEY)

    try:
        plaintext = decrypt_text(token, password)
        await update.message.reply_text(
            f"✅ *Deşifrə uğurlu oldu!*\n\n"
            f"📄 *Orijinal mətn:*\n`{plaintext}`",
            parse_mode="Markdown",
        )
    except ValueError as e:
        await update.message.reply_text(
            f"❌ *Deşifrə alınmadı*\n\n`{e}`\n\n"
            "Açar yanlışdır və ya mətn dəyişdirilib.",
            parse_mode="Markdown",
        )
    except Exception as e:
        logger.error(f"Decrypt error: {e}")
        await update.message.reply_text("❌ Xəta baş verdi.")

    ctx.user_data.clear()
    await update.message.reply_text("Ana menyu:", reply_markup=main_menu_keyboard())
    return ConversationHandler.END


async def cancel_cmd(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    ctx.user_data.clear()
    await update.message.reply_text("Ləğv edildi.", reply_markup=main_menu_keyboard())
    return ConversationHandler.END


# ─────────────────────────────────────────────
#   MAIN
# ─────────────────────────────────────────────

def main():
    if not TOKEN:
        raise RuntimeError("BOT_TOKEN mühit dəyişəni təyin edilməyib!")

    app = Application.builder().token(TOKEN).build()

    conv = ConversationHandler(
        entry_points=[
            CommandHandler("start", start),
            CallbackQueryHandler(button_handler),
        ],
        states={
            WAITING_KEY_ENCRYPT: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, got_key_for_encrypt),
                CallbackQueryHandler(button_handler),
            ],
            WAITING_TEXT: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, got_text_for_encrypt),
                CallbackQueryHandler(button_handler),
            ],
            WAITING_KEY_DECRYPT: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, got_key_for_decrypt),
                CallbackQueryHandler(button_handler),
            ],
            WAITING_DECRYPT: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, got_token_for_decrypt),
                CallbackQueryHandler(button_handler),
            ],
        },
        fallbacks=[
            CommandHandler("cancel", cancel_cmd),
            CommandHandler("start", start),
        ],
        allow_reentry=True,
    )

    app.add_handler(conv)
    logger.info("Bot işə düşdü...")
    app.run_polling(drop_pending_updates=True)


if __name__ == "__main__":
    main()
