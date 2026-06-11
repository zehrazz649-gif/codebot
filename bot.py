"""
StegoBot v1 — Maksimum Steganography
  • AES-256-GCM şifrələmə (ən güclü simmetrik şifrə)
  • PBKDF2-SHA256 (600,000 iterasiya) — açar gücləndirmə
  • HMAC-SHA256 — bütövlük yoxlaması
  • LSB steganography — şəkildə gizlətmə
  • Yalnız fayl kimi göndər/al — JPEG sıxışdırmasından qorunma
  • Paralel işləmə — numpy vectorized əməliyyatlar
"""

import os, io, base64, hashlib, hmac as hmac_mod, struct, logging, secrets, time
from pathlib import Path

import numpy as np
from PIL import Image

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application, CommandHandler, MessageHandler,
    CallbackQueryHandler, ConversationHandler,
    filters, ContextTypes,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(format="%(asctime)s %(levelname)s %(message)s", level=logging.INFO)
logger = logging.getLogger(__name__)

# ── Config ────────────────────────────────────────────────────────────────────
BOT_TOKEN    = os.environ.get("BOT_TOKEN", "")
BOT_USERNAME = os.environ.get("BOT_USERNAME", "your_bot")

# ── States ────────────────────────────────────────────────────────────────────
S_HIDE_KEY, S_HIDE_TEXT, S_HIDE_IMG = range(3)
S_REVEAL_KEY, S_REVEAL_IMG          = range(3, 5)

# ── Magic header ──────────────────────────────────────────────────────────────
MAGIC = b"STEG"   # 4 bayt — gizli məlumat olduğunu təsdiq edir

# ══════════════════════════════════════════════════════════════════════════════
#  CRYPTO  —  AES-256-GCM + PBKDF2 + HMAC
#  Format: MAGIC(4) + salt(32) + nonce(12) + hmac(32) + ciphertext
# ══════════════════════════════════════════════════════════════════════════════

def _derive_key(password: str, salt: bytes) -> bytes:
    """PBKDF2-SHA256, 600k iterasiya → 256-bit açar"""
    kdf = PBKDF2HMAC(hashes.SHA256(), 32, salt, 600_000, default_backend())
    return kdf.derive(password.encode("utf-8"))

def encrypt(plaintext: bytes, password: str) -> bytes:
    """
    AES-256-GCM şifrələmə + HMAC-SHA256 bütövlük imzası.
    Qaytarır: MAGIC + salt + nonce + hmac + ciphertext
    """
    salt  = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    key   = _derive_key(password, salt)

    ct    = AESGCM(key).encrypt(nonce, plaintext, None)

    # Əlavə HMAC — bütün payload-ı imzala
    mac_key = hashlib.sha256(b"steg_mac:" + key).digest()
    sig     = hmac_mod.new(mac_key, salt + nonce + ct, hashlib.sha256).digest()

    return MAGIC + salt + nonce + sig + ct

def decrypt(payload: bytes, password: str) -> bytes:
    """
    HMAC yoxla → AES-256-GCM deşifrə et.
    Səhv açar və ya dəyişdirilmiş məlumat → ValueError.
    """
    if len(payload) < 4 + 32 + 12 + 32 + 16:
        raise ValueError("Payload çox qısadır.")
    if payload[:4] != MAGIC:
        raise ValueError("Bu şəkildə gizli məlumat yoxdur.")

    salt    = payload[4:36]
    nonce   = payload[36:48]
    sig     = payload[48:80]
    ct      = payload[80:]

    key     = _derive_key(password, salt)
    mac_key = hashlib.sha256(b"steg_mac:" + key).digest()
    expected = hmac_mod.new(mac_key, salt + nonce + ct, hashlib.sha256).digest()

    if not hmac_mod.compare_digest(sig, expected):
        raise ValueError("Şifrə yanlışdır və ya məlumat dəyişdirilib.")

    try:
        return AESGCM(key).decrypt(nonce, ct, None)
    except Exception:
        raise ValueError("Deşifrə uğursuz — açar yanlışdır.")

# ══════════════════════════════════════════════════════════════════════════════
#  STEGANOGRAPHY  —  LSB (vectorized numpy, maksimum sürət)
#  Format şəkildə: uzunluq(32 bit) + payload bits → LSB-lərə yazılır
# ══════════════════════════════════════════════════════════════════════════════

def steg_embed(img_bytes: bytes, secret: bytes) -> bytes:
    """
    Şifrəli məlumatı şəklin piksel LSB-lərinə göm.
    İstənilən şəkil formatı qəbul edilir, PNG kimi qaytarılır.
    Numpy vectorized — böyük şəkillərdə belə sürətli.
    """
    img  = Image.open(io.BytesIO(img_bytes)).convert("RGB")
    arr  = np.array(img, dtype=np.uint8)
    flat = arr.flatten()

    # Uzunluq (4 bayt) + məlumat
    length_prefix = struct.pack(">I", len(secret))
    full_payload  = length_prefix + secret
    bits = np.unpackbits(np.frombuffer(full_payload, dtype=np.uint8))

    needed = len(bits)
    if needed > len(flat):
        raise ValueError(
            f"Şəkil çox kiçikdir.\n"
            f"Lazım olan piksel: {needed // 3:,}\n"
            f"Mövcud piksel: {len(flat) // 3:,}\n"
            f"Daha böyük şəkil istifadə et."
        )

    # Vectorized LSB yazma — ən sürətli üsul
    flat[:needed] = (flat[:needed] & np.uint8(0xFE)) | bits.astype(np.uint8)

    out = Image.fromarray(flat.reshape(arr.shape).astype(np.uint8), "RGB")
    buf = io.BytesIO()
    out.save(buf, format="PNG", optimize=False, compress_level=1)  # sürət üçün az sıxışdırma
    return buf.getvalue()

def steg_extract(img_bytes: bytes) -> bytes:
    """
    Şəkildən gizli məlumatı çıxart.
    Numpy vectorized — sürətli oxuma.
    """
    img  = Image.open(io.BytesIO(img_bytes)).convert("RGB")
    flat = np.array(img, dtype=np.uint8).flatten()

    # Uzunluğu oxu (ilk 32 bit = 4 bayt)
    if len(flat) < 32:
        raise ValueError("Şəkil çox kiçikdir.")

    len_bits = (flat[:32] & 1).astype(np.uint8)
    length   = struct.unpack(">I", np.packbits(len_bits).tobytes())[0]

    if length == 0:
        raise ValueError("Bu şəkildə gizli məlumat yoxdur.")
    if length > 50 * 1024 * 1024:  # 50 MB limit
        raise ValueError("Bu şəkildə gizli məlumat yoxdur.")
    if 32 + length * 8 > len(flat):
        raise ValueError("Bu şəkildə gizli məlumat yoxdur.")

    # Məlumatı oxu
    total_bits = 32 + length * 8
    all_bits   = (flat[:total_bits] & 1).astype(np.uint8)
    payload    = np.packbits(all_bits)[4:4 + length].tobytes()
    return payload

def capacity_info(img_bytes: bytes) -> str:
    """Şəkilin neçə bayt məlumat saxlaya biləcəyini hesabla."""
    img     = Image.open(io.BytesIO(img_bytes)).convert("RGB")
    arr     = np.array(img)
    pixels  = arr.shape[0] * arr.shape[1]
    max_bytes = (pixels * 3 - 32) // 8 - 4  # 3 kanal, uzunluq prefix çıx
    return pixels, max_bytes

# ══════════════════════════════════════════════════════════════════════════════
#  KEYBOARDS
# ══════════════════════════════════════════════════════════════════════════════

def kb_main():
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("🖼 Şəklə Gizlət",    callback_data="hide"),
            InlineKeyboardButton("🔎 Şəkildən Çıxart", callback_data="reveal"),
        ],
        [
            InlineKeyboardButton("🎲 Güclü Açar Yarat", callback_data="genkey"),
        ],
    ])

def kb_cancel():
    return InlineKeyboardMarkup([[InlineKeyboardButton("❌ Ləğv et", callback_data="cancel")]])

# ══════════════════════════════════════════════════════════════════════════════
#  /start
# ══════════════════════════════════════════════════════════════════════════════

async def cmd_start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    ctx.user_data.clear()
    await update.message.reply_text(
        "🔐 *StegoBot* — Şəkildə Gizlətmə\n\n"
        "Şifrəli məlumatı şəkilə göm — görünməz olsun.\n\n"
        "🛡 *Şifrələmə:* AES-256-GCM + PBKDF2 + HMAC-SHA256\n"
        "🖼 *Metod:* LSB Steganography\n"
        "⚡ *Sürət:* Numpy vectorized\n\n"
        "⚠️ Şəkili həmişə *📎 Fayl kimi* göndər\n"
        "_(Şəkil kimi göndərsən Telegram JPEG-ə çevirir → məlumat pozulur)_",
        parse_mode="Markdown",
        reply_markup=kb_main(),
    )
    return ConversationHandler.END

# ══════════════════════════════════════════════════════════════════════════════
#  BUTTON ROUTER
# ══════════════════════════════════════════════════════════════════════════════

async def button_handler(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    d = q.data

    if d == "hide":
        ctx.user_data.clear()
        await q.edit_message_text(
            "🖼 *Şəklə Gizlətmə*\n\n"
            "*Addım 1/3* — 🔑 Şifrə açarını daxil et:\n"
            "_(Güclü açar = güclü qorunma)_",
            parse_mode="Markdown", reply_markup=kb_cancel(),
        )
        return S_HIDE_KEY

    if d == "reveal":
        ctx.user_data.clear()
        await q.edit_message_text(
            "🔎 *Şəkildən Çıxartma*\n\n"
            "*Addım 1/2* — 🔑 Şifrə açarını daxil et:",
            parse_mode="Markdown", reply_markup=kb_cancel(),
        )
        return S_REVEAL_KEY

    if d == "genkey":
        k = secrets.token_hex(32)
        await q.edit_message_text(
            "🎲 *Güclü Açar (256-bit):*\n\n"
            f"`{k}`\n\n"
            "⚠️ Bu açarı özəl saxla — itirsən məlumat bərpa olunmaz!",
            parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([[
                InlineKeyboardButton("⬅️ Geri", callback_data="back")
            ]]),
        )
        return ConversationHandler.END

    if d in ("cancel", "back"):
        ctx.user_data.clear()
        await q.edit_message_text("Ana menyu:", reply_markup=kb_main())
        return ConversationHandler.END

# ══════════════════════════════════════════════════════════════════════════════
#  HIDE FLOW  (3 addım: açar → mətn → şəkil)
# ══════════════════════════════════════════════════════════════════════════════

async def hide_key_step(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    ctx.user_data["key"] = update.message.text.strip()
    await update.message.reply_text(
        "*Addım 2/3* — 📝 Gizlədəcəyin mətni yaz:",
        parse_mode="Markdown", reply_markup=kb_cancel(),
    )
    return S_HIDE_TEXT

async def hide_text_step(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    pw   = ctx.user_data["key"]
    text = update.message.text.strip()
    try:
        payload = encrypt(text.encode("utf-8"), pw)
        ctx.user_data["payload"] = payload
        await update.message.reply_text(
            f"*Addım 3/3* — 🖼 Şəkil göndər:\n\n"
            f"📦 Gizlənəcək ölçü: *{len(payload):,} bayt*\n"
            f"📐 Lazım olan minimum piksel: *{len(payload)*8//3 + 20:,}*\n\n"
            f"⚠️ Şəkili *📎 Fayl kimi* göndər!\n"
            f"_(Şəkil kimi göndərsən JPEG-ə çevrilir)_",
            parse_mode="Markdown", reply_markup=kb_cancel(),
        )
        return S_HIDE_IMG
    except Exception as e:
        await update.message.reply_text(f"❌ Xəta: {e}")
        ctx.user_data.clear()
        return ConversationHandler.END

async def hide_img_step(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    # Fayl kimi göndərilmiş şəkil qəbul et
    doc   = update.message.document
    photo = update.message.photo

    if not doc and not photo:
        await update.message.reply_text(
            "❌ Fayl göndərilmədi.\n"
            "📎 *Fayl kimi* göndər (yox şəkil kimi).",
            parse_mode="Markdown"
        )
        return S_HIDE_IMG

    # JPEG xəbərdarlığı
    if photo:
        await update.message.reply_text(
            "⚠️ Telegram bu şəkili JPEG-ə çevirdi — məlumat pozula bilər!\n"
            "Daha etibarlı nəticə üçün *📎 Fayl kimi* göndər.",
            parse_mode="Markdown"
        )

    payload = ctx.user_data.get("payload")
    if not payload:
        await update.message.reply_text("❌ Sessiya bitib. /start vurun.")
        return ConversationHandler.END

    buf = io.BytesIO()
    if doc:
        await (await doc.get_file()).download_to_memory(buf)
    else:
        await (await photo[-1].get_file()).download_to_memory(buf)

    img_bytes = buf.getvalue()

    try:
        # Tutum yoxla
        pixels, max_bytes = capacity_info(img_bytes)
        if len(payload) > max_bytes:
            await update.message.reply_text(
                f"❌ Şəkil kiçikdir!\n\n"
                f"📐 Şəkilin tutumu: {max_bytes:,} bayt\n"
                f"📦 Lazım olan: {len(payload):,} bayt\n\n"
                f"Daha böyük şəkil göndər.",
            )
            return S_HIDE_IMG

        t0     = time.time()
        result = steg_embed(img_bytes, payload)
        ms     = int((time.time() - t0) * 1000)

        await update.message.reply_document(
            io.BytesIO(result),
            filename="stego.png",
            caption=(
                f"✅ *Gizlədildi!*\n\n"
                f"🖼 Şəkil: {pixels:,} piksel\n"
                f"📦 Gizli məlumat: {len(payload):,} bayt\n"
                f"⚡ Əməliyyat vaxtı: {ms} ms\n\n"
                f"⚠️ Bu faylı *📎 Fayl kimi* göndər — şəkil kimi göndərsən məlumat pozulur."
            ),
            parse_mode="Markdown",
        )
    except ValueError as e:
        await update.message.reply_text(f"❌ {e}")
    except Exception as e:
        logger.exception("steg_embed error")
        await update.message.reply_text(f"❌ Xəta: {e}")

    ctx.user_data.clear()
    await update.message.reply_text("Ana menyu:", reply_markup=kb_main())
    return ConversationHandler.END

# ══════════════════════════════════════════════════════════════════════════════
#  REVEAL FLOW  (2 addım: açar → şəkil)
# ══════════════════════════════════════════════════════════════════════════════

async def reveal_key_step(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    ctx.user_data["key"] = update.message.text.strip()
    await update.message.reply_text(
        "*Addım 2/2* — 🖼 Gizli məlumat olan şəkili göndər:\n\n"
        "⚠️ *📎 Fayl kimi* göndər!",
        parse_mode="Markdown", reply_markup=kb_cancel(),
    )
    return S_REVEAL_IMG

async def reveal_img_step(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    doc   = update.message.document
    photo = update.message.photo

    if not doc and not photo:
        await update.message.reply_text(
            "❌ Fayl göndərilmədi.\n📎 *Fayl kimi* göndər.",
            parse_mode="Markdown"
        )
        return S_REVEAL_IMG

    if photo:
        await update.message.reply_text(
            "⚠️ Şəkil JPEG kimi göndərildi — əgər məlumat tapılmazsa "
            "*📎 Fayl kimi* yenidən göndər.",
            parse_mode="Markdown"
        )

    pw  = ctx.user_data.get("key", "")
    buf = io.BytesIO()
    if doc:
        await (await doc.get_file()).download_to_memory(buf)
    else:
        await (await photo[-1].get_file()).download_to_memory(buf)

    try:
        t0      = time.time()
        raw     = steg_extract(buf.getvalue())
        ms_ext  = int((time.time() - t0) * 1000)

        t1      = time.time()
        plain   = decrypt(raw, pw)
        ms_dec  = int((time.time() - t1) * 1000)

        text    = plain.decode("utf-8")

        await update.message.reply_text(
            f"🔎 *Gizli məlumat tapıldı!*\n\n"
            f"`{text}`\n\n"
            f"⚡ Çıxartma: {ms_ext} ms  |  Deşifrə: {ms_dec} ms",
            parse_mode="Markdown",
        )
    except ValueError as e:
        await update.message.reply_text(
            f"❌ `{e}`",
            parse_mode="Markdown"
        )
    except Exception as e:
        logger.exception("steg_extract error")
        await update.message.reply_text(f"❌ Xəta: {e}")

    ctx.user_data.clear()
    await update.message.reply_text("Ana menyu:", reply_markup=kb_main())
    return ConversationHandler.END

# ══════════════════════════════════════════════════════════════════════════════
#  COMMANDS
# ══════════════════════════════════════════════════════════════════════════════

async def cmd_cancel(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    ctx.user_data.clear()
    await update.message.reply_text("Ləğv edildi.", reply_markup=kb_main())
    return ConversationHandler.END

# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main():
    if not BOT_TOKEN:
        raise RuntimeError("BOT_TOKEN təyin edilməyib!")

    app = Application.builder().token(BOT_TOKEN).build()

    conv = ConversationHandler(
        entry_points=[
            CommandHandler("start",  cmd_start),
            CallbackQueryHandler(button_handler),
        ],
        states={
            S_HIDE_KEY:   [MessageHandler(filters.TEXT & ~filters.COMMAND, hide_key_step),   CallbackQueryHandler(button_handler)],
            S_HIDE_TEXT:  [MessageHandler(filters.TEXT & ~filters.COMMAND, hide_text_step),  CallbackQueryHandler(button_handler)],
            S_HIDE_IMG:   [MessageHandler(filters.Document.ALL | filters.PHOTO, hide_img_step), CallbackQueryHandler(button_handler)],
            S_REVEAL_KEY: [MessageHandler(filters.TEXT & ~filters.COMMAND, reveal_key_step), CallbackQueryHandler(button_handler)],
            S_REVEAL_IMG: [MessageHandler(filters.Document.ALL | filters.PHOTO, reveal_img_step), CallbackQueryHandler(button_handler)],
        },
        fallbacks=[
            CommandHandler("cancel", cmd_cancel),
            CommandHandler("start",  cmd_start),
        ],
        allow_reentry=True,
    )

    app.add_handler(conv)
    logger.info("StegoBot v1 işə düşdü ✅")
    app.run_polling(drop_pending_updates=True)


if __name__ == "__main__":
    main()
