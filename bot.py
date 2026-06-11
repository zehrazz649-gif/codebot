"""
StegoBot v2 — Steganography + QR Şifrələmə
  • AES-256-GCM + PBKDF2-SHA256 (600k iter) + HMAC-SHA256
  • LSB Steganography — şəkildə gizlətmə (numpy vectorized)
  • QR Şifrələmə — şifrəli məlumatı QR koda çevir / QR-dan oxu
"""

import os, io, base64, hashlib, hmac as hmac_mod, struct, logging, secrets, time

import numpy as np
from PIL import Image
import qrcode
from pyzbar.pyzbar import decode as qr_decode

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

logging.basicConfig(format="%(asctime)s %(levelname)s %(message)s", level=logging.INFO)
logger = logging.getLogger(__name__)

BOT_TOKEN    = os.environ.get("BOT_TOKEN", "")
BOT_USERNAME = os.environ.get("BOT_USERNAME", "your_bot")

# ── States ────────────────────────────────────────────────────────────────────
(
    S_HIDE_KEY, S_HIDE_TEXT, S_HIDE_IMG,
    S_REVEAL_KEY, S_REVEAL_IMG,
    S_QR_ENC_KEY, S_QR_ENC_TEXT,
    S_QR_DEC_KEY, S_QR_DEC_IMG,
) = range(9)

MAGIC    = b"STEG"
QR_MAGIC = b"QRCR"

# ══════════════════════════════════════════════════════════════════════════════
#  CRYPTO CORE  —  AES-256-GCM + PBKDF2 + HMAC
# ══════════════════════════════════════════════════════════════════════════════

def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(hashes.SHA256(), 32, salt, 600_000, default_backend())
    return kdf.derive(password.encode("utf-8"))

def encrypt(plaintext: bytes, password: str) -> bytes:
    salt  = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    key   = _derive_key(password, salt)
    ct    = AESGCM(key).encrypt(nonce, plaintext, None)
    mac_key = hashlib.sha256(b"steg_mac:" + key).digest()
    sig   = hmac_mod.new(mac_key, salt + nonce + ct, hashlib.sha256).digest()
    return MAGIC + salt + nonce + sig + ct

def decrypt(payload: bytes, password: str) -> bytes:
    if len(payload) < 4 + 32 + 12 + 32 + 16:
        raise ValueError("Payload çox qısadır.")
    if payload[:4] != MAGIC:
        raise ValueError("Tanınmayan format.")
    salt = payload[4:36]; nonce = payload[36:48]
    sig  = payload[48:80]; ct   = payload[80:]
    key  = _derive_key(password, salt)
    mac_key = hashlib.sha256(b"steg_mac:" + key).digest()
    if not hmac_mod.compare_digest(sig, hmac_mod.new(mac_key, salt + nonce + ct, hashlib.sha256).digest()):
        raise ValueError("Şifrə yanlışdır və ya məlumat dəyişdirilib.")
    try:
        return AESGCM(key).decrypt(nonce, ct, None)
    except Exception:
        raise ValueError("Deşifrə uğursuz.")

# ══════════════════════════════════════════════════════════════════════════════
#  QR CRYPTO  —  daha yüngül şifrələmə (QR tutumu məhduddu)
#  QR məlumatı base64url saxlayır, max ~2000 simvol
#  Format: QR_MAGIC(4) + salt(16) + nonce(12) + ciphertext → base64url
# ══════════════════════════════════════════════════════════════════════════════

def qr_encrypt(plaintext: bytes, password: str) -> str:
    """Məlumatı şifrələ → QR-a uyğun base64url string qaytarır."""
    salt  = secrets.token_bytes(16)   # QR üçün daha kiçik salt
    nonce = secrets.token_bytes(12)
    key   = _derive_key(password, salt)
    ct    = AESGCM(key).encrypt(nonce, plaintext, None)
    raw   = QR_MAGIC + salt + nonce + ct
    return base64.urlsafe_b64encode(raw).decode()

def qr_decrypt(b64_data: str, password: str) -> bytes:
    """Base64url stringini deşifrə et."""
    try:
        raw = base64.urlsafe_b64decode(b64_data + "==")
    except Exception:
        raise ValueError("Keçərsiz QR məlumatı.")
    if len(raw) < 4 + 16 + 12 + 16:
        raise ValueError("QR məlumatı çox qısadır.")
    if raw[:4] != QR_MAGIC:
        raise ValueError("Bu QR bu bot tərəfindən yaradılmayıb.")
    salt  = raw[4:20]; nonce = raw[20:32]; ct = raw[32:]
    key   = _derive_key(password, salt)
    try:
        return AESGCM(key).decrypt(nonce, ct, None)
    except Exception:
        raise ValueError("Şifrə yanlışdır.")

def make_qr(data: str, error_correction=qrcode.constants.ERROR_CORRECT_H) -> bytes:
    """
    Şifrəli datadan yüksək keyfiyyətli QR kod yarat.
    ERROR_CORRECT_H — %30 zədələnmədə belə oxunur.
    """
    qr = qrcode.QRCode(
        version=None,           # avtomatik ölçü
        error_correction=error_correction,
        box_size=10,            # piksel/qutu — yüksək keyfiyyət
        border=4,
    )
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white").convert("RGB")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()

def read_qr(img_bytes: bytes) -> str:
    """Şəkildən QR kodu oxu."""
    img    = Image.open(io.BytesIO(img_bytes))
    # Kontrast artır — bulanıq/kiçik QR-lar üçün
    img_gray = img.convert("L")
    results  = qr_decode(img_gray)
    if not results:
        # RGB ilə yenidən cəhd et
        results = qr_decode(img.convert("RGB"))
    if not results:
        raise ValueError(
            "QR kod oxunmadı.\n\n"
            "• Şəkil aydın olmalıdır\n"
            "• QR tam görünməlidir\n"
            "• Fayl kimi göndər (JPEG sıxışdırması QR-ı korur)"
        )
    return results[0].data.decode("utf-8")

# ══════════════════════════════════════════════════════════════════════════════
#  STEGANOGRAPHY  —  LSB vectorized
# ══════════════════════════════════════════════════════════════════════════════

def steg_embed(img_bytes: bytes, secret: bytes) -> bytes:
    img  = Image.open(io.BytesIO(img_bytes)).convert("RGB")
    arr  = np.array(img, dtype=np.uint8)
    flat = arr.flatten()
    full_payload = struct.pack(">I", len(secret)) + secret
    bits = np.unpackbits(np.frombuffer(full_payload, dtype=np.uint8))
    if len(bits) > len(flat):
        raise ValueError(
            f"Şəkil kiçikdir.\n"
            f"Lazım: {len(bits)//3//8:,} piksel  |  Var: {len(flat)//3:,} piksel"
        )
    flat[:len(bits)] = (flat[:len(bits)] & np.uint8(0xFE)) | bits.astype(np.uint8)
    out = Image.fromarray(flat.reshape(arr.shape).astype(np.uint8), "RGB")
    buf = io.BytesIO()
    out.save(buf, format="PNG", optimize=False, compress_level=1)
    return buf.getvalue()

def steg_extract(img_bytes: bytes) -> bytes:
    img  = Image.open(io.BytesIO(img_bytes)).convert("RGB")
    flat = np.array(img, dtype=np.uint8).flatten()
    if len(flat) < 32:
        raise ValueError("Şəkil çox kiçikdir.")
    length = struct.unpack(">I", np.packbits((flat[:32] & 1).astype(np.uint8)).tobytes())[0]
    if length == 0 or 32 + length * 8 > len(flat) or length > 50 * 1024 * 1024:
        raise ValueError("Bu şəkildə gizli məlumat yoxdur.")
    total = 32 + length * 8
    return np.packbits((flat[:total] & 1).astype(np.uint8))[4:4 + length].tobytes()

def capacity_info(img_bytes: bytes):
    arr = np.array(Image.open(io.BytesIO(img_bytes)).convert("RGB"))
    px  = arr.shape[0] * arr.shape[1]
    return px, (px * 3 - 32) // 8 - 4

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
            InlineKeyboardButton("📱 QR Şifrələ",   callback_data="qr_enc"),
            InlineKeyboardButton("📷 QR Oxu/Deşifrə", callback_data="qr_dec"),
        ],
        [
            InlineKeyboardButton("🎲 Güclü Açar Yarat", callback_data="genkey"),
        ],
    ])

def kb_cancel():
    return InlineKeyboardMarkup([[InlineKeyboardButton("❌ Ləğv et", callback_data="cancel")]])

def kb_back():
    return InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ Geri", callback_data="back")]])

# ══════════════════════════════════════════════════════════════════════════════
#  /start
# ══════════════════════════════════════════════════════════════════════════════

async def cmd_start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    ctx.user_data.clear()
    await update.message.reply_text(
        "🔐 *StegoBot v2*\n\n"
        "🖼 *Steganography* — şifrəli məlumatı şəklə göm\n"
        "📱 *QR Şifrələmə* — şifrəli QR kod yarat / oxu\n\n"
        "🛡 *Şifrələmə:* AES-256-GCM + PBKDF2 + HMAC\n"
        "⚡ *Sürət:* Numpy vectorized\n\n"
        "⚠️ Faylları həmişə *📎 Fayl kimi* göndər",
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
            "🖼 *Şəklə Gizlətmə*\n\n*Addım 1/3* — 🔑 Şifrə açarı daxil et:",
            parse_mode="Markdown", reply_markup=kb_cancel(),
        )
        return S_HIDE_KEY

    if d == "reveal":
        ctx.user_data.clear()
        await q.edit_message_text(
            "🔎 *Şəkildən Çıxartma*\n\n*Addım 1/2* — 🔑 Şifrə açarı daxil et:",
            parse_mode="Markdown", reply_markup=kb_cancel(),
        )
        return S_REVEAL_KEY

    if d == "qr_enc":
        ctx.user_data.clear()
        await q.edit_message_text(
            "📱 *QR Şifrələmə*\n\n"
            "*Addım 1/2* — 🔑 Şifrə açarı daxil et:\n\n"
            "_Açarı QR oxuyacaq şəxsə də bildirməlisən_",
            parse_mode="Markdown", reply_markup=kb_cancel(),
        )
        return S_QR_ENC_KEY

    if d == "qr_dec":
        ctx.user_data.clear()
        await q.edit_message_text(
            "📷 *QR Oxu / Deşifrə*\n\n*Addım 1/2* — 🔑 Şifrə açarı daxil et:",
            parse_mode="Markdown", reply_markup=kb_cancel(),
        )
        return S_QR_DEC_KEY

    if d == "genkey":
        k = secrets.token_hex(32)
        await q.edit_message_text(
            "🎲 *Güclü Açar (256-bit):*\n\n"
            f"`{k}`\n\n"
            "⚠️ Bu açarı özəl saxla!",
            parse_mode="Markdown", reply_markup=kb_back(),
        )
        return ConversationHandler.END

    if d in ("cancel", "back"):
        ctx.user_data.clear()
        await q.edit_message_text("Ana menyu:", reply_markup=kb_main())
        return ConversationHandler.END

# ══════════════════════════════════════════════════════════════════════════════
#  STEG HIDE FLOW
# ══════════════════════════════════════════════════════════════════════════════

async def hide_key_step(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    ctx.user_data["key"] = update.message.text.strip()
    await update.message.reply_text(
        "*Addım 2/3* — 📝 Gizlədəcəyin mətni yaz:",
        parse_mode="Markdown", reply_markup=kb_cancel(),
    )
    return S_HIDE_TEXT

async def hide_text_step(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    pw = ctx.user_data["key"]
    try:
        payload = encrypt(update.message.text.strip().encode("utf-8"), pw)
        ctx.user_data["payload"] = payload
        await update.message.reply_text(
            f"*Addım 3/3* — 🖼 Şəkil göndər _(📎 Fayl kimi)_\n\n"
            f"📦 Lazım olan minimum: *{len(payload)*8//3//8 + 10:,} piksel*",
            parse_mode="Markdown", reply_markup=kb_cancel(),
        )
        return S_HIDE_IMG
    except Exception as e:
        await update.message.reply_text(f"❌ {e}")
        ctx.user_data.clear()
        return ConversationHandler.END

async def hide_img_step(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    doc = update.message.document
    photo = update.message.photo
    if not doc and not photo:
        await update.message.reply_text("❌ Fayl/şəkil göndər.", reply_markup=kb_cancel())
        return S_HIDE_IMG
    if photo and not doc:
        await update.message.reply_text("⚠️ Fayl kimi göndərsən daha etibarlı olur.", parse_mode="Markdown")

    payload = ctx.user_data.get("payload")
    buf = io.BytesIO()
    obj = doc if doc else photo[-1]
    await (await obj.get_file()).download_to_memory(buf)

    try:
        px, max_b = capacity_info(buf.getvalue())
        if len(payload) > max_b:
            await update.message.reply_text(
                f"❌ Şəkil kiçikdir!\n"
                f"Tutum: {max_b:,} bayt  |  Lazım: {len(payload):,} bayt\n"
                "Daha böyük şəkil göndər."
            )
            return S_HIDE_IMG
        t0 = time.time()
        result = steg_embed(buf.getvalue(), payload)
        ms = int((time.time() - t0) * 1000)
        await update.message.reply_document(
            io.BytesIO(result), filename="stego.png",
            caption=(
                f"✅ *Gizlədildi!*\n\n"
                f"🖼 Piksel: {px:,}  |  📦 Məlumat: {len(payload):,} bayt\n"
                f"⚡ {ms} ms\n\n"
                f"⚠️ Bu faylı *📎 Fayl kimi* paylaş!"
            ),
            parse_mode="Markdown",
        )
    except Exception as e:
        await update.message.reply_text(f"❌ {e}")

    ctx.user_data.clear()
    await update.message.reply_text("Ana menyu:", reply_markup=kb_main())
    return ConversationHandler.END

# ══════════════════════════════════════════════════════════════════════════════
#  STEG REVEAL FLOW
# ══════════════════════════════════════════════════════════════════════════════

async def reveal_key_step(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    ctx.user_data["key"] = update.message.text.strip()
    await update.message.reply_text(
        "*Addım 2/2* — 🖼 Şəkili göndər _(📎 Fayl kimi)_:",
        parse_mode="Markdown", reply_markup=kb_cancel(),
    )
    return S_REVEAL_IMG

async def reveal_img_step(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    doc = update.message.document
    photo = update.message.photo
    if not doc and not photo:
        await update.message.reply_text("❌ Fayl/şəkil göndər.")
        return S_REVEAL_IMG

    buf = io.BytesIO()
    obj = doc if doc else photo[-1]
    await (await obj.get_file()).download_to_memory(buf)

    try:
        t0  = time.time()
        raw = steg_extract(buf.getvalue())
        t1  = time.time()
        txt = decrypt(raw, ctx.user_data["key"]).decode("utf-8")
        ms  = int((time.time() - t0) * 1000)
        await update.message.reply_text(
            f"🔎 *Tapıldı!*\n\n`{txt}`\n\n⚡ {ms} ms",
            parse_mode="Markdown",
        )
    except ValueError as e:
        await update.message.reply_text(f"❌ `{e}`", parse_mode="Markdown")
    except Exception as e:
        await update.message.reply_text(f"❌ {e}")

    ctx.user_data.clear()
    await update.message.reply_text("Ana menyu:", reply_markup=kb_main())
    return ConversationHandler.END

# ══════════════════════════════════════════════════════════════════════════════
#  QR ENC FLOW  —  mətn → şifrəli QR kod
# ══════════════════════════════════════════════════════════════════════════════

async def qr_enc_key_step(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    ctx.user_data["key"] = update.message.text.strip()
    await update.message.reply_text(
        "*Addım 2/2* — 📝 QR-a kodlanacaq mətni yaz:\n\n"
        "_(Maksimum ~300 simvol tövsiyə olunur — uzun mətn QR-ı mürəkkəbləşdirir)_",
        parse_mode="Markdown", reply_markup=kb_cancel(),
    )
    return S_QR_ENC_TEXT

async def qr_enc_text_step(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    pw   = ctx.user_data["key"]
    text = update.message.text.strip()

    try:
        t0       = time.time()
        b64_data = qr_encrypt(text.encode("utf-8"), pw)
        qr_bytes = make_qr(b64_data)
        ms       = int((time.time() - t0) * 1000)

        # Məlumat ölçüsünü hesabla
        data_len = len(b64_data)

        await update.message.reply_photo(
            io.BytesIO(qr_bytes),
            caption=(
                f"📱 *QR Şifrələndi!*\n\n"
                f"📦 QR məlumat: {data_len} simvol\n"
                f"🛡 Şifrə: AES-256-GCM\n"
                f"⚡ {ms} ms\n\n"
                f"Bu QR-ı skan edib açarla deşifrə et."
            ),
            parse_mode="Markdown",
        )
    except Exception as e:
        logger.exception("qr_enc error")
        await update.message.reply_text(f"❌ {e}")

    ctx.user_data.clear()
    await update.message.reply_text("Ana menyu:", reply_markup=kb_main())
    return ConversationHandler.END

# ══════════════════════════════════════════════════════════════════════════════
#  QR DEC FLOW  —  QR şəkil → deşifrə
# ══════════════════════════════════════════════════════════════════════════════

async def qr_dec_key_step(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    ctx.user_data["key"] = update.message.text.strip()
    await update.message.reply_text(
        "*Addım 2/2* — 📷 QR kod şəklini göndər:\n\n"
        "_(Şəkil kimi göndərmək olar — QR oxuma JPEG-dən də işləyir)_",
        parse_mode="Markdown", reply_markup=kb_cancel(),
    )
    return S_QR_DEC_IMG

async def qr_dec_img_step(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    doc   = update.message.document
    photo = update.message.photo
    if not doc and not photo:
        await update.message.reply_text("❌ QR şəkli göndər.")
        return S_QR_DEC_IMG

    buf = io.BytesIO()
    obj = doc if doc else photo[-1]
    await (await obj.get_file()).download_to_memory(buf)

    try:
        t0       = time.time()
        b64_data = read_qr(buf.getvalue())
        t1       = time.time()
        plain    = qr_decrypt(b64_data, ctx.user_data["key"])
        ms       = int((time.time() - t0) * 1000)
        text     = plain.decode("utf-8")

        await update.message.reply_text(
            f"📱 *QR Deşifrə uğurlu!*\n\n`{text}`\n\n⚡ {ms} ms",
            parse_mode="Markdown",
        )
    except ValueError as e:
        await update.message.reply_text(f"❌ `{e}`", parse_mode="Markdown")
    except Exception as e:
        logger.exception("qr_dec error")
        await update.message.reply_text(f"❌ {e}")

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
            CommandHandler("start", cmd_start),
            CallbackQueryHandler(button_handler),
        ],
        states={
            S_HIDE_KEY:    [MessageHandler(filters.TEXT & ~filters.COMMAND, hide_key_step),    CallbackQueryHandler(button_handler)],
            S_HIDE_TEXT:   [MessageHandler(filters.TEXT & ~filters.COMMAND, hide_text_step),   CallbackQueryHandler(button_handler)],
            S_HIDE_IMG:    [MessageHandler(filters.Document.ALL | filters.PHOTO, hide_img_step), CallbackQueryHandler(button_handler)],
            S_REVEAL_KEY:  [MessageHandler(filters.TEXT & ~filters.COMMAND, reveal_key_step),  CallbackQueryHandler(button_handler)],
            S_REVEAL_IMG:  [MessageHandler(filters.Document.ALL | filters.PHOTO, reveal_img_step), CallbackQueryHandler(button_handler)],
            S_QR_ENC_KEY:  [MessageHandler(filters.TEXT & ~filters.COMMAND, qr_enc_key_step),  CallbackQueryHandler(button_handler)],
            S_QR_ENC_TEXT: [MessageHandler(filters.TEXT & ~filters.COMMAND, qr_enc_text_step), CallbackQueryHandler(button_handler)],
            S_QR_DEC_KEY:  [MessageHandler(filters.TEXT & ~filters.COMMAND, qr_dec_key_step),  CallbackQueryHandler(button_handler)],
            S_QR_DEC_IMG:  [MessageHandler(filters.Document.ALL | filters.PHOTO, qr_dec_img_step), CallbackQueryHandler(button_handler)],
        },
        fallbacks=[
            CommandHandler("cancel", cmd_cancel),
            CommandHandler("start",  cmd_start),
        ],
        allow_reentry=True,
    )

    app.add_handler(conv)
    logger.info("StegoBot v2 işə düşdü ✅")
    app.run_polling(drop_pending_updates=True)


if __name__ == "__main__":
    main()
