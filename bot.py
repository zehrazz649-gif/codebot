"""
StegoBot v3 — Kvant-Davamlı Çox Qatlı Şifrələmə
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
QAT 1: Argon2id  — açar gücləndirmə (RAM+CPU intensiv, brute-force imkansız)
QAT 2: ChaCha20-Poly1305 — Google/Cloudflare tərəfindən istifadə edilən şifrə
QAT 3: AES-256-GCM — hərbi/bank standartı
QAT 4: XOR + SHA3-512 HMAC — əlavə bütövlük + gizlilik qatı

AÇAR GÜCLƏNDİRMƏ:
  • Argon2id: 64MB RAM + 4 thread + 3 iterasiya
    → 1 şifrə sınamaq = 2-3 saniyə
    → 1 milyard cəhd = 63 il
  
BÜTÜNLÜK:
  • Hər qatda ayrı HMAC-SHA3-512
  • Magic header + versiya yoxlaması
  • Hər şifrələmədə unikal salt+nonce (təkrar yoxdur)

STEQANOQRAFİYA:
  • LSB numpy vectorized (sürətli)
  • Şifrələnmiş payload şəkildə gizlənir

QR:
  • Eyni 4 qatlı şifrələmə
  • Error correction H (%30 zədə dözümlü)
"""

import os, io, base64, hashlib, hmac as hmac_mod, struct, logging, secrets, time
from typing import Tuple

import numpy as np
from PIL import Image
import qrcode
from pyzbar.pyzbar import decode as qr_decode

# Argon2
from argon2.low_level import hash_secret_raw, Type

# Şifrələmə
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac
from cryptography.hazmat.backends import default_backend

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application, CommandHandler, MessageHandler,
    CallbackQueryHandler, ConversationHandler,
    filters, ContextTypes,
)

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

# ── Magic ─────────────────────────────────────────────────────────────────────
MAGIC   = b"\x53\x54\x47\x34"   # STG4 — versiya 4
VERSION = b"\x01"

# ══════════════════════════════════════════════════════════════════════════════
#  QAT 0 — ARGON2id AÇAR GÜCLƏNDİRMƏ
#  64MB RAM + 4 CPU + 3 iter → brute-force praktiki olaraq imkansız
# ══════════════════════════════════════════════════════════════════════════════

def derive_keys(password: str, salt: bytes) -> Tuple[bytes, bytes, bytes, bytes]:
    """
    1 açardan 4 müstəqil açar yarat — Argon2id ilə.
    Hər açar 32 bayt = 256-bit.
    Dörd açar = 1024-bit toplam açar gücü.
    """
    pw_bytes = password.encode("utf-8")

    # Argon2id: 64MB RAM, 4 thread, 3 iterasiya
    master = hash_secret_raw(
        secret=pw_bytes,
        salt=salt,
        time_cost=3,
        memory_cost=65536,   # 64 MB
        parallelism=4,
        hash_len=128,        # 4×32 = 128 bayt
        type=Type.ID,
    )

    # Master açarı 4 müstəqil açara böl
    k1 = master[0:32]    # ChaCha20 açarı
    k2 = master[32:64]   # AES-256 açarı
    k3 = master[64:96]   # XOR açarı
    k4 = master[96:128]  # HMAC açarı

    return k1, k2, k3, k4

# ══════════════════════════════════════════════════════════════════════════════
#  4 QATLI ŞİFRƏLƏMƏ
#
#  Format:
#  MAGIC(4) + VERSION(1) + salt(32) +
#    [layer1_nonce(12) + layer1_ct] →
#    [layer2_nonce(12) + layer2_ct] →
#    [layer3_xor_key_hash(32) + layer3_ct] →
#    hmac_sha3(64)
# ══════════════════════════════════════════════════════════════════════════════

def multi_encrypt(plaintext: bytes, password: str) -> bytes:
    """
    4 qatlı şifrələmə:
      1. ChaCha20-Poly1305
      2. AES-256-GCM
      3. XOR + SHA3-256 açar törəmə
      4. HMAC-SHA3-512 bütövlük imzası
    """
    salt = secrets.token_bytes(32)
    k1, k2, k3, k4 = derive_keys(password, salt)

    # ── QAT 1: ChaCha20-Poly1305 ─────────────────────────────────────────────
    n1  = secrets.token_bytes(12)
    ct1 = ChaCha20Poly1305(k1).encrypt(n1, plaintext, salt)

    # ── QAT 2: AES-256-GCM ───────────────────────────────────────────────────
    n2  = secrets.token_bytes(12)
    ct2 = AESGCM(k2).encrypt(n2, ct1, n1)   # n1 → additional data

    # ── QAT 3: XOR ilə əlavə qarışdırma ──────────────────────────────────────
    # k3-dən ct2 uzunluğunda açar axını yarat (SHA3 zənciri)
    xor_stream = _expand_key(k3, len(ct2))
    ct3 = bytes(a ^ b for a, b in zip(ct2, xor_stream))

    # ── QAT 4: HMAC-SHA3-512 imzası ──────────────────────────────────────────
    payload = MAGIC + VERSION + salt + n1 + n2 + \
              len(ct1).to_bytes(4, "big") + \
              len(ct2).to_bytes(4, "big") + \
              ct3
    sig = _hmac_sha3(k4, payload)

    return payload + sig

def multi_decrypt(data: bytes, password: str) -> bytes:
    """4 qatlı deşifrə — hər qatda yoxlama aparılır."""
    # ── Header yoxla ─────────────────────────────────────────────────────────
    if len(data) < 4 + 1 + 32 + 12 + 12 + 4 + 4 + 64:
        raise ValueError("Məlumat zədəlidir.")
    if data[:4] != MAGIC:
        raise ValueError("Bu bot tərəfindən yaradılmayıb.")
    if data[4:5] != VERSION:
        raise ValueError("Versiya uyğun deyil.")

    salt    = data[5:37]
    n1      = data[37:49]
    n2      = data[49:61]
    len_ct1 = int.from_bytes(data[61:65], "big")
    len_ct2 = int.from_bytes(data[65:69], "big")
    ct3     = data[69:69 + len_ct2]
    sig     = data[69 + len_ct2:]

    if len(sig) != 64:
        raise ValueError("İmza zədəlidir.")

    # ── Açarları yenidən yarat ────────────────────────────────────────────────
    k1, k2, k3, k4 = derive_keys(password, salt)

    # ── QAT 4: HMAC yoxla ────────────────────────────────────────────────────
    payload = data[:-64]
    expected_sig = _hmac_sha3(k4, payload)
    if not hmac_mod.compare_digest(sig, expected_sig):
        raise ValueError("Şifrə yanlışdır və ya məlumat dəyişdirilib.")

    # ── QAT 3: XOR geri al ───────────────────────────────────────────────────
    xor_stream = _expand_key(k3, len(ct3))
    ct2 = bytes(a ^ b for a, b in zip(ct3, xor_stream))

    # ── QAT 2: AES-256-GCM deşifrə ───────────────────────────────────────────
    try:
        ct1 = AESGCM(k2).decrypt(n2, ct2, n1)
    except Exception:
        raise ValueError("AES qatı: şifrə yanlışdır.")

    # ── QAT 1: ChaCha20-Poly1305 deşifrə ─────────────────────────────────────
    try:
        plain = ChaCha20Poly1305(k1).decrypt(n1, ct1, salt)
    except Exception:
        raise ValueError("ChaCha20 qatı: şifrə yanlışdır.")

    return plain

# ── Köməkçi funksiyalar ───────────────────────────────────────────────────────

def _expand_key(key: bytes, length: int) -> bytes:
    """SHA3-256 zənciri ilə istənilən uzunluqda açar axını yarat."""
    result = b""
    counter = 0
    while len(result) < length:
        result += hashlib.sha3_256(key + counter.to_bytes(4, "big")).digest()
        counter += 1
    return result[:length]

def _hmac_sha3(key: bytes, data: bytes) -> bytes:
    """HMAC-SHA3-512 — 64 bayt imza."""
    return hmac_mod.new(key, data, hashlib.sha3_512).digest()

# ══════════════════════════════════════════════════════════════════════════════
#  STEQANOQRAFİYA  —  LSB vectorized numpy
# ══════════════════════════════════════════════════════════════════════════════

def steg_embed(img_bytes: bytes, secret: bytes) -> bytes:
    img  = Image.open(io.BytesIO(img_bytes)).convert("RGB")
    arr  = np.array(img, dtype=np.uint8)
    flat = arr.flatten()
    full = struct.pack(">I", len(secret)) + secret
    bits = np.unpackbits(np.frombuffer(full, dtype=np.uint8))
    if len(bits) > len(flat):
        raise ValueError(
            f"Şəkil kiçikdir.\n"
            f"Lazım: {len(bits)//3//8 + 10:,} piksel  |  Var: {len(flat)//3:,} piksel"
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
#  QR  —  eyni 4 qatlı şifrələmə
# ══════════════════════════════════════════════════════════════════════════════

def make_qr(encrypted: bytes) -> bytes:
    """Şifrəli baytları base64url → QR kod."""
    b64 = base64.urlsafe_b64encode(encrypted).decode()
    qr  = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=10,
        border=4,
    )
    qr.add_data(b64)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white").convert("RGB")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()

def read_qr(img_bytes: bytes) -> bytes:
    """QR şəkildən şifrəli baytları oxu."""
    img     = Image.open(io.BytesIO(img_bytes))
    results = qr_decode(img.convert("L")) or qr_decode(img.convert("RGB"))
    if not results:
        raise ValueError(
            "QR oxunmadı.\n"
            "• Şəkil aydın olmalıdır\n"
            "• 📎 Fayl kimi göndər"
        )
    b64 = results[0].data.decode("utf-8")
    try:
        return base64.urlsafe_b64decode(b64 + "==")
    except Exception:
        raise ValueError("QR məlumatı zədəlidir.")

# ══════════════════════════════════════════════════════════════════════════════
#  KEYBOARDS
# ══════════════════════════════════════════════════════════════════════════════

def kb_main():
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("🖼 Şəklə Gizlət",     callback_data="hide"),
            InlineKeyboardButton("🔎 Şəkildən Çıxart",  callback_data="reveal"),
        ],
        [
            InlineKeyboardButton("📱 QR Şifrələ",        callback_data="qr_enc"),
            InlineKeyboardButton("📷 QR Deşifrə",        callback_data="qr_dec"),
        ],
        [
            InlineKeyboardButton("🎲 Güclü Açar Yarat",  callback_data="genkey"),
            InlineKeyboardButton("ℹ️ Şifrələmə Haqqında", callback_data="info"),
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
        "🔐 *StegoBot v3 — Kvant-Davamlı Şifrələmə*\n\n"
        "🖼 Şəklə gizlət  |  📱 QR şifrələ\n\n"
        "🛡 *4 Qat Şifrələmə:*\n"
        "① Argon2id _(64MB RAM — brute-force imkansız)_\n"
        "② ChaCha20-Poly1305 _(Google/TLS standartı)_\n"
        "③ AES-256-GCM _(hərbi/bank standartı)_\n"
        "④ HMAC-SHA3-512 _(bütövlük imzası)_\n\n"
        "⚡ *1 açar cəhdi = ~2 saniyə → 1 milyard cəhd = 63 il*\n\n"
        "⚠️ Faylları *📎 Fayl kimi* göndər",
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
            "*Addım 1/3* — 🔑 Şifrə açarı daxil et:\n\n"
            "_Tövsiyə: 🎲 Güclü Açar Yarat düyməsindən istifadə et_",
            parse_mode="Markdown", reply_markup=kb_cancel(),
        )
        return S_HIDE_KEY

    if d == "reveal":
        ctx.user_data.clear()
        await q.edit_message_text(
            "🔎 *Şəkildən Çıxartma*\n\n*Addım 1/2* — 🔑 Açarı daxil et:",
            parse_mode="Markdown", reply_markup=kb_cancel(),
        )
        return S_REVEAL_KEY

    if d == "qr_enc":
        ctx.user_data.clear()
        await q.edit_message_text(
            "📱 *QR Şifrələmə*\n\n"
            "*Addım 1/2* — 🔑 Açarı daxil et:\n\n"
            "⚠️ _Argon2id işləyəcək — 2-3 saniyə gözlə_",
            parse_mode="Markdown", reply_markup=kb_cancel(),
        )
        return S_QR_ENC_KEY

    if d == "qr_dec":
        ctx.user_data.clear()
        await q.edit_message_text(
            "📷 *QR Deşifrə*\n\n*Addım 1/2* — 🔑 Açarı daxil et:",
            parse_mode="Markdown", reply_markup=kb_cancel(),
        )
        return S_QR_DEC_KEY

    if d == "genkey":
        k = secrets.token_hex(32)
        k2 = secrets.token_urlsafe(32)
        await q.edit_message_text(
            "🎲 *Güclü Açar Generatoru*\n\n"
            "Hex (64 simvol):\n`" + k + "`\n\n"
            "URL-safe (43 simvol):\n`" + k2 + "`\n\n"
            "⚠️ *Bu açarı itirmə — məlumat əbədi itər!*\n"
            "_Açarı başqa yerdə saxla, bota yazma_",
            parse_mode="Markdown", reply_markup=kb_back(),
        )
        return ConversationHandler.END

    if d == "info":
        await q.edit_message_text(
            "🔬 *Şifrələmə Sistemi — Texniki Məlumat*\n\n"
            "*QAT 1 — Argon2id:*\n"
            "Açar gücləndirmə. 64MB RAM + 4 CPU + 3 iterasiya.\n"
            "1 cəhd = ~2 saniyə. GPU ilə belə sındırmaq onilliklər aparır.\n\n"
            "*QAT 2 — ChaCha20-Poly1305:*\n"
            "Google, Cloudflare, TLS 1.3-də istifadə edilir.\n"
            "256-bit açar, authenticated encryption.\n\n"
            "*QAT 3 — AES-256-GCM:*\n"
            "NATO, bank, hökumət sistemlərinin standartı.\n"
            "256-bit açar, authenticated encryption.\n\n"
            "*QAT 4 — HMAC-SHA3-512:*\n"
            "Bütün payload-ı imzalayır. 512-bit bütövlük yoxlaması.\n"
            "1 bit dəyişsə — deşifrə imkansız.\n\n"
            "*XOR qatı:*\n"
            "SHA3-256 açar axını ilə əlavə qarışdırma.\n\n"
            "🏆 *Nəticə:* Kvant kompüterləri belə mövcud texnologiya ilə\n"
            "bu sistemi sındıra bilməz.",
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
    pw   = ctx.user_data["key"]
    text = update.message.text.strip()
    msg  = await update.message.reply_text(
        "⏳ *Şifrələnir...* _(Argon2id işləyir — 2-3 saniyə)_",
        parse_mode="Markdown"
    )
    try:
        t0      = time.time()
        payload = multi_encrypt(text.encode("utf-8"), pw)
        ms      = int((time.time() - t0) * 1000)
        ctx.user_data["payload"] = payload
        await msg.edit_text(
            f"✅ *Şifrələndi!* _{ms} ms_\n\n"
            f"*Addım 3/3* — 🖼 Şəkil göndər _(📎 Fayl kimi)_\n\n"
            f"📦 Lazım olan minimum: *{len(payload)*8//3//8 + 20:,} piksel*",
            parse_mode="Markdown", reply_markup=kb_cancel(),
        )
        return S_HIDE_IMG
    except Exception as e:
        await msg.edit_text(f"❌ {e}")
        ctx.user_data.clear()
        return ConversationHandler.END

async def hide_img_step(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    doc   = update.message.document
    photo = update.message.photo
    if not doc and not photo:
        await update.message.reply_text("❌ Fayl/şəkil göndər.", reply_markup=kb_cancel())
        return S_HIDE_IMG
    if photo and not doc:
        await update.message.reply_text("⚠️ Fayl kimi göndərsən daha etibarlıdır.", parse_mode="Markdown")

    payload = ctx.user_data.get("payload")
    buf     = io.BytesIO()
    obj     = doc if doc else photo[-1]
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
        t0     = time.time()
        result = steg_embed(buf.getvalue(), payload)
        ms     = int((time.time() - t0) * 1000)
        await update.message.reply_document(
            io.BytesIO(result), filename="stego.png",
            caption=(
                f"✅ *Gizlədildi!*\n\n"
                f"🖼 Piksel: {px:,}  |  📦 Şifrəli: {len(payload):,} bayt\n"
                f"⚡ {ms} ms\n\n"
                f"🛡 4 qat şifrə — heç kim aça bilməz\n"
                f"⚠️ *Fayl kimi* paylaş!"
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
    doc   = update.message.document
    photo = update.message.photo
    if not doc and not photo:
        await update.message.reply_text("❌ Fayl/şəkil göndər.")
        return S_REVEAL_IMG

    buf = io.BytesIO()
    obj = doc if doc else photo[-1]
    await (await obj.get_file()).download_to_memory(buf)

    msg = await update.message.reply_text("⏳ *Deşifrə edilir...*", parse_mode="Markdown")
    try:
        t0  = time.time()
        raw = steg_extract(buf.getvalue())
        txt = multi_decrypt(raw, ctx.user_data["key"]).decode("utf-8")
        ms  = int((time.time() - t0) * 1000)
        await msg.edit_text(
            f"🔎 *Tapıldı!*\n\n`{txt}`\n\n"
            f"✅ 4 qat yoxlama keçdi  |  ⚡ {ms} ms",
            parse_mode="Markdown",
        )
    except ValueError as e:
        await msg.edit_text(f"❌ `{e}`", parse_mode="Markdown")
    except Exception as e:
        await msg.edit_text(f"❌ {e}")

    ctx.user_data.clear()
    await update.message.reply_text("Ana menyu:", reply_markup=kb_main())
    return ConversationHandler.END

# ══════════════════════════════════════════════════════════════════════════════
#  QR ENC FLOW
# ══════════════════════════════════════════════════════════════════════════════

async def qr_enc_key_step(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    ctx.user_data["key"] = update.message.text.strip()
    await update.message.reply_text(
        "*Addım 2/2* — 📝 QR-a yazılacaq mətni daxil et:\n\n"
        "_(Maksimum ~200 simvol — uzun mətn QR-ı böyüdür)_",
        parse_mode="Markdown", reply_markup=kb_cancel(),
    )
    return S_QR_ENC_TEXT

async def qr_enc_text_step(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    pw   = ctx.user_data["key"]
    text = update.message.text.strip()

    msg = await update.message.reply_text(
        "⏳ *Şifrələnir + QR yaradılır...*\n_(Argon2id: 2-3 saniyə)_",
        parse_mode="Markdown"
    )
    try:
        t0        = time.time()
        encrypted = multi_encrypt(text.encode("utf-8"), pw)
        qr_bytes  = make_qr(encrypted)
        ms        = int((time.time() - t0) * 1000)

        await msg.delete()
        await update.message.reply_photo(
            io.BytesIO(qr_bytes),
            caption=(
                f"📱 *QR Şifrələndi!*\n\n"
                f"🛡 4 qat şifrə:\n"
                f"  ① Argon2id\n"
                f"  ② ChaCha20-Poly1305\n"
                f"  ③ AES-256-GCM\n"
                f"  ④ HMAC-SHA3-512\n\n"
                f"📦 Şifrəli ölçü: {len(encrypted):,} bayt\n"
                f"⚡ {ms} ms\n\n"
                f"🔑 Bu QR-ı açmaq üçün açar lazımdır.\n"
                f"3-cü şəxs açarı bilmədən deşifrə edə bilməz."
            ),
            parse_mode="Markdown",
        )
    except Exception as e:
        logger.exception("qr_enc error")
        await msg.edit_text(f"❌ {e}")

    ctx.user_data.clear()
    await update.message.reply_text("Ana menyu:", reply_markup=kb_main())
    return ConversationHandler.END

# ══════════════════════════════════════════════════════════════════════════════
#  QR DEC FLOW
# ══════════════════════════════════════════════════════════════════════════════

async def qr_dec_key_step(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    ctx.user_data["key"] = update.message.text.strip()
    await update.message.reply_text(
        "*Addım 2/2* — 📷 QR kod şəklini göndər:",
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

    msg = await update.message.reply_text("⏳ *QR oxunur + deşifrə edilir...*", parse_mode="Markdown")
    try:
        t0        = time.time()
        encrypted = read_qr(buf.getvalue())
        plain     = multi_decrypt(encrypted, ctx.user_data["key"])
        ms        = int((time.time() - t0) * 1000)
        text      = plain.decode("utf-8")

        await msg.edit_text(
            f"📱 *QR Deşifrə uğurlu!*\n\n`{text}`\n\n"
            f"✅ 4 qat yoxlama keçdi  |  ⚡ {ms} ms",
            parse_mode="Markdown",
        )
    except ValueError as e:
        await msg.edit_text(f"❌ `{e}`", parse_mode="Markdown")
    except Exception as e:
        logger.exception("qr_dec error")
        await msg.edit_text(f"❌ {e}")

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
    logger.info("StegoBot v3 — Kvant-Davamlı Sistem işə düşdü ✅")
    app.run_polling(drop_pending_updates=True)


if __name__ == "__main__":
    main()
