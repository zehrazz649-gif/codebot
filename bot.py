"""
CryptoBot v2 — AES-256-GCM Telegram Şifrələmə Botu
Yeni funksiyalar:
  • Token müddəti  (1h / 6h / 24h / 7gün / sınırsız)
  • Güclü açar generatoru  (/genkey)
  • Fayl şifrələmə/deşifrələmə  (.txt, .pdf, istənilən binary)
  • İki tərəfli şifrələmə  (X25519 ECDH + AES-256-GCM)
"""

import os, io, base64, hashlib, struct, logging, secrets, time
from datetime import datetime, timezone

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application, CommandHandler, MessageHandler,
    CallbackQueryHandler, ConversationHandler, filters, ContextTypes,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.backends import default_backend

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(format="%(asctime)s %(name)s %(levelname)s %(message)s", level=logging.INFO)
logger = logging.getLogger(__name__)

# ── Config ────────────────────────────────────────────────────────────────────
BOT_TOKEN = os.environ.get("BOT_TOKEN", "")

# ── Conversation states ───────────────────────────────────────────────────────
(
    # symmetric encrypt flow
    S_ENC_KEY, S_ENC_EXPIRY, S_ENC_TEXT, S_ENC_FILE,
    # symmetric decrypt flow
    S_DEC_KEY, S_DEC_TOKEN, S_DEC_FILE,
    # E2E flow
    E2E_SEND_PUBKEY, E2E_SEND_MSG,
    E2E_RECV_PRIVKEY, E2E_RECV_BUNDLE,
) = range(11)

# ── Protocol versions ─────────────────────────────────────────────────────────
VER_SYM  = b"\x02"   # symmetric  (v2 = with expiry)
VER_E2E  = b"\x03"   # E2E ECDH


# ══════════════════════════════════════════════════════════════════════════════
#  CRYPTO CORE
# ══════════════════════════════════════════════════════════════════════════════

def _pbkdf2(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(hashes.SHA256(), 32, salt, 600_000, default_backend())
    return kdf.derive(password.encode())


def sym_encrypt(data: bytes, password: str, ttl_seconds: int | None) -> bytes:
    """
    Symmetric encrypt (AES-256-GCM + PBKDF2).
    Wire format:
      VER(1) | SALT(32) | NONCE(12) | EXPIRES_TS(8, big-endian int64, 0=never) | CT+TAG
    """
    salt  = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    key   = _pbkdf2(password, salt)
    expires = int(time.time()) + ttl_seconds if ttl_seconds else 0
    aad   = struct.pack(">q", expires)          # authenticated additional data
    ct    = AESGCM(key).encrypt(nonce, data, aad)
    return VER_SYM + salt + nonce + aad + ct


def sym_decrypt(payload: bytes, password: str) -> bytes:
    """Decrypt symmetric payload. Raises ValueError on bad password / expiry / tampering."""
    if len(payload) < 1 + 32 + 12 + 8 + 16:
        raise ValueError("Payload çox qısadır.")
    if payload[0:1] != VER_SYM:
        raise ValueError("Versiya uyğun deyil (köhnə token?).")
    salt    = payload[1:33]
    nonce   = payload[33:45]
    aad     = payload[45:53]
    ct      = payload[53:]
    expires = struct.unpack(">q", aad)[0]
    if expires and time.time() > expires:
        ts = datetime.fromtimestamp(expires, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        raise ValueError(f"Tokenin müddəti bitib: {ts}")
    key = _pbkdf2(password, salt)
    try:
        return AESGCM(key).decrypt(nonce, ct, aad)
    except Exception:
        raise ValueError("Şifrə yanlışdır və ya məlumat dəyişdirilib.")


# ── E2E (X25519 ECDH) ─────────────────────────────────────────────────────────

def e2e_generate_keypair() -> tuple[bytes, bytes]:
    """Returns (private_bytes_b64, public_bytes_b64)."""
    priv = X25519PrivateKey.generate()
    pub  = priv.public_key()
    priv_b64 = base64.urlsafe_b64encode(
        priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    ).decode()
    pub_b64 = base64.urlsafe_b64encode(
        pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    ).decode()
    return priv_b64, pub_b64


def e2e_encrypt(plaintext: bytes, recipient_pub_b64: str) -> bytes:
    """Encrypt for recipient using their X25519 public key (ephemeral ECDH)."""
    recipient_pub_raw = base64.urlsafe_b64decode(recipient_pub_b64 + "==")
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
    recipient_pub = X25519PublicKey.from_public_bytes(recipient_pub_raw)

    eph_priv = X25519PrivateKey.generate()
    eph_pub  = eph_priv.public_key()
    shared   = eph_priv.exchange(recipient_pub)

    # derive AES key from shared secret via HKDF-SHA256 (manual PBKDF2 on shared||eph_pub)
    eph_pub_raw = eph_pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    salt  = eph_pub_raw[:32]
    key   = _pbkdf2(shared.hex(), salt)
    nonce = secrets.token_bytes(12)
    ct    = AESGCM(key).encrypt(nonce, plaintext, None)
    return VER_E2E + eph_pub_raw + nonce + ct


def e2e_decrypt(payload: bytes, recipient_priv_b64: str) -> bytes:
    """Decrypt E2E bundle using recipient's private key."""
    if len(payload) < 1 + 32 + 12 + 16:
        raise ValueError("E2E payload çox qısadır.")
    if payload[0:1] != VER_E2E:
        raise ValueError("E2E token versiyası yanlışdır.")
    eph_pub_raw = payload[1:33]
    nonce       = payload[33:45]
    ct          = payload[45:]

    priv_raw = base64.urlsafe_b64decode(recipient_priv_b64 + "==")
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
    priv    = X25519PrivateKey.from_private_bytes(priv_raw)
    eph_pub = X25519PublicKey.from_public_bytes(eph_pub_raw)
    shared  = priv.exchange(eph_pub)

    salt = eph_pub_raw[:32]
    key  = _pbkdf2(shared.hex(), salt)
    try:
        return AESGCM(key).decrypt(nonce, ct, None)
    except Exception:
        raise ValueError("Deşifrə alınmadı — yanlış şəxsi açar və ya dəyişdirilmiş məlumat.")


# ── Helpers ───────────────────────────────────────────────────────────────────

def fingerprint(data: bytes) -> str:
    return hashlib.sha256(data).digest()[:6].hex().upper()

def b64enc(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode()

def b64dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "==")

def genkey(length: int = 32) -> str:
    """Generate a cryptographically random passphrase (hex)."""
    return secrets.token_hex(length)

EXPIRY_OPTIONS = {
    "1h":  3600,
    "6h":  21600,
    "24h": 86400,
    "7d":  604800,
    "∞":   None,
}


# ══════════════════════════════════════════════════════════════════════════════
#  KEYBOARDS
# ══════════════════════════════════════════════════════════════════════════════

def kb_main():
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("🔒 Şifrələ",   callback_data="sym_enc"),
            InlineKeyboardButton("🔓 Deşifrələ", callback_data="sym_dec"),
        ],
        [
            InlineKeyboardButton("📁 Fayl şifrələ",   callback_data="file_enc"),
            InlineKeyboardButton("📂 Fayl deşifrələ", callback_data="file_dec"),
        ],
        [
            InlineKeyboardButton("🔑 Açar generatoru", callback_data="genkey"),
            InlineKeyboardButton("🤝 İki tərəfli",     callback_data="e2e_menu"),
        ],
        [InlineKeyboardButton("ℹ️ Haqqında", callback_data="about")],
    ])

def kb_cancel():
    return InlineKeyboardMarkup([[InlineKeyboardButton("❌ Ləğv et", callback_data="cancel")]])

def kb_expiry():
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("⏱ 1 saat",  callback_data="exp_1h"),
            InlineKeyboardButton("⏱ 6 saat",  callback_data="exp_6h"),
            InlineKeyboardButton("⏱ 24 saat", callback_data="exp_24h"),
        ],
        [
            InlineKeyboardButton("📅 7 gün",    callback_data="exp_7d"),
            InlineKeyboardButton("♾ Sınırsız", callback_data="exp_inf"),
        ],
        [InlineKeyboardButton("❌ Ləğv et", callback_data="cancel")],
    ])

def kb_e2e():
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("📤 Göndərən (şifrələ)", callback_data="e2e_send"),
            InlineKeyboardButton("📥 Alan (deşifrələ)",   callback_data="e2e_recv"),
        ],
        [InlineKeyboardButton("🔑 Açar cütü yarat", callback_data="e2e_keygen")],
        [InlineKeyboardButton("⬅️ Geri", callback_data="back")],
    ])

def kb_back():
    return InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ Ana menyu", callback_data="back")]])


# ══════════════════════════════════════════════════════════════════════════════
#  COMMAND HANDLERS
# ══════════════════════════════════════════════════════════════════════════════

async def cmd_start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    ctx.user_data.clear()
    await update.message.reply_text(
        "🔐 *CryptoBot v2* — Güclü Şifrələmə\n\n"
        "AES-256-GCM · X25519 ECDH · PBKDF2-SHA256\n\n"
        "Nə etmək istəyirsən?",
        parse_mode="Markdown",
        reply_markup=kb_main(),
    )
    return ConversationHandler.END


async def cmd_genkey(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    k16 = genkey(16)
    k32 = genkey(32)
    await update.message.reply_text(
        "🔑 *Güclü açar generatoru*\n\n"
        "128-bit (qısa):\n`" + k16 + "`\n\n"
        "256-bit (tövsiyə olunan):\n`" + k32 + "`\n\n"
        "⚠️ _Açarı özəl saxla — itirsən, mətni bərpa etmək mümkünsüz!_",
        parse_mode="Markdown",
        reply_markup=kb_back(),
    )
    return ConversationHandler.END


async def cmd_cancel(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    ctx.user_data.clear()
    await update.message.reply_text("Ləğv edildi.", reply_markup=kb_main())
    return ConversationHandler.END


# ══════════════════════════════════════════════════════════════════════════════
#  BUTTON ROUTER
# ══════════════════════════════════════════════════════════════════════════════

async def button_handler(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    d = q.data

    # ── Expiry selection ──────────────────────────────────────────────────────
    if d.startswith("exp_"):
        key_map = {"exp_1h": "1h", "exp_6h": "6h", "exp_24h": "24h", "exp_7d": "7d", "exp_inf": "∞"}
        label = key_map[d]
        ctx.user_data["expiry_label"] = label
        ctx.user_data["expiry_sec"]   = EXPIRY_OPTIONS[label]

        mode = ctx.user_data.get("mode")
        if mode == "file_enc":
            await q.edit_message_text(
                f"📁 *Müddət: {label}*\n\nİndi şifrələnəcək faylı göndər:",
                parse_mode="Markdown", reply_markup=kb_cancel(),
            )
            return S_ENC_FILE
        else:
            await q.edit_message_text(
                f"⏱ *Müddət: {label}*\n\nŞifrələnəcək mətni yazın:",
                parse_mode="Markdown", reply_markup=kb_cancel(),
            )
            return S_ENC_TEXT

    # ── Main menu buttons ─────────────────────────────────────────────────────
    if d == "sym_enc":
        ctx.user_data.clear()
        ctx.user_data["mode"] = "sym_enc"
        await q.edit_message_text(
            "🔑 *Şifrə açarı daxil et:*\n_(istənilən söz, cümlə, ya da /genkey ilə alınan açar)_",
            parse_mode="Markdown", reply_markup=kb_cancel(),
        )
        return S_ENC_KEY

    if d == "sym_dec":
        ctx.user_data.clear()
        ctx.user_data["mode"] = "sym_dec"
        await q.edit_message_text(
            "🔑 *Şifrə açarını daxil et:*",
            parse_mode="Markdown", reply_markup=kb_cancel(),
        )
        return S_DEC_KEY

    if d == "file_enc":
        ctx.user_data.clear()
        ctx.user_data["mode"] = "file_enc"
        await q.edit_message_text(
            "🔑 *Fayl şifrələmə — açar daxil et:*",
            parse_mode="Markdown", reply_markup=kb_cancel(),
        )
        return S_ENC_KEY

    if d == "file_dec":
        ctx.user_data.clear()
        ctx.user_data["mode"] = "file_dec"
        await q.edit_message_text(
            "🔑 *Fayl deşifrələmə — açar daxil et:*",
            parse_mode="Markdown", reply_markup=kb_cancel(),
        )
        return S_DEC_KEY

    if d == "genkey":
        k16 = genkey(16)
        k32 = genkey(32)
        await q.edit_message_text(
            "🔑 *Güclü açar generatoru*\n\n"
            "128-bit:\n`" + k16 + "`\n\n"
            "256-bit (tövsiyə):\n`" + k32 + "`\n\n"
            "⚠️ _Açarı özəl saxla!_",
            parse_mode="Markdown", reply_markup=kb_back(),
        )
        return ConversationHandler.END

    if d == "e2e_menu":
        ctx.user_data.clear()
        await q.edit_message_text(
            "🤝 *İki tərəfli şifrələmə (E2E)*\n\n"
            "X25519 ECDH alqoritmi ilə yalnız alan şəxsin deşifrə edə biləcəyi mesajlar göndər.\n\n"
            "*Necə işləyir:*\n"
            "1. Alan şəxs `Açar cütü yarat` → Sənə public key göndərir\n"
            "2. Sən `Göndərən` → Public key + mətn → Şifrəli bundle alırsan\n"
            "3. Alan şəxs `Alan` → Öz private key-i ilə deşifrə edir\n\n"
            "Nə etmək istəyirsən?",
            parse_mode="Markdown", reply_markup=kb_e2e(),
        )
        return ConversationHandler.END

    if d == "e2e_keygen":
        priv_b64, pub_b64 = e2e_generate_keypair()
        await q.edit_message_text(
            "🔑 *X25519 Açar Cütü*\n\n"
            "📢 *Public key* (qarşı tərəfə göndər):\n`" + pub_b64 + "`\n\n"
            "🔒 *Private key* (YALNIZ SƏNİN — heç kimə vermə):\n`" + priv_b64 + "`\n\n"
            "⚠️ _Private key-i özəl yerdə saxla. İtirsən, mesajları bərpa etmək mümkünsüz!_",
            parse_mode="Markdown", reply_markup=kb_back(),
        )
        return ConversationHandler.END

    if d == "e2e_send":
        ctx.user_data.clear()
        ctx.user_data["mode"] = "e2e_send"
        await q.edit_message_text(
            "📤 *E2E Göndərən*\n\nAlıcının *public key*-ni yapışdır:",
            parse_mode="Markdown", reply_markup=kb_cancel(),
        )
        return E2E_SEND_PUBKEY

    if d == "e2e_recv":
        ctx.user_data.clear()
        ctx.user_data["mode"] = "e2e_recv"
        await q.edit_message_text(
            "📥 *E2E Alan*\n\nÖz *private key*-ini yapışdır:",
            parse_mode="Markdown", reply_markup=kb_cancel(),
        )
        return E2E_RECV_PRIVKEY

    if d == "about":
        await q.edit_message_text(
            "ℹ️ *CryptoBot v2 — Texniki Məlumat*\n\n"
            "🔐 Simmetrik: AES-256-GCM\n"
            "🤝 E2E: X25519 ECDH\n"
            "🔑 Açar törəmə: PBKDF2-SHA256 · 600,000 iter\n"
            "🎲 Salt: 256-bit random\n"
            "📦 Nonce: 96-bit random\n"
            "✅ Auth: GCM 128-bit tag\n"
            "⏱ Token müddəti: AAD içinə daxil (tamper-proof)\n"
            "📁 Fayl: binary-safe (istənilən format)\n\n"
            "Hər şifrələmə unikaldır.",
            parse_mode="Markdown", reply_markup=kb_back(),
        )
        return ConversationHandler.END

    if d in ("cancel", "back"):
        ctx.user_data.clear()
        await q.edit_message_text("Ana menyu:", reply_markup=kb_main())
        return ConversationHandler.END


# ══════════════════════════════════════════════════════════════════════════════
#  SYMMETRIC ENCRYPT FLOW
# ══════════════════════════════════════════════════════════════════════════════

async def got_enc_key(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    ctx.user_data["enc_key"] = update.message.text.strip()
    await update.message.reply_text(
        "⏱ *Token neçə müddət etibarlı olsun?*",
        parse_mode="Markdown", reply_markup=kb_expiry(),
    )
    return S_ENC_EXPIRY


async def got_enc_text(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    plaintext = update.message.text.strip().encode()
    password  = ctx.user_data["enc_key"]
    ttl       = ctx.user_data.get("expiry_sec")
    label     = ctx.user_data.get("expiry_label", "∞")

    try:
        raw   = sym_encrypt(plaintext, password, ttl)
        token = b64enc(raw)
        fp    = fingerprint(raw)
        exp_str = f"⏱ Müddət: {label}" if label != "∞" else "♾ Müddətsiz"

        if len(token) <= 3500:
            await update.message.reply_text(
                f"✅ *Şifrələndi!*\n\n"
                f"🔏 Token:\n`{token}`\n\n"
                f"🆔 Barmaq izi: `{fp}`\n"
                f"{exp_str}",
                parse_mode="Markdown",
            )
        else:
            await update.message.reply_text(
                f"✅ Şifrələndi! `{fp}` | {exp_str}\n_(token uzundur, aşağıda)_",
                parse_mode="Markdown",
            )
            for i in range(0, len(token), 4000):
                await update.message.reply_text(f"`{token[i:i+4000]}`", parse_mode="Markdown")
    except Exception as e:
        logger.exception("Encrypt error")
        await update.message.reply_text(f"❌ Xəta: {e}")

    ctx.user_data.clear()
    await update.message.reply_text("Ana menyu:", reply_markup=kb_main())
    return ConversationHandler.END


# ══════════════════════════════════════════════════════════════════════════════
#  SYMMETRIC DECRYPT FLOW
# ══════════════════════════════════════════════════════════════════════════════

async def got_dec_key(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    ctx.user_data["dec_key"] = update.message.text.strip()
    mode = ctx.user_data.get("mode")
    if mode == "file_dec":
        await update.message.reply_text(
            "📂 Şifrəli faylı göndər:", reply_markup=kb_cancel()
        )
        return S_DEC_FILE
    else:
        await update.message.reply_text(
            "📋 *Şifrəli tokeni yapışdır:*",
            parse_mode="Markdown", reply_markup=kb_cancel(),
        )
        return S_DEC_TOKEN


async def got_dec_token(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    token    = update.message.text.strip()
    password = ctx.user_data["dec_key"]
    try:
        raw  = b64dec(token)
        data = sym_decrypt(raw, password)
        text = data.decode("utf-8")
        await update.message.reply_text(
            f"✅ *Deşifrə uğurlu!*\n\n📄 Mətn:\n`{text}`",
            parse_mode="Markdown",
        )
    except ValueError as e:
        await update.message.reply_text(f"❌ *Xəta:* `{e}`", parse_mode="Markdown")
    except Exception:
        logger.exception("Decrypt error")
        await update.message.reply_text("❌ Deşifrə alınmadı.")

    ctx.user_data.clear()
    await update.message.reply_text("Ana menyu:", reply_markup=kb_main())
    return ConversationHandler.END


# ══════════════════════════════════════════════════════════════════════════════
#  FILE ENCRYPT / DECRYPT FLOW
# ══════════════════════════════════════════════════════════════════════════════

async def got_enc_file(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    doc      = update.message.document
    password = ctx.user_data["enc_key"]
    ttl      = ctx.user_data.get("expiry_sec")
    label    = ctx.user_data.get("expiry_label", "∞")

    if not doc:
        await update.message.reply_text("❌ Fayl göndərilmədi. Yenidən cəhd et.")
        return S_ENC_FILE

    tg_file  = await doc.get_file()
    buf      = io.BytesIO()
    await tg_file.download_to_memory(buf)
    raw_data = buf.getvalue()

    try:
        encrypted = sym_encrypt(raw_data, password, ttl)
        fp        = fingerprint(encrypted)
        orig_name = doc.file_name or "file"
        out_name  = orig_name + ".enc"
        exp_str   = f"⏱ {label}" if label != "∞" else "♾ Müddətsiz"

        await update.message.reply_document(
            document=io.BytesIO(encrypted),
            filename=out_name,
            caption=(
                f"✅ Şifrələndi — `{orig_name}`\n"
                f"🆔 Barmaq izi: `{fp}`\n"
                f"{exp_str}\n"
                f"📦 Ölçü: {len(raw_data):,} → {len(encrypted):,} bayt"
            ),
            parse_mode="Markdown",
        )
    except Exception as e:
        logger.exception("File encrypt error")
        await update.message.reply_text(f"❌ Xəta: {e}")

    ctx.user_data.clear()
    await update.message.reply_text("Ana menyu:", reply_markup=kb_main())
    return ConversationHandler.END


async def got_dec_file(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    doc      = update.message.document
    password = ctx.user_data["dec_key"]

    if not doc:
        await update.message.reply_text("❌ Fayl göndərilmədi. Yenidən cəhd et.")
        return S_DEC_FILE

    tg_file  = await doc.get_file()
    buf      = io.BytesIO()
    await tg_file.download_to_memory(buf)
    enc_data = buf.getvalue()

    try:
        decrypted = sym_decrypt(enc_data, password)
        orig_name = doc.file_name or "file.enc"
        out_name  = orig_name.removesuffix(".enc") if orig_name.endswith(".enc") else "decrypted_" + orig_name

        await update.message.reply_document(
            document=io.BytesIO(decrypted),
            filename=out_name,
            caption=f"✅ Deşifrə uğurlu — `{out_name}`\n📦 {len(decrypted):,} bayt",
            parse_mode="Markdown",
        )
    except ValueError as e:
        await update.message.reply_text(f"❌ *Xəta:* `{e}`", parse_mode="Markdown")
    except Exception:
        logger.exception("File decrypt error")
        await update.message.reply_text("❌ Deşifrə alınmadı.")

    ctx.user_data.clear()
    await update.message.reply_text("Ana menyu:", reply_markup=kb_main())
    return ConversationHandler.END


# ══════════════════════════════════════════════════════════════════════════════
#  E2E FLOW
# ══════════════════════════════════════════════════════════════════════════════

async def e2e_got_pubkey(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    pub_b64 = update.message.text.strip()
    # basic length check (X25519 pub = 32 bytes → 43 chars base64url)
    try:
        raw = b64dec(pub_b64)
        if len(raw) != 32:
            raise ValueError
    except Exception:
        await update.message.reply_text("❌ Public key formatı yanlışdır. 43 simvol olmalıdır.")
        return E2E_SEND_PUBKEY

    ctx.user_data["e2e_pub"] = pub_b64
    await update.message.reply_text(
        "✏️ *Göndərəcəyin mətni yaz:*",
        parse_mode="Markdown", reply_markup=kb_cancel(),
    )
    return E2E_SEND_MSG


async def e2e_got_msg(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    pub_b64   = ctx.user_data["e2e_pub"]
    plaintext = update.message.text.strip().encode()
    try:
        bundle  = e2e_encrypt(plaintext, pub_b64)
        token   = b64enc(bundle)
        fp      = fingerprint(bundle)
        await update.message.reply_text(
            f"✅ *E2E Şifrələndi!*\n\n"
            f"📦 Bundle (alıcıya göndər):\n`{token}`\n\n"
            f"🆔 Barmaq izi: `{fp}`\n\n"
            f"_Yalnız alıcının private key-i ilə açıla bilər._",
            parse_mode="Markdown",
        )
    except Exception as e:
        await update.message.reply_text(f"❌ Xəta: {e}")

    ctx.user_data.clear()
    await update.message.reply_text("Ana menyu:", reply_markup=kb_main())
    return ConversationHandler.END


async def e2e_got_privkey(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    priv_b64 = update.message.text.strip()
    try:
        raw = b64dec(priv_b64)
        if len(raw) != 32:
            raise ValueError
    except Exception:
        await update.message.reply_text("❌ Private key formatı yanlışdır.")
        return E2E_RECV_PRIVKEY

    ctx.user_data["e2e_priv"] = priv_b64
    await update.message.reply_text(
        "📦 *E2E bundle-i (şifrəli tokeni) yapışdır:*",
        parse_mode="Markdown", reply_markup=kb_cancel(),
    )
    return E2E_RECV_BUNDLE


async def e2e_got_bundle(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    priv_b64 = ctx.user_data["e2e_priv"]
    token    = update.message.text.strip()
    try:
        bundle    = b64dec(token)
        plaintext = e2e_decrypt(bundle, priv_b64)
        await update.message.reply_text(
            f"✅ *E2E Deşifrə uğurlu!*\n\n📄 Mətn:\n`{plaintext.decode()}`",
            parse_mode="Markdown",
        )
    except ValueError as e:
        await update.message.reply_text(f"❌ *Xəta:* `{e}`", parse_mode="Markdown")
    except Exception:
        logger.exception("E2E decrypt error")
        await update.message.reply_text("❌ Deşifrə alınmadı.")

    ctx.user_data.clear()
    await update.message.reply_text("Ana menyu:", reply_markup=kb_main())
    return ConversationHandler.END


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main():
    if not BOT_TOKEN:
        raise RuntimeError("BOT_TOKEN mühit dəyişəni təyin edilməyib!")

    app = Application.builder().token(BOT_TOKEN).build()

    conv = ConversationHandler(
        entry_points=[
            CommandHandler("start",  cmd_start),
            CommandHandler("genkey", cmd_genkey),
            CallbackQueryHandler(button_handler),
        ],
        states={
            # symmetric encrypt
            S_ENC_KEY:    [MessageHandler(filters.TEXT & ~filters.COMMAND, got_enc_key),
                           CallbackQueryHandler(button_handler)],
            S_ENC_EXPIRY: [CallbackQueryHandler(button_handler)],
            S_ENC_TEXT:   [MessageHandler(filters.TEXT & ~filters.COMMAND, got_enc_text),
                           CallbackQueryHandler(button_handler)],
            S_ENC_FILE:   [MessageHandler(filters.Document.ALL, got_enc_file),
                           CallbackQueryHandler(button_handler)],
            # symmetric decrypt
            S_DEC_KEY:    [MessageHandler(filters.TEXT & ~filters.COMMAND, got_dec_key),
                           CallbackQueryHandler(button_handler)],
            S_DEC_TOKEN:  [MessageHandler(filters.TEXT & ~filters.COMMAND, got_dec_token),
                           CallbackQueryHandler(button_handler)],
            S_DEC_FILE:   [MessageHandler(filters.Document.ALL, got_dec_file),
                           CallbackQueryHandler(button_handler)],
            # E2E send
            E2E_SEND_PUBKEY: [MessageHandler(filters.TEXT & ~filters.COMMAND, e2e_got_pubkey),
                              CallbackQueryHandler(button_handler)],
            E2E_SEND_MSG:    [MessageHandler(filters.TEXT & ~filters.COMMAND, e2e_got_msg),
                              CallbackQueryHandler(button_handler)],
            # E2E recv
            E2E_RECV_PRIVKEY: [MessageHandler(filters.TEXT & ~filters.COMMAND, e2e_got_privkey),
                               CallbackQueryHandler(button_handler)],
            E2E_RECV_BUNDLE:  [MessageHandler(filters.TEXT & ~filters.COMMAND, e2e_got_bundle),
                               CallbackQueryHandler(button_handler)],
        },
        fallbacks=[
            CommandHandler("cancel", cmd_cancel),
            CommandHandler("start",  cmd_start),
        ],
        allow_reentry=True,
    )

    app.add_handler(conv)
    logger.info("CryptoBot v2 işə düşdü...")
    app.run_polling(drop_pending_updates=True)


if __name__ == "__main__":
    main()
