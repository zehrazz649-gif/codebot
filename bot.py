"""
CryptoBot v3 — Sadə E2E sistemi
  • Hər istifadəçinin sabit deep-link adresi var
  • Göndərən linki açır → mətn yazır → şifrəli gedir
  • Alan /inbox ilə oxuyur
  • AES-256-GCM + PBKDF2  |  Fayl şifrələmə  |  Token müddəti  |  /genkey
"""

import os, io, base64, hashlib, struct, logging, secrets, time, json
from datetime import datetime, timezone
from pathlib import Path

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application, CommandHandler, MessageHandler,
    CallbackQueryHandler, ConversationHandler, filters, ContextTypes,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(format="%(asctime)s %(levelname)s %(message)s", level=logging.INFO)
logger = logging.getLogger(__name__)

# ── Config ────────────────────────────────────────────────────────────────────
BOT_TOKEN  = os.environ.get("BOT_TOKEN", "")
BOT_USERNAME = os.environ.get("BOT_USERNAME", "your_bot")   # @username-siz, məsələn: mycryptobot
INBOX_FILE = Path("inbox.json")   # Railway-də /tmp/inbox.json da ola bilər

# ── States ────────────────────────────────────────────────────────────────────
(
    S_ENC_KEY, S_ENC_EXPIRY, S_ENC_TEXT, S_ENC_FILE,
    S_DEC_KEY, S_DEC_TOKEN, S_DEC_FILE,
    S_SEND_MSG, S_INBOX_KEY,
) = range(9)

VER = b"\x02"

EXPIRY_OPTIONS = {
    "exp_1h":  ("1 saat",   3600),
    "exp_6h":  ("6 saat",   21600),
    "exp_24h": ("24 saat",  86400),
    "exp_7d":  ("7 gün",    604800),
    "exp_inf": ("Sınırsız", None),
}

# ══════════════════════════════════════════════════════════════════════════════
#  INBOX  (sadə JSON fayl storage)
# ══════════════════════════════════════════════════════════════════════════════

def _load_inbox() -> dict:
    if INBOX_FILE.exists():
        try:
            return json.loads(INBOX_FILE.read_text())
        except Exception:
            pass
    return {}

def _save_inbox(data: dict):
    INBOX_FILE.write_text(json.dumps(data, ensure_ascii=False))

def inbox_add(recipient_id: int, sender_name: str, encrypted_b64: str, expiry_label: str):
    data = _load_inbox()
    key  = str(recipient_id)
    if key not in data:
        data[key] = []
    data[key].append({
        "from":    sender_name,
        "msg":     encrypted_b64,
        "expiry":  expiry_label,
        "time":    int(time.time()),
    })
    _save_inbox(data)

def inbox_get(recipient_id: int) -> list:
    data = _load_inbox()
    return data.get(str(recipient_id), [])

def inbox_clear(recipient_id: int):
    data = _load_inbox()
    data[str(recipient_id)] = []
    _save_inbox(data)

# ══════════════════════════════════════════════════════════════════════════════
#  CRYPTO CORE
# ══════════════════════════════════════════════════════════════════════════════

def _pbkdf2(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(hashes.SHA256(), 32, salt, 600_000, default_backend())
    return kdf.derive(password.encode())

def sym_encrypt(data: bytes, password: str, ttl_seconds: int | None) -> bytes:
    salt    = secrets.token_bytes(32)
    nonce   = secrets.token_bytes(12)
    key     = _pbkdf2(password, salt)
    expires = int(time.time()) + ttl_seconds if ttl_seconds else 0
    aad     = struct.pack(">q", expires)
    ct      = AESGCM(key).encrypt(nonce, data, aad)
    return VER + salt + nonce + aad + ct

def sym_decrypt(payload: bytes, password: str) -> bytes:
    if len(payload) < 1 + 32 + 12 + 8 + 16:
        raise ValueError("Token çox qısadır.")
    if payload[0:1] != VER:
        raise ValueError("Versiya uyğun deyil.")
    salt    = payload[1:33]
    nonce   = payload[33:45]
    aad     = payload[45:53]
    ct      = payload[53:]
    expires = struct.unpack(">q", aad)[0]
    if expires and time.time() > expires:
        ts = datetime.fromtimestamp(expires, tz=timezone.utc).strftime("%d.%m.%Y %H:%M UTC")
        raise ValueError(f"Tokenin müddəti bitib ({ts}).")
    key = _pbkdf2(password, salt)
    try:
        return AESGCM(key).decrypt(nonce, ct, aad)
    except Exception:
        raise ValueError("Şifrə yanlışdır və ya məlumat dəyişdirilib.")

def b64enc(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode()

def b64dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "==")

def fp(b: bytes) -> str:
    return hashlib.sha256(b).digest()[:5].hex().upper()

def genkey(n=32) -> str:
    return secrets.token_hex(n)

# ══════════════════════════════════════════════════════════════════════════════
#  KEYBOARDS
# ══════════════════════════════════════════════════════════════════════════════

def kb_main():
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("🔒 Şifrələ",    callback_data="sym_enc"),
            InlineKeyboardButton("🔓 Deşifrələ",  callback_data="sym_dec"),
        ],
        [
            InlineKeyboardButton("📁 Fayl şifrələ",   callback_data="file_enc"),
            InlineKeyboardButton("📂 Fayl deşifrələ", callback_data="file_dec"),
        ],
        [
            InlineKeyboardButton("📬 Gələn qutu",      callback_data="inbox"),
            InlineKeyboardButton("🔗 Mənim linkım",    callback_data="mylink"),
        ],
        [
            InlineKeyboardButton("🎲 Güclü açar yarat", callback_data="genkey"),
        ],
    ])

def kb_cancel():
    return InlineKeyboardMarkup([[InlineKeyboardButton("❌ Ləğv et", callback_data="cancel")]])

def kb_expiry():
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("1 saat",    callback_data="exp_1h"),
            InlineKeyboardButton("6 saat",    callback_data="exp_6h"),
            InlineKeyboardButton("24 saat",   callback_data="exp_24h"),
        ],
        [
            InlineKeyboardButton("7 gün",      callback_data="exp_7d"),
            InlineKeyboardButton("♾ Sınırsız", callback_data="exp_inf"),
        ],
        [InlineKeyboardButton("❌ Ləğv et", callback_data="cancel")],
    ])

def kb_back():
    return InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ Geri", callback_data="back")]])

def kb_inbox_actions():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("🗑 Hamısını sil", callback_data="inbox_clear")],
        [InlineKeyboardButton("⬅️ Geri",         callback_data="back")],
    ])

# ══════════════════════════════════════════════════════════════════════════════
#  /start — həm normal həm də deep-link (t.me/bot?start=send_USERID)
# ══════════════════════════════════════════════════════════════════════════════

async def cmd_start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    ctx.user_data.clear()
    args = ctx.args  # deep-link parametri

    # ── Deep-link: kimsə "Sənə şifrəli mesaj göndər" linkindən gəlib ──
    if args and args[0].startswith("send_"):
        try:
            recipient_id = int(args[0][5:])
        except ValueError:
            recipient_id = None

        if recipient_id:
            try:
                chat = await ctx.bot.get_chat(recipient_id)
                name = chat.full_name or f"İstifadəçi {recipient_id}"
            except Exception:
                name = f"İstifadəçi #{recipient_id}"

            ctx.user_data["send_to_id"]   = recipient_id
            ctx.user_data["send_to_name"] = name
            ctx.user_data["mode"]         = "send_msg"

            await update.message.reply_text(
                f"✉️ *{name}* üçün şifrəli mesaj yazırsın.\n\n"
                f"Əvvəlcə bir *şifrə açarı* daxil et — "
                f"bu açarı alıcıya ayrıca (telefon, şəxsən) bildir:\n\n"
                f"_(Açar nə qədər güclü olsa, şifrələmə o qədər etibarlıdır)_",
                parse_mode="Markdown",
                reply_markup=InlineKeyboardMarkup([
                    [InlineKeyboardButton("🎲 Açar yarat", callback_data="genkey_for_send")],
                    [InlineKeyboardButton("❌ Ləğv et",    callback_data="cancel")],
                ]),
            )
            return S_SEND_MSG

    # ── Normal start ──────────────────────────────────────────────────────────
    await update.message.reply_text(
        "🔐 *CryptoBot* — Güclü Şifrələmə\n\n"
        "• Mətn və fayl şifrələ/deşifrələ\n"
        "• 🔗 *Linkinlə* başqaları sənə şifrəli mesaj göndərsin\n"
        "• 📬 Mesajları *Gələn qutu*-da oxu\n"
        "• 🎲 Güclü açar yarat\n\n"
        "Nə etmək istəyirsən?",
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

    # ── Expiry seçimi ─────────────────────────────────────────────────────────
    if d in EXPIRY_OPTIONS:
        label, ttl = EXPIRY_OPTIONS[d]
        ctx.user_data["expiry_label"] = label
        ctx.user_data["expiry_sec"]   = ttl
        mode = ctx.user_data.get("mode", "")

        if "file" in mode:
            await q.edit_message_text(
                f"📁 *Müddət: {label}*\n\nFaylı göndər:",
                parse_mode="Markdown", reply_markup=kb_cancel(),
            )
            return S_ENC_FILE
        elif mode == "send_msg_text":
            await q.edit_message_text(
                f"✉️ *Müddət: {label}*\n\nMətnini yaz:",
                parse_mode="Markdown", reply_markup=kb_cancel(),
            )
            ctx.user_data["mode"] = "send_msg_final"
            return S_SEND_MSG
        else:
            await q.edit_message_text(
                f"⏱ *Müddət: {label}*\n\nŞifrələnəcək mətni yazın:",
                parse_mode="Markdown", reply_markup=kb_cancel(),
            )
            return S_ENC_TEXT

    # ── Genkey (send üçün) ────────────────────────────────────────────────────
    if d == "genkey_for_send":
        k = genkey(16)
        await q.edit_message_text(
            f"🎲 *Təklif olunan açar:*\n`{k}`\n\n"
            f"_Bu açarı alıcıya ayrıca bildir, sonra aşağıya yaz:_",
            parse_mode="Markdown",
            reply_markup=kb_cancel(),
        )
        return S_SEND_MSG

    # ── Şifrələmə ─────────────────────────────────────────────────────────────
    if d == "sym_enc":
        ctx.user_data.clear(); ctx.user_data["mode"] = "sym_enc"
        await q.edit_message_text(
            "🔑 *Şifrə açarını daxil et:*\n_(istənilən söz və ya cümlə)_",
            parse_mode="Markdown", reply_markup=kb_cancel(),
        )
        return S_ENC_KEY

    if d == "sym_dec":
        ctx.user_data.clear(); ctx.user_data["mode"] = "sym_dec"
        await q.edit_message_text(
            "🔑 *Şifrə açarını daxil et:*",
            parse_mode="Markdown", reply_markup=kb_cancel(),
        )
        return S_DEC_KEY

    if d == "file_enc":
        ctx.user_data.clear(); ctx.user_data["mode"] = "file_enc"
        await q.edit_message_text(
            "🔑 *Fayl şifrələmə — açar daxil et:*",
            parse_mode="Markdown", reply_markup=kb_cancel(),
        )
        return S_ENC_KEY

    if d == "file_dec":
        ctx.user_data.clear(); ctx.user_data["mode"] = "file_dec"
        await q.edit_message_text(
            "🔑 *Fayl deşifrələmə — açar daxil et:*",
            parse_mode="Markdown", reply_markup=kb_cancel(),
        )
        return S_DEC_KEY

    # ── Açar generatoru ───────────────────────────────────────────────────────
    if d == "genkey":
        k16 = genkey(16); k32 = genkey(32)
        await q.edit_message_text(
            "🎲 *Güclü açar generatoru*\n\n"
            "128-bit:\n`" + k16 + "`\n\n"
            "256-bit _(tövsiyə)_:\n`" + k32 + "`\n\n"
            "⚠️ Açarı özəl saxla — itirsən bərpa mümkünsüz!",
            parse_mode="Markdown", reply_markup=kb_back(),
        )
        return ConversationHandler.END

    # ── Mənim linkım ──────────────────────────────────────────────────────────
    if d == "mylink":
        uid  = q.from_user.id
        link = f"https://t.me/{BOT_USERNAME}?start=send_{uid}"
        await q.edit_message_text(
            "🔗 *Sənin şəxsi şifrəli mesaj linkin:*\n\n"
            f"`{link}`\n\n"
            "Bu linki istənilən yerə paylaş.\n"
            "Kimsə linki açsın → açar seçsin → mətn yazsın → sənin *Gələn qutu*na düşür.\n\n"
            "📬 Mesajları oxumaq üçün → *Gələn qutu* düyməsinə bas.",
            parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("📬 Gələn qutu", callback_data="inbox")],
                [InlineKeyboardButton("⬅️ Geri",       callback_data="back")],
            ]),
        )
        return ConversationHandler.END

    # ── Gələn qutu ────────────────────────────────────────────────────────────
    if d == "inbox":
        uid      = q.from_user.id
        messages = inbox_get(uid)
        if not messages:
            await q.edit_message_text(
                "📬 *Gələn qutu boşdur.*\n\n"
                f"Linkini paylaş: `https://t.me/{BOT_USERNAME}?start=send_{uid}`",
                parse_mode="Markdown", reply_markup=kb_back(),
            )
            return ConversationHandler.END

        await q.edit_message_text(
            f"📬 *Gələn qutu* — {len(messages)} mesaj\n\n"
            "Mesajları oxumaq üçün *şifrə açarını* daxil et\n"
            "_(hər mesajın açarı göndərən tərəfindən bildirilmişdir)_",
            parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🔓 Oxu",          callback_data="inbox_read")],
                [InlineKeyboardButton("🗑 Hamısını sil", callback_data="inbox_clear")],
                [InlineKeyboardButton("⬅️ Geri",         callback_data="back")],
            ]),
        )
        return ConversationHandler.END

    if d == "inbox_read":
        uid      = q.from_user.id
        messages = inbox_get(uid)
        if not messages:
            await q.edit_message_text("📭 Qutu boşdur.", reply_markup=kb_back())
            return ConversationHandler.END
        ctx.user_data["inbox_msgs"] = messages
        ctx.user_data["inbox_uid"]  = uid
        ctx.user_data["mode"]       = "inbox_read"
        await q.edit_message_text(
            f"📬 {len(messages)} mesaj var.\n\n🔑 Şifrə açarını daxil et:",
            parse_mode="Markdown", reply_markup=kb_cancel(),
        )
        return S_INBOX_KEY

    if d == "inbox_clear":
        uid = q.from_user.id
        inbox_clear(uid)
        await q.edit_message_text("🗑 Gələn qutu təmizləndi.", reply_markup=kb_back())
        return ConversationHandler.END

    # ── Cancel / Back ─────────────────────────────────────────────────────────
    if d in ("cancel", "back"):
        ctx.user_data.clear()
        await q.edit_message_text("Ana menyu:", reply_markup=kb_main())
        return ConversationHandler.END

# ══════════════════════════════════════════════════════════════════════════════
#  SEND MSG FLOW  (deep-link gələn)
# ══════════════════════════════════════════════════════════════════════════════

async def send_msg_step(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    text = update.message.text.strip()
    mode = ctx.user_data.get("mode", "")

    # İlk addım: açar daxil edilir
    if "key" not in ctx.user_data.get("send_key", "x"):
        if "send_key" not in ctx.user_data:
            ctx.user_data["send_key"] = text
            ctx.user_data["mode"]     = "send_msg_text"
            await update.message.reply_text(
                f"✅ Açar qeyd edildi.\n\n"
                f"⏱ Token neçə müddət etibarlı olsun?",
                reply_markup=kb_expiry(),
            )
            return S_SEND_MSG

    # Son addım: mətn daxil edilir (expiry seçildikdən sonra)
    if mode == "send_msg_final":
        password     = ctx.user_data["send_key"]
        recipient_id = ctx.user_data["send_to_id"]
        sender_name  = update.effective_user.full_name or "Anonim"
        ttl          = ctx.user_data.get("expiry_sec")
        label        = ctx.user_data.get("expiry_label", "Sınırsız")

        try:
            raw   = sym_encrypt(text.encode(), password, ttl)
            token = b64enc(raw)
            inbox_add(recipient_id, sender_name, token, label)

            # Alıcıya bildiriş göndər
            try:
                await ctx.bot.send_message(
                    chat_id=recipient_id,
                    text=f"📬 *Yeni şifrəli mesaj!*\n\nGöndərən: *{sender_name}*\nMüddət: {label}\n\n_Oxumaq üçün /inbox_",
                    parse_mode="Markdown",
                )
            except Exception:
                pass  # Alıcı bota start etməyibsə

            await update.message.reply_text(
                f"✅ *Mesaj göndərildi!*\n\n"
                f"📬 Alıcı bildiriş alacaq.\n"
                f"⏱ Müddət: {label}",
                parse_mode="Markdown",
            )
        except Exception as e:
            logger.exception("send_msg error")
            await update.message.reply_text(f"❌ Xəta: {e}")

        ctx.user_data.clear()
        return ConversationHandler.END

    return S_SEND_MSG

# ══════════════════════════════════════════════════════════════════════════════
#  INBOX READ FLOW
# ══════════════════════════════════════════════════════════════════════════════

async def inbox_key_step(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    password = update.message.text.strip()
    messages = ctx.user_data.get("inbox_msgs", [])
    uid      = ctx.user_data.get("inbox_uid")

    if not messages:
        await update.message.reply_text("📭 Qutu boşdur.", reply_markup=kb_main())
        ctx.user_data.clear()
        return ConversationHandler.END

    success = 0
    fail    = 0
    lines   = []

    for i, item in enumerate(messages, 1):
        try:
            raw  = b64dec(item["msg"])
            text = sym_decrypt(raw, password).decode()
            ts   = datetime.fromtimestamp(item["time"]).strftime("%d.%m %H:%M")
            lines.append(f"*{i}.* 👤 {item['from']} · {ts}\n`{text}`")
            success += 1
        except ValueError as e:
            lines.append(f"*{i}.* ❌ `{e}`")
            fail += 1

    summary = f"✅ {success} oxundu" + (f"  |  ❌ {fail} açılmadı" if fail else "")
    full    = summary + "\n\n" + "\n\n".join(lines)

    # Telegram 4096 limit
    if len(full) <= 4000:
        await update.message.reply_text(full, parse_mode="Markdown")
    else:
        await update.message.reply_text(summary, parse_mode="Markdown")
        for chunk in lines:
            await update.message.reply_text(chunk, parse_mode="Markdown")

    await update.message.reply_text(
        "Silmək istəyirsən?",
        reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("🗑 Hamısını sil", callback_data="inbox_clear")],
            [InlineKeyboardButton("⬅️ Ana menyu",   callback_data="back")],
        ]),
    )
    ctx.user_data.clear()
    return ConversationHandler.END

# ══════════════════════════════════════════════════════════════════════════════
#  SYMMETRIC ENCRYPT FLOW
# ══════════════════════════════════════════════════════════════════════════════

async def got_enc_key(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    ctx.user_data["enc_key"] = update.message.text.strip()
    await update.message.reply_text("⏱ Token neçə müddət etibarlı olsun?", reply_markup=kb_expiry())
    return S_ENC_EXPIRY

async def got_enc_text(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    pw    = ctx.user_data["enc_key"]
    ttl   = ctx.user_data.get("expiry_sec")
    label = ctx.user_data.get("expiry_label", "Sınırsız")
    try:
        raw   = sym_encrypt(update.message.text.strip().encode(), pw, ttl)
        token = b64enc(raw)
        fprint = fp(raw)
        msg = (
            f"✅ *Şifrələndi!*\n\n"
            f"🔏 Token:\n`{token}`\n\n"
            f"🆔 `{fprint}`  ·  ⏱ {label}"
        )
        if len(msg) <= 4000:
            await update.message.reply_text(msg, parse_mode="Markdown")
        else:
            await update.message.reply_text(f"✅ `{fprint}` · {label}", parse_mode="Markdown")
            for i in range(0, len(token), 4000):
                await update.message.reply_text(f"`{token[i:i+4000]}`", parse_mode="Markdown")
    except Exception as e:
        await update.message.reply_text(f"❌ {e}")
    ctx.user_data.clear()
    await update.message.reply_text("Ana menyu:", reply_markup=kb_main())
    return ConversationHandler.END

# ══════════════════════════════════════════════════════════════════════════════
#  SYMMETRIC DECRYPT FLOW
# ══════════════════════════════════════════════════════════════════════════════

async def got_dec_key(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    ctx.user_data["dec_key"] = update.message.text.strip()
    if ctx.user_data.get("mode") == "file_dec":
        await update.message.reply_text("📂 Şifrəli faylı göndər:", reply_markup=kb_cancel())
        return S_DEC_FILE
    await update.message.reply_text("📋 Şifrəli tokeni yapışdır:", reply_markup=kb_cancel())
    return S_DEC_TOKEN

async def got_dec_token(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    pw = ctx.user_data["dec_key"]
    try:
        raw  = b64dec(update.message.text.strip())
        text = sym_decrypt(raw, pw).decode()
        await update.message.reply_text(f"✅ *Deşifrə uğurlu!*\n\n`{text}`", parse_mode="Markdown")
    except ValueError as e:
        await update.message.reply_text(f"❌ `{e}`", parse_mode="Markdown")
    except Exception:
        await update.message.reply_text("❌ Deşifrə alınmadı.")
    ctx.user_data.clear()
    await update.message.reply_text("Ana menyu:", reply_markup=kb_main())
    return ConversationHandler.END

# ══════════════════════════════════════════════════════════════════════════════
#  FILE FLOWS
# ══════════════════════════════════════════════════════════════════════════════

async def got_enc_file(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    doc = update.message.document
    if not doc:
        await update.message.reply_text("❌ Fayl göndərilmədi.")
        return S_ENC_FILE
    pw    = ctx.user_data["enc_key"]
    ttl   = ctx.user_data.get("expiry_sec")
    label = ctx.user_data.get("expiry_label", "Sınırsız")
    buf   = io.BytesIO()
    await (await doc.get_file()).download_to_memory(buf)
    raw   = buf.getvalue()
    try:
        enc  = sym_encrypt(raw, pw, ttl)
        name = (doc.file_name or "file") + ".enc"
        await update.message.reply_document(
            io.BytesIO(enc), filename=name,
            caption=f"✅ `{doc.file_name}` şifrələndi\n🆔 `{fp(enc)}`  ·  ⏱ {label}",
            parse_mode="Markdown",
        )
    except Exception as e:
        await update.message.reply_text(f"❌ {e}")
    ctx.user_data.clear()
    await update.message.reply_text("Ana menyu:", reply_markup=kb_main())
    return ConversationHandler.END

async def got_dec_file(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    doc = update.message.document
    if not doc:
        await update.message.reply_text("❌ Fayl göndərilmədi.")
        return S_DEC_FILE
    pw  = ctx.user_data["dec_key"]
    buf = io.BytesIO()
    await (await doc.get_file()).download_to_memory(buf)
    try:
        dec  = sym_decrypt(buf.getvalue(), pw)
        name = doc.file_name.removesuffix(".enc") if doc.file_name and doc.file_name.endswith(".enc") else "decrypted_" + (doc.file_name or "file")
        await update.message.reply_document(io.BytesIO(dec), filename=name, caption=f"✅ Deşifrə uğurlu — `{name}`", parse_mode="Markdown")
    except ValueError as e:
        await update.message.reply_text(f"❌ `{e}`", parse_mode="Markdown")
    except Exception:
        await update.message.reply_text("❌ Deşifrə alınmadı.")
    ctx.user_data.clear()
    await update.message.reply_text("Ana menyu:", reply_markup=kb_main())
    return ConversationHandler.END

# ══════════════════════════════════════════════════════════════════════════════
#  COMMANDS
# ══════════════════════════════════════════════════════════════════════════════

async def cmd_genkey(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "🎲 *Güclü açar generatoru*\n\n"
        "128-bit:\n`" + genkey(16) + "`\n\n"
        "256-bit _(tövsiyə)_:\n`" + genkey(32) + "`",
        parse_mode="Markdown",
    )

async def cmd_mylink(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    uid  = update.effective_user.id
    link = f"https://t.me/{BOT_USERNAME}?start=send_{uid}"
    await update.message.reply_text(
        f"🔗 *Sənin linkin:*\n`{link}`\n\nPaylaş — kimsə mesaj göndərsin.",
        parse_mode="Markdown",
    )

async def cmd_inbox(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    uid  = update.effective_user.id
    msgs = inbox_get(uid)
    if not msgs:
        await update.message.reply_text("📭 Gələn qutu boşdur.")
        return
    ctx.user_data["inbox_msgs"] = msgs
    ctx.user_data["inbox_uid"]  = uid
    ctx.user_data["mode"]       = "inbox_read"
    await update.message.reply_text(
        f"📬 *{len(msgs)} şifrəli mesaj var.*\n\n🔑 Açarı daxil et:",
        parse_mode="Markdown", reply_markup=kb_cancel(),
    )
    return S_INBOX_KEY

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
            CommandHandler("genkey", cmd_genkey),
            CommandHandler("mylink", cmd_mylink),
            CommandHandler("inbox",  cmd_inbox),
            CallbackQueryHandler(button_handler),
        ],
        states={
            S_ENC_KEY:    [MessageHandler(filters.TEXT & ~filters.COMMAND, got_enc_key),   CallbackQueryHandler(button_handler)],
            S_ENC_EXPIRY: [CallbackQueryHandler(button_handler)],
            S_ENC_TEXT:   [MessageHandler(filters.TEXT & ~filters.COMMAND, got_enc_text),  CallbackQueryHandler(button_handler)],
            S_ENC_FILE:   [MessageHandler(filters.Document.ALL, got_enc_file),             CallbackQueryHandler(button_handler)],
            S_DEC_KEY:    [MessageHandler(filters.TEXT & ~filters.COMMAND, got_dec_key),   CallbackQueryHandler(button_handler)],
            S_DEC_TOKEN:  [MessageHandler(filters.TEXT & ~filters.COMMAND, got_dec_token), CallbackQueryHandler(button_handler)],
            S_DEC_FILE:   [MessageHandler(filters.Document.ALL, got_dec_file),             CallbackQueryHandler(button_handler)],
            S_SEND_MSG:   [MessageHandler(filters.TEXT & ~filters.COMMAND, send_msg_step), CallbackQueryHandler(button_handler)],
            S_INBOX_KEY:  [MessageHandler(filters.TEXT & ~filters.COMMAND, inbox_key_step),CallbackQueryHandler(button_handler)],
        },
        fallbacks=[
            CommandHandler("cancel", cmd_cancel),
            CommandHandler("start",  cmd_start),
        ],
        allow_reentry=True,
    )

    app.add_handler(conv)
    logger.info("CryptoBot v3 işə düşdü ✅")
    app.run_polling(drop_pending_updates=True)


if __name__ == "__main__":
    main()
