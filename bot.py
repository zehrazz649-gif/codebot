"""
CryptoBot v4 — Genişləndirilmiş E2E sistemi
  • AES-256-GCM + PBKDF2  |  Fayl şifrələmə  |  Token müddəti  |  /genkey
  ── YENİ XÜSUSİYYƏTLƏR ──
  • Qrup Broadcast    — adminlər bütün abunəçilərə şifrəli mesaj göndərə bilər
  • Rəqəmsal İmza     — HMAC-SHA256 ilə imzalanmış tokenlər
  • Brute-force Qoruması — ardıcıl uğursuz cəhdlər → müvəqqəti blok
  • Inline Mode       — @bot token → birbaşa deşifrə
  • Şəkildə Gizlətmə — LSB steganography (şifrəli mətn PNG-yə gizlədilir)
"""

import os, io, base64, hashlib, hmac, struct, logging, secrets, time, json
from datetime import datetime, timezone
from pathlib import Path
from collections import defaultdict

from PIL import Image
import numpy as np

from telegram import (
    Update, InlineKeyboardButton, InlineKeyboardMarkup,
    InlineQueryResultArticle, InputTextMessageContent,
)
from telegram.ext import (
    Application, CommandHandler, MessageHandler,
    CallbackQueryHandler, ConversationHandler,
    InlineQueryHandler, filters, ContextTypes,
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
INBOX_FILE   = Path("inbox.json")
SUBS_FILE    = Path("subscribers.json")   # broadcast abunəçiləri
# Admin ID-ləri (vergüllə ayrılmış: "123456,789012")
ADMIN_IDS    = set(
    int(x) for x in os.environ.get("ADMIN_IDS", "").split(",") if x.strip().isdigit()
)

# ── Brute-force qoruması ──────────────────────────────────────────────────────
BF_MAX_ATTEMPTS  = 5          # bu qədər uğursuz cəhddən sonra blok
BF_BLOCK_SECONDS = 300        # 5 dəqiqə blok
_bf_attempts: dict[int, int]   = defaultdict(int)   # uid → cəhd sayı
_bf_blocked:  dict[int, float] = {}                  # uid → blok bitmə vaxtı

# ── States ────────────────────────────────────────────────────────────────────
(
    S_ENC_KEY, S_ENC_EXPIRY, S_ENC_TEXT, S_ENC_FILE,
    S_DEC_KEY, S_DEC_TOKEN, S_DEC_FILE,
    S_SEND_MSG, S_INBOX_KEY,
    S_SIGN_KEY, S_SIGN_TEXT,
    S_VERIFY_KEY, S_VERIFY_TOKEN,
    S_STEG_HIDE_KEY, S_STEG_HIDE_TEXT, S_STEG_HIDE_IMG,
    S_STEG_REVEAL_KEY, S_STEG_REVEAL_IMG,
    S_BROADCAST_KEY, S_BROADCAST_TEXT,
) = range(20)

VER      = b"\x02"
VER_SIGN = b"\x03"   # imzalı token versiyası

EXPIRY_OPTIONS = {
    "exp_1h":  ("1 saat",   3600),
    "exp_6h":  ("6 saat",   21600),
    "exp_24h": ("24 saat",  86400),
    "exp_7d":  ("7 gün",    604800),
    "exp_inf": ("Sınırsız", None),
}

# ══════════════════════════════════════════════════════════════════════════════
#  BRUTE-FORCE QORUMASI
# ══════════════════════════════════════════════════════════════════════════════

def bf_is_blocked(uid: int) -> float | None:
    """Blok varsa, neçə saniyə qaldığını qaytarır. Yoxdursa None."""
    if uid in _bf_blocked:
        remaining = _bf_blocked[uid] - time.time()
        if remaining > 0:
            return remaining
        else:
            del _bf_blocked[uid]
            _bf_attempts[uid] = 0
    return None

def bf_record_fail(uid: int):
    _bf_attempts[uid] += 1
    if _bf_attempts[uid] >= BF_MAX_ATTEMPTS:
        _bf_blocked[uid] = time.time() + BF_BLOCK_SECONDS
        _bf_attempts[uid] = 0
        return True   # bloklandı
    return False

def bf_record_success(uid: int):
    _bf_attempts[uid] = 0

def bf_remaining_attempts(uid: int) -> int:
    return max(0, BF_MAX_ATTEMPTS - _bf_attempts.get(uid, 0))

# ══════════════════════════════════════════════════════════════════════════════
#  SUBSCRIBERS  (broadcast üçün)
# ══════════════════════════════════════════════════════════════════════════════

def subs_load() -> list[int]:
    if SUBS_FILE.exists():
        try:
            return json.loads(SUBS_FILE.read_text())
        except Exception:
            pass
    return []

def subs_save(data: list[int]):
    SUBS_FILE.write_text(json.dumps(list(set(data))))

def subs_add(uid: int):
    lst = subs_load()
    if uid not in lst:
        lst.append(uid)
        subs_save(lst)

def subs_remove(uid: int):
    lst = subs_load()
    subs_save([x for x in lst if x != uid])

# ══════════════════════════════════════════════════════════════════════════════
#  INBOX
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
        "from":   sender_name,
        "msg":    encrypted_b64,
        "expiry": expiry_label,
        "time":   int(time.time()),
    })
    _save_inbox(data)

def inbox_get(recipient_id: int) -> list:
    return _load_inbox().get(str(recipient_id), [])

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

# ── Rəqəmsal İmza (HMAC-SHA256) ───────────────────────────────────────────────

def sign_encrypt(data: bytes, password: str, ttl_seconds: int | None) -> bytes:
    """Şifrələ + HMAC imzası əlavə et."""
    enc      = sym_encrypt(data, password, ttl_seconds)
    mac_key  = hashlib.sha256(b"sign:" + password.encode()).digest()
    sig      = hmac.new(mac_key, enc, hashlib.sha256).digest()
    return VER_SIGN + sig + enc   # version(1) + hmac(32) + encrypted_payload

def sign_decrypt(payload: bytes, password: str) -> tuple[bytes, bool]:
    """Deşifrə et. (plaintext, imza_düzgündür) qaytarır."""
    if payload[0:1] != VER_SIGN:
        raise ValueError("İmzalı token deyil.")
    if len(payload) < 1 + 32 + 1:
        raise ValueError("Token çox qısadır.")
    sig_recv = payload[1:33]
    enc      = payload[33:]
    mac_key  = hashlib.sha256(b"sign:" + password.encode()).digest()
    sig_calc = hmac.new(mac_key, enc, hashlib.sha256).digest()
    valid    = hmac.compare_digest(sig_recv, sig_calc)
    plain    = sym_decrypt(enc, password)
    return plain, valid

# ── Steganography (LSB) ────────────────────────────────────────────────────────

def steg_hide(img_bytes: bytes, secret_bytes: bytes) -> bytes:
    """Şifrəli mətn-i PNG şəkilin LSB-lərinə gizlət."""
    img  = Image.open(io.BytesIO(img_bytes)).convert("RGB")
    data = np.array(img, dtype=np.uint8)
    flat = data.flatten()

    # Uzunluq prefix (4 bayt big-endian) + məzmun
    payload = struct.pack(">I", len(secret_bytes)) + secret_bytes
    bits    = np.unpackbits(np.frombuffer(payload, dtype=np.uint8))

    if len(bits) > len(flat):
        raise ValueError(f"Şəkil çox kiçikdir. Lazım: {len(bits)//8} bayt, var: {len(flat)//8} bayt.")

    flat[:len(bits)] = (flat[:len(bits)] & 0xFE) | bits
    out_arr = flat.reshape(data.shape).astype(np.uint8)
    out_img = Image.fromarray(out_arr, "RGB")
    buf     = io.BytesIO()
    out_img.save(buf, format="PNG")
    return buf.getvalue()

def steg_reveal(img_bytes: bytes) -> bytes:
    """Şəkilin LSB-lərindən gizli məzmunu çıxart."""
    img  = Image.open(io.BytesIO(img_bytes)).convert("RGB")
    flat = np.array(img, dtype=np.uint8).flatten()
    # Əvvəlcə uzunluq oxu (4 bayt = 32 bit)
    len_bits = flat[:32] & 1
    length   = int(np.packbits(len_bits).tobytes().hex(), 16)
    if length == 0 or length > len(flat) // 8:
        raise ValueError("Şəkildə gizli məlumat tapılmadı.")
    total_bits = 32 + length * 8
    all_bits   = flat[:total_bits] & 1
    payload    = np.packbits(all_bits)[4:4 + length].tobytes()
    return payload

# ── Köməkçi ───────────────────────────────────────────────────────────────────

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

def kb_main(is_admin=False):
    rows = [
        [
            InlineKeyboardButton("🔒 Şifrələ",    callback_data="sym_enc"),
            InlineKeyboardButton("🔓 Deşifrələ",  callback_data="sym_dec"),
        ],
        [
            InlineKeyboardButton("📁 Fayl şifrələ",   callback_data="file_enc"),
            InlineKeyboardButton("📂 Fayl deşifrələ", callback_data="file_dec"),
        ],
        [
            InlineKeyboardButton("✍️ İmzala",     callback_data="sign_enc"),
            InlineKeyboardButton("🔍 İmzanı yoxla", callback_data="sign_dec"),
        ],
        [
            InlineKeyboardButton("🖼 Şəklə gizlət",  callback_data="steg_hide"),
            InlineKeyboardButton("🔎 Şəkildən çıxart", callback_data="steg_reveal"),
        ],
        [
            InlineKeyboardButton("📬 Gələn qutu",      callback_data="inbox"),
            InlineKeyboardButton("🔗 Mənim linkım",    callback_data="mylink"),
        ],
        [
            InlineKeyboardButton("🎲 Güclü açar yarat", callback_data="genkey"),
        ],
    ]
    if is_admin:
        rows.append([InlineKeyboardButton("📢 Broadcast", callback_data="broadcast")])
    return InlineKeyboardMarkup(rows)

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
#  /start
# ══════════════════════════════════════════════════════════════════════════════

async def cmd_start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    ctx.user_data.clear()
    uid  = update.effective_user.id
    args = ctx.args
    subs_add(uid)   # abunə siyahısına əlavə et

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
                f"bu açarı alıcıya ayrıca bildir:\n\n"
                f"_(Açar nə qədər güclü olsa, şifrələmə o qədər etibarlıdır)_",
                parse_mode="Markdown",
                reply_markup=InlineKeyboardMarkup([
                    [InlineKeyboardButton("🎲 Açar yarat", callback_data="genkey_for_send")],
                    [InlineKeyboardButton("❌ Ləğv et",    callback_data="cancel")],
                ]),
            )
            return S_SEND_MSG

    is_admin = uid in ADMIN_IDS
    await update.message.reply_text(
        "🔐 *CryptoBot v4* — Güclü Şifrələmə\n\n"
        "• Mətn və fayl şifrələ/deşifrələ\n"
        "• ✍️ *Rəqəmsal imza* — HMAC-SHA256\n"
        "• 🖼 *Steganography* — şəklə gizlət\n"
        "• 🔗 *Linkinlə* başqaları sənə mesaj göndərsin\n"
        "• 📬 Mesajları *Gələn qutu*-da oxu\n"
        "• 🎲 Güclü açar yarat\n"
        + ("• 📢 *Broadcast* — bütün abunəçilərə göndər\n" if is_admin else "") +
        "\n_Inline:_ `@" + BOT_USERNAME + " <token>` yazaraq deşifrə et",
        parse_mode="Markdown",
        reply_markup=kb_main(is_admin),
    )
    return ConversationHandler.END

# ══════════════════════════════════════════════════════════════════════════════
#  INLINE MODE  — @bot <token> <açar>
# ══════════════════════════════════════════════════════════════════════════════

async def inline_query(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    query = update.inline_query.query.strip()
    uid   = update.inline_query.from_user.id

    # Blok yoxlaması
    remaining = bf_is_blocked(uid)
    if remaining:
        results = [InlineQueryResultArticle(
            id="blocked",
            title="🚫 Bloklandın",
            input_message_content=InputTextMessageContent(
                f"🚫 Çox uğursuz cəhd. {int(remaining)} saniyə gözlə."
            ),
        )]
        await update.inline_query.answer(results, cache_time=0)
        return

    if not query:
        results = [InlineQueryResultArticle(
            id="help",
            title="💡 Necə istifadə etmək olar",
            description="@bot <token> <açar>  →  deşifrə",
            input_message_content=InputTextMessageContent(
                "Inline istifadəsi:\n`@" + BOT_USERNAME + " <token> <açar>`\n\nToken və açarı boşluqla ayır.",
                parse_mode="Markdown",
            ),
        )]
        await update.inline_query.answer(results, cache_time=0)
        return

    parts = query.split(None, 1)
    if len(parts) < 2:
        results = [InlineQueryResultArticle(
            id="nokey",
            title="🔑 Açar lazımdır",
            description="<token> <açar> formatında yaz",
            input_message_content=InputTextMessageContent("Açar daxil et: `@bot <token> <açar>`", parse_mode="Markdown"),
        )]
        await update.inline_query.answer(results, cache_time=0)
        return

    token_str, password = parts[0], parts[1]
    try:
        raw = b64dec(token_str)
        # İmzalı token?
        if raw[0:1] == VER_SIGN:
            plain, valid = sign_decrypt(raw, password)
            text = plain.decode()
            sig_icon = "✅ İmza doğrudur" if valid else "⚠️ İmza yanlışdır"
            result_text = f"🔓 {sig_icon}\n\n`{text}`"
        else:
            text = sym_decrypt(raw, password).decode()
            result_text = f"🔓 Deşifrə uğurlu!\n\n`{text}`"

        bf_record_success(uid)
        results = [InlineQueryResultArticle(
            id="ok",
            title=f"✅ Deşifrə: {text[:40]}{'…' if len(text) > 40 else ''}",
            input_message_content=InputTextMessageContent(result_text, parse_mode="Markdown"),
        )]
    except ValueError as e:
        blocked = bf_record_fail(uid)
        if blocked:
            msg = f"🚫 {BF_MAX_ATTEMPTS} uğursuz cəhd — {BF_BLOCK_SECONDS//60} dəq bloklandın."
        else:
            left = bf_remaining_attempts(uid)
            msg  = f"❌ {e}\n_{left} cəhd qalıb_"
        results = [InlineQueryResultArticle(
            id="fail",
            title="❌ Deşifrə alınmadı",
            input_message_content=InputTextMessageContent(msg, parse_mode="Markdown"),
        )]

    await update.inline_query.answer(results, cache_time=0)

# ══════════════════════════════════════════════════════════════════════════════
#  BUTTON ROUTER
# ══════════════════════════════════════════════════════════════════════════════

async def button_handler(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    d   = q.data
    uid = q.from_user.id

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
        elif mode in ("sign_enc",):
            await q.edit_message_text(
                f"✍️ *Müddət: {label}*\n\nİmzalanacaq mətni yazın:",
                parse_mode="Markdown", reply_markup=kb_cancel(),
            )
            ctx.user_data["mode"] = "sign_enc_text"
            return S_SIGN_TEXT
        elif mode == "broadcast_expiry":
            await q.edit_message_text(
                f"📢 *Müddət: {label}*\n\nBroadcast mətnini yazın:",
                parse_mode="Markdown", reply_markup=kb_cancel(),
            )
            ctx.user_data["mode"] = "broadcast_text"
            return S_BROADCAST_TEXT
        else:
            await q.edit_message_text(
                f"⏱ *Müddət: {label}*\n\nŞifrələnəcək mətni yazın:",
                parse_mode="Markdown", reply_markup=kb_cancel(),
            )
            return S_ENC_TEXT

    if d == "genkey_for_send":
        k = genkey(16)
        await q.edit_message_text(
            f"🎲 *Təklif olunan açar:*\n`{k}`\n\n_Bu açarı alıcıya ayrıca bildir, sonra aşağıya yaz:_",
            parse_mode="Markdown", reply_markup=kb_cancel(),
        )
        return S_SEND_MSG

    if d == "sym_enc":
        ctx.user_data.clear(); ctx.user_data["mode"] = "sym_enc"
        await q.edit_message_text("🔑 *Şifrə açarını daxil et:*\n_(istənilən söz)_",
                                  parse_mode="Markdown", reply_markup=kb_cancel())
        return S_ENC_KEY

    if d == "sym_dec":
        ctx.user_data.clear(); ctx.user_data["mode"] = "sym_dec"
        await q.edit_message_text("🔑 *Şifrə açarını daxil et:*",
                                  parse_mode="Markdown", reply_markup=kb_cancel())
        return S_DEC_KEY

    if d == "file_enc":
        ctx.user_data.clear(); ctx.user_data["mode"] = "file_enc"
        await q.edit_message_text("🔑 *Fayl şifrələmə — açar daxil et:*",
                                  parse_mode="Markdown", reply_markup=kb_cancel())
        return S_ENC_KEY

    if d == "file_dec":
        ctx.user_data.clear(); ctx.user_data["mode"] = "file_dec"
        await q.edit_message_text("🔑 *Fayl deşifrələmə — açar daxil et:*",
                                  parse_mode="Markdown", reply_markup=kb_cancel())
        return S_DEC_KEY

    # ── Rəqəmsal imza ────────────────────────────────────────────────────────
    if d == "sign_enc":
        ctx.user_data.clear(); ctx.user_data["mode"] = "sign_enc"
        await q.edit_message_text(
            "✍️ *Rəqəmsal İmza — Açar daxil et:*\n"
            "_Açar həm şifrələmək həm də imzalamaq üçün istifadə olunacaq_",
            parse_mode="Markdown", reply_markup=kb_cancel(),
        )
        return S_SIGN_KEY

    if d == "sign_dec":
        ctx.user_data.clear(); ctx.user_data["mode"] = "sign_dec"
        await q.edit_message_text("🔑 *İmza yoxlama — Açar daxil et:*",
                                  parse_mode="Markdown", reply_markup=kb_cancel())
        return S_VERIFY_KEY

    # ── Steganography ─────────────────────────────────────────────────────────
    if d == "steg_hide":
        ctx.user_data.clear(); ctx.user_data["mode"] = "steg_hide"
        await q.edit_message_text(
            "🖼 *Şəklə Gizlətmə*\n\n🔑 Əvvəlcə şifrə açarı daxil et:",
            parse_mode="Markdown", reply_markup=kb_cancel(),
        )
        return S_STEG_HIDE_KEY

    if d == "steg_reveal":
        ctx.user_data.clear(); ctx.user_data["mode"] = "steg_reveal"
        await q.edit_message_text(
            "🔎 *Şəkildən Çıxartma*\n\n🔑 Şifrə açarı daxil et:",
            parse_mode="Markdown", reply_markup=kb_cancel(),
        )
        return S_STEG_REVEAL_KEY

    # ── Broadcast (yalnız admin) ──────────────────────────────────────────────
    if d == "broadcast":
        if uid not in ADMIN_IDS:
            await q.answer("⛔ İcazəniz yoxdur.", show_alert=True)
            return ConversationHandler.END
        ctx.user_data.clear(); ctx.user_data["mode"] = "broadcast_key"
        await q.edit_message_text(
            "📢 *Broadcast Mesaj*\n\n"
            "🔑 Şifrə açarı daxil et\n_(bütün alıcılar bu açarı bilməlidir)_:",
            parse_mode="Markdown", reply_markup=kb_cancel(),
        )
        return S_BROADCAST_KEY

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

    if d == "mylink":
        link = f"https://t.me/{BOT_USERNAME}?start=send_{uid}"
        await q.edit_message_text(
            "🔗 *Sənin şəxsi şifrəli mesaj linkin:*\n\n"
            f"`{link}`\n\n"
            "Bu linki istənilən yerə paylaş.\n"
            "Kimsə linki açsın → açar seçsin → mətn yazsın → sənin *Gələn qutu*na düşür.",
            parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("📬 Gələn qutu", callback_data="inbox")],
                [InlineKeyboardButton("⬅️ Geri",       callback_data="back")],
            ]),
        )
        return ConversationHandler.END

    if d == "inbox":
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
            "Mesajları oxumaq üçün *şifrə açarını* daxil et",
            parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🔓 Oxu",          callback_data="inbox_read")],
                [InlineKeyboardButton("🗑 Hamısını sil", callback_data="inbox_clear")],
                [InlineKeyboardButton("⬅️ Geri",         callback_data="back")],
            ]),
        )
        return ConversationHandler.END

    if d == "inbox_read":
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
        inbox_clear(uid)
        await q.edit_message_text("🗑 Gələn qutu təmizləndi.", reply_markup=kb_back())
        return ConversationHandler.END

    if d in ("cancel", "back"):
        ctx.user_data.clear()
        is_admin = uid in ADMIN_IDS
        await q.edit_message_text("Ana menyu:", reply_markup=kb_main(is_admin))
        return ConversationHandler.END

# ══════════════════════════════════════════════════════════════════════════════
#  SEND MSG FLOW
# ══════════════════════════════════════════════════════════════════════════════

async def send_msg_step(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    text = update.message.text.strip()
    mode = ctx.user_data.get("mode", "")

    if "send_key" not in ctx.user_data:
        ctx.user_data["send_key"] = text
        ctx.user_data["mode"]     = "send_msg_text"
        await update.message.reply_text("⏱ Token neçə müddət etibarlı olsun?", reply_markup=kb_expiry())
        return S_SEND_MSG

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
            try:
                await ctx.bot.send_message(
                    chat_id=recipient_id,
                    text=f"📬 *Yeni şifrəli mesaj!*\n\nGöndərən: *{sender_name}*\nMüddət: {label}\n\n_Oxumaq üçün /inbox_",
                    parse_mode="Markdown",
                )
            except Exception:
                pass
            await update.message.reply_text(
                f"✅ *Mesaj göndərildi!*\n\n📬 Alıcı bildiriş alacaq.\n⏱ Müddət: {label}",
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
    uid      = update.effective_user.id
    password = update.message.text.strip()
    messages = ctx.user_data.get("inbox_msgs", [])

    # Brute-force yoxla
    remaining = bf_is_blocked(uid)
    if remaining:
        await update.message.reply_text(
            f"🚫 Çox uğursuz cəhd. *{int(remaining)} saniyə* gözlə.",
            parse_mode="Markdown"
        )
        return S_INBOX_KEY

    if not messages:
        await update.message.reply_text("📭 Qutu boşdur.", reply_markup=kb_main(uid in ADMIN_IDS))
        ctx.user_data.clear()
        return ConversationHandler.END

    success = fail = 0
    lines   = []
    for i, item in enumerate(messages, 1):
        try:
            raw = b64dec(item["msg"])
            # İmzalı token yoxla
            if raw[0:1] == VER_SIGN:
                plain, valid = sign_decrypt(raw, password)
                text = plain.decode()
                sig_icon = "✅ İmza OK" if valid else "⚠️ İmza yanlış"
                ts   = datetime.fromtimestamp(item["time"]).strftime("%d.%m %H:%M")
                lines.append(f"*{i}.* 👤 {item['from']} · {ts} · {sig_icon}\n`{text}`")
            else:
                text = sym_decrypt(raw, password).decode()
                ts   = datetime.fromtimestamp(item["time"]).strftime("%d.%m %H:%M")
                lines.append(f"*{i}.* 👤 {item['from']} · {ts}\n`{text}`")
            success += 1
        except ValueError as e:
            lines.append(f"*{i}.* ❌ `{e}`")
            fail += 1

    if fail > 0:
        blocked = bf_record_fail(uid)
        if blocked:
            await update.message.reply_text(
                f"🚫 {BF_MAX_ATTEMPTS} uğursuz cəhd — {BF_BLOCK_SECONDS//60} dəqiqəlik bloklandın!",
                parse_mode="Markdown"
            )
            ctx.user_data.clear()
            return ConversationHandler.END
        left = bf_remaining_attempts(uid)
        lines.append(f"\n⚠️ Bəzi mesajlar açılmadı. _Qalan cəhd: {left}_")
    else:
        bf_record_success(uid)

    summary = f"✅ {success} oxundu" + (f"  |  ❌ {fail} açılmadı" if fail else "")
    full    = summary + "\n\n" + "\n\n".join(lines)

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
        raw    = sym_encrypt(update.message.text.strip().encode(), pw, ttl)
        token  = b64enc(raw)
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
    await update.message.reply_text("Ana menyu:", reply_markup=kb_main(update.effective_user.id in ADMIN_IDS))
    return ConversationHandler.END

# ══════════════════════════════════════════════════════════════════════════════
#  SYMMETRIC DECRYPT FLOW  (brute-force qorumalı)
# ══════════════════════════════════════════════════════════════════════════════

async def got_dec_key(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    remaining = bf_is_blocked(uid)
    if remaining:
        await update.message.reply_text(
            f"🚫 Bloklanmısınız. *{int(remaining)} saniyə* gözləyin.",
            parse_mode="Markdown"
        )
        return S_DEC_KEY
    ctx.user_data["dec_key"] = update.message.text.strip()
    if ctx.user_data.get("mode") == "file_dec":
        await update.message.reply_text("📂 Şifrəli faylı göndər:", reply_markup=kb_cancel())
        return S_DEC_FILE
    await update.message.reply_text("📋 Şifrəli tokeni yapışdır:", reply_markup=kb_cancel())
    return S_DEC_TOKEN

async def got_dec_token(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    remaining = bf_is_blocked(uid)
    if remaining:
        await update.message.reply_text(f"🚫 {int(remaining)} saniyə gözlə.", parse_mode="Markdown")
        return S_DEC_TOKEN

    pw = ctx.user_data["dec_key"]
    try:
        raw = b64dec(update.message.text.strip())
        # İmzalı token?
        if raw[0:1] == VER_SIGN:
            plain, valid = sign_decrypt(raw, pw)
            text = plain.decode()
            sig_icon = "✅ İmza doğrudur" if valid else "⚠️ İmza yanlışdır!"
            await update.message.reply_text(
                f"🔓 *Deşifrə uğurlu!*\n{sig_icon}\n\n`{text}`",
                parse_mode="Markdown"
            )
        else:
            text = sym_decrypt(raw, pw).decode()
            await update.message.reply_text(f"✅ *Deşifrə uğurlu!*\n\n`{text}`", parse_mode="Markdown")
        bf_record_success(uid)
    except ValueError as e:
        blocked = bf_record_fail(uid)
        if blocked:
            await update.message.reply_text(
                f"🚫 {BF_MAX_ATTEMPTS} uğursuz cəhd — {BF_BLOCK_SECONDS//60} dəqiqəlik bloklandınız!",
                parse_mode="Markdown"
            )
        else:
            left = bf_remaining_attempts(uid)
            await update.message.reply_text(
                f"❌ `{e}`\n_Qalan cəhd: {left}_",
                parse_mode="Markdown"
            )
        ctx.user_data.clear()
        return ConversationHandler.END
    except Exception:
        await update.message.reply_text("❌ Deşifrə alınmadı.")
    ctx.user_data.clear()
    await update.message.reply_text("Ana menyu:", reply_markup=kb_main(uid in ADMIN_IDS))
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
    try:
        enc  = sym_encrypt(buf.getvalue(), pw, ttl)
        name = (doc.file_name or "file") + ".enc"
        await update.message.reply_document(
            io.BytesIO(enc), filename=name,
            caption=f"✅ `{doc.file_name}` şifrələndi\n🆔 `{fp(enc)}`  ·  ⏱ {label}",
            parse_mode="Markdown",
        )
    except Exception as e:
        await update.message.reply_text(f"❌ {e}")
    ctx.user_data.clear()
    await update.message.reply_text("Ana menyu:", reply_markup=kb_main(update.effective_user.id in ADMIN_IDS))
    return ConversationHandler.END

async def got_dec_file(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
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
        await update.message.reply_document(io.BytesIO(dec), filename=name,
                                            caption=f"✅ Deşifrə uğurlu — `{name}`",
                                            parse_mode="Markdown")
        bf_record_success(uid)
    except ValueError as e:
        blocked = bf_record_fail(uid)
        if blocked:
            await update.message.reply_text(f"🚫 Bloklandınız! {BF_BLOCK_SECONDS//60} dəq gözləyin.")
        else:
            left = bf_remaining_attempts(uid)
            await update.message.reply_text(f"❌ `{e}`\n_Qalan cəhd: {left}_", parse_mode="Markdown")
    except Exception:
        await update.message.reply_text("❌ Deşifrə alınmadı.")
    ctx.user_data.clear()
    await update.message.reply_text("Ana menyu:", reply_markup=kb_main(uid in ADMIN_IDS))
    return ConversationHandler.END

# ══════════════════════════════════════════════════════════════════════════════
#  RƏQƏMSAl İMZA FLOW
# ══════════════════════════════════════════════════════════════════════════════

async def sign_key_step(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    ctx.user_data["sign_key"] = update.message.text.strip()
    await update.message.reply_text("⏱ Token neçə müddət etibarlı olsun?", reply_markup=kb_expiry())
    return S_SIGN_TEXT   # expiry callback mode="sign_enc" ilə S_SIGN_TEXT-ə yönləndirir

async def sign_text_step(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    pw    = ctx.user_data["sign_key"]
    ttl   = ctx.user_data.get("expiry_sec")
    label = ctx.user_data.get("expiry_label", "Sınırsız")
    sender = update.effective_user.full_name or "Anonim"
    try:
        raw    = sign_encrypt(update.message.text.strip().encode(), pw, ttl)
        token  = b64enc(raw)
        fprint = fp(raw)
        await update.message.reply_text(
            f"✍️ *İmzalandı və Şifrələndi!*\n\n"
            f"👤 İmzalayan: *{sender}*\n"
            f"🔏 Token:\n`{token}`\n\n"
            f"🆔 `{fprint}`  ·  ⏱ {label}\n\n"
            f"_Alıcı deşifrə edəndə imza avtomatik yoxlanılır_",
            parse_mode="Markdown",
        )
    except Exception as e:
        await update.message.reply_text(f"❌ {e}")
    ctx.user_data.clear()
    await update.message.reply_text("Ana menyu:", reply_markup=kb_main(update.effective_user.id in ADMIN_IDS))
    return ConversationHandler.END

async def verify_key_step(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    remaining = bf_is_blocked(uid)
    if remaining:
        await update.message.reply_text(f"🚫 {int(remaining)} saniyə gözlə.")
        return S_VERIFY_KEY
    ctx.user_data["verify_key"] = update.message.text.strip()
    await update.message.reply_text("📋 İmzalı tokeni yapışdır:", reply_markup=kb_cancel())
    return S_VERIFY_TOKEN

async def verify_token_step(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    remaining = bf_is_blocked(uid)
    if remaining:
        await update.message.reply_text(f"🚫 {int(remaining)} saniyə gözlə.")
        return S_VERIFY_TOKEN

    pw = ctx.user_data["verify_key"]
    try:
        raw = b64dec(update.message.text.strip())
        if raw[0:1] != VER_SIGN:
            await update.message.reply_text("⚠️ Bu adi (imzasız) token görünür. Deşifrə etmək üçün ana menyudan 🔓 istifadə edin.")
            ctx.user_data.clear()
            return ConversationHandler.END
        plain, valid = sign_decrypt(raw, pw)
        text = plain.decode()
        icon = "✅ İmza **DOĞRUdur** — məlumat dəyişdirilməyib." if valid else "❌ İmza **YANLIŞ** — məlumat dəyişdirilib!"
        await update.message.reply_text(
            f"🔍 *İmza Yoxlaması*\n\n{icon}\n\n📝 Mətn:\n`{text}`",
            parse_mode="Markdown"
        )
        bf_record_success(uid)
    except ValueError as e:
        blocked = bf_record_fail(uid)
        if blocked:
            await update.message.reply_text(f"🚫 Bloklandınız! {BF_BLOCK_SECONDS//60} dəq gözləyin.")
        else:
            left = bf_remaining_attempts(uid)
            await update.message.reply_text(f"❌ `{e}`\n_Qalan cəhd: {left}_", parse_mode="Markdown")
    except Exception as e:
        await update.message.reply_text(f"❌ Xəta: {e}")
    ctx.user_data.clear()
    await update.message.reply_text("Ana menyu:", reply_markup=kb_main(uid in ADMIN_IDS))
    return ConversationHandler.END

# ══════════════════════════════════════════════════════════════════════════════
#  STEQANOQRAFİYA FLOW
# ══════════════════════════════════════════════════════════════════════════════

async def steg_hide_key_step(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    ctx.user_data["steg_key"] = update.message.text.strip()
    await update.message.reply_text("📝 Gizlədəcəyin mətni yaz:", reply_markup=kb_cancel())
    return S_STEG_HIDE_TEXT

async def steg_hide_text_step(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    pw   = ctx.user_data["steg_key"]
    text = update.message.text.strip()
    try:
        raw   = sym_encrypt(text.encode(), pw, None)
        ctx.user_data["steg_payload"] = raw
        await update.message.reply_text(
            "🖼 İndi **PNG şəkil** göndər.\n"
            f"_Şəkildə ən az {len(raw)*8+32} piksel olmalıdır_",
            parse_mode="Markdown", reply_markup=kb_cancel()
        )
        return S_STEG_HIDE_IMG
    except Exception as e:
        await update.message.reply_text(f"❌ {e}")
        ctx.user_data.clear()
        return ConversationHandler.END

async def steg_hide_img_step(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    photo = update.message.photo or (update.message.document if update.message.document and
                                     update.message.document.mime_type == "image/png" else None)
    if not photo:
        await update.message.reply_text("❌ PNG şəkil göndər.")
        return S_STEG_HIDE_IMG

    payload = ctx.user_data.get("steg_payload")
    if not payload:
        await update.message.reply_text("❌ Sessiya bitib.")
        return ConversationHandler.END

    buf = io.BytesIO()
    if isinstance(photo, list):
        file_obj = await (photo[-1]).get_file()
    else:
        file_obj = await photo.get_file()
    await file_obj.download_to_memory(buf)

    try:
        result_bytes = steg_hide(buf.getvalue(), payload)
        await update.message.reply_document(
            io.BytesIO(result_bytes),
            filename="hidden.png",
            caption="🖼 Şəklə gizlədildi! Bu PNG-ni paylaş — heç kim bilməz.",
        )
    except ValueError as e:
        await update.message.reply_text(f"❌ {e}")
    except Exception as e:
        await update.message.reply_text(f"❌ Xəta: {e}")

    ctx.user_data.clear()
    await update.message.reply_text("Ana menyu:", reply_markup=kb_main(uid in ADMIN_IDS))
    return ConversationHandler.END

async def steg_reveal_key_step(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    remaining = bf_is_blocked(uid)
    if remaining:
        await update.message.reply_text(f"🚫 {int(remaining)} saniyə gözlə.")
        return S_STEG_REVEAL_KEY
    ctx.user_data["steg_reveal_key"] = update.message.text.strip()
    await update.message.reply_text("🖼 Gizli məlumat olan PNG şəklini göndər:", reply_markup=kb_cancel())
    return S_STEG_REVEAL_IMG

async def steg_reveal_img_step(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    uid   = update.effective_user.id
    photo = update.message.photo or (update.message.document if update.message.document and
                                     update.message.document.mime_type == "image/png" else None)
    if not photo:
        await update.message.reply_text("❌ PNG şəkil göndər.")
        return S_STEG_REVEAL_IMG

    pw  = ctx.user_data.get("steg_reveal_key", "")
    buf = io.BytesIO()
    if isinstance(photo, list):
        file_obj = await (photo[-1]).get_file()
    else:
        file_obj = await photo.get_file()
    await file_obj.download_to_memory(buf)

    try:
        raw_payload = steg_reveal(buf.getvalue())
        text = sym_decrypt(raw_payload, pw).decode()
        bf_record_success(uid)
        await update.message.reply_text(
            f"🔎 *Gizli məlumat tapıldı!*\n\n`{text}`",
            parse_mode="Markdown"
        )
    except ValueError as e:
        blocked = bf_record_fail(uid)
        if blocked:
            await update.message.reply_text(f"🚫 Bloklandınız! {BF_BLOCK_SECONDS//60} dəq gözləyin.")
        else:
            left = bf_remaining_attempts(uid)
            await update.message.reply_text(f"❌ `{e}`\n_Qalan cəhd: {left}_", parse_mode="Markdown")
    except Exception as e:
        await update.message.reply_text(f"❌ Xəta: {e}")

    ctx.user_data.clear()
    await update.message.reply_text("Ana menyu:", reply_markup=kb_main(uid in ADMIN_IDS))
    return ConversationHandler.END

# ══════════════════════════════════════════════════════════════════════════════
#  BROADCAST FLOW  (yalnız adminlər)
# ══════════════════════════════════════════════════════════════════════════════

async def broadcast_key_step(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    if uid not in ADMIN_IDS:
        await update.message.reply_text("⛔ İcazəniz yoxdur.")
        return ConversationHandler.END
    ctx.user_data["bc_key"]  = update.message.text.strip()
    ctx.user_data["mode"]    = "broadcast_expiry"
    await update.message.reply_text("⏱ Token neçə müddət etibarlı olsun?", reply_markup=kb_expiry())
    return S_BROADCAST_TEXT  # expiry callback buraya yönləndirəcək

async def broadcast_text_step(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    if uid not in ADMIN_IDS:
        await update.message.reply_text("⛔ İcazəniz yoxdur.")
        return ConversationHandler.END

    pw       = ctx.user_data["bc_key"]
    ttl      = ctx.user_data.get("expiry_sec")
    label    = ctx.user_data.get("expiry_label", "Sınırsız")
    text     = update.message.text.strip()
    subs     = subs_load()
    sender   = update.effective_user.full_name or "Admin"

    if not subs:
        await update.message.reply_text("📭 Heç bir abunəçi yoxdur.")
        ctx.user_data.clear()
        return ConversationHandler.END

    await update.message.reply_text(f"📢 *{len(subs)} abunəçiyə göndərilir...*", parse_mode="Markdown")

    raw   = sym_encrypt(text.encode(), pw, ttl)
    token = b64enc(raw)
    sent = fail = 0

    for sub_id in subs:
        try:
            await ctx.bot.send_message(
                chat_id=sub_id,
                text=(
                    f"📢 *Admin Broadcast Mesajı*\n\n"
                    f"👤 Göndərən: *{sender}*\n"
                    f"⏱ Müddət: {label}\n\n"
                    f"🔏 Şifrəli Token:\n`{token}`\n\n"
                    f"_Deşifrə üçün: 🔓 Deşifrələ → açarı daxil et_"
                ),
                parse_mode="Markdown",
            )
            sent += 1
        except Exception:
            fail += 1

    await update.message.reply_text(
        f"✅ *Broadcast tamamlandı!*\n\n"
        f"📤 Göndərildi: {sent}\n"
        f"❌ Uğursuz: {fail}\n"
        f"⏱ Müddət: {label}",
        parse_mode="Markdown",
    )
    ctx.user_data.clear()
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
        return ConversationHandler.END
    ctx.user_data["inbox_msgs"] = msgs
    ctx.user_data["inbox_uid"]  = uid
    ctx.user_data["mode"]       = "inbox_read"
    await update.message.reply_text(
        f"📬 *{len(msgs)} şifrəli mesaj var.*\n\n🔑 Açarı daxil et:",
        parse_mode="Markdown", reply_markup=kb_cancel(),
    )
    return S_INBOX_KEY

async def cmd_cancel(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    ctx.user_data.clear()
    await update.message.reply_text("Ləğv edildi.", reply_markup=kb_main(uid in ADMIN_IDS))
    return ConversationHandler.END

async def cmd_unsub(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    subs_remove(uid)
    await update.message.reply_text("✅ Broadcast siyahısından çıxarıldınız. (/start ilə yenidən qoşula bilərsiniz)")

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
            CommandHandler("unsub",  cmd_unsub),
            CallbackQueryHandler(button_handler),
        ],
        states={
            S_ENC_KEY:          [MessageHandler(filters.TEXT & ~filters.COMMAND, got_enc_key),         CallbackQueryHandler(button_handler)],
            S_ENC_EXPIRY:       [CallbackQueryHandler(button_handler)],
            S_ENC_TEXT:         [MessageHandler(filters.TEXT & ~filters.COMMAND, got_enc_text),        CallbackQueryHandler(button_handler)],
            S_ENC_FILE:         [MessageHandler(filters.Document.ALL, got_enc_file),                   CallbackQueryHandler(button_handler)],
            S_DEC_KEY:          [MessageHandler(filters.TEXT & ~filters.COMMAND, got_dec_key),         CallbackQueryHandler(button_handler)],
            S_DEC_TOKEN:        [MessageHandler(filters.TEXT & ~filters.COMMAND, got_dec_token),       CallbackQueryHandler(button_handler)],
            S_DEC_FILE:         [MessageHandler(filters.Document.ALL, got_dec_file),                   CallbackQueryHandler(button_handler)],
            S_SEND_MSG:         [MessageHandler(filters.TEXT & ~filters.COMMAND, send_msg_step),       CallbackQueryHandler(button_handler)],
            S_INBOX_KEY:        [MessageHandler(filters.TEXT & ~filters.COMMAND, inbox_key_step),      CallbackQueryHandler(button_handler)],
            S_SIGN_KEY:         [MessageHandler(filters.TEXT & ~filters.COMMAND, sign_key_step),       CallbackQueryHandler(button_handler)],
            S_SIGN_TEXT:        [MessageHandler(filters.TEXT & ~filters.COMMAND, sign_text_step),      CallbackQueryHandler(button_handler)],
            S_VERIFY_KEY:       [MessageHandler(filters.TEXT & ~filters.COMMAND, verify_key_step),     CallbackQueryHandler(button_handler)],
            S_VERIFY_TOKEN:     [MessageHandler(filters.TEXT & ~filters.COMMAND, verify_token_step),   CallbackQueryHandler(button_handler)],
            S_STEG_HIDE_KEY:    [MessageHandler(filters.TEXT & ~filters.COMMAND, steg_hide_key_step),  CallbackQueryHandler(button_handler)],
            S_STEG_HIDE_TEXT:   [MessageHandler(filters.TEXT & ~filters.COMMAND, steg_hide_text_step), CallbackQueryHandler(button_handler)],
            S_STEG_HIDE_IMG:    [MessageHandler(filters.PHOTO | filters.Document.IMAGE, steg_hide_img_step), CallbackQueryHandler(button_handler)],
            S_STEG_REVEAL_KEY:  [MessageHandler(filters.TEXT & ~filters.COMMAND, steg_reveal_key_step),CallbackQueryHandler(button_handler)],
            S_STEG_REVEAL_IMG:  [MessageHandler(filters.PHOTO | filters.Document.IMAGE, steg_reveal_img_step), CallbackQueryHandler(button_handler)],
            S_BROADCAST_KEY:    [MessageHandler(filters.TEXT & ~filters.COMMAND, broadcast_key_step),  CallbackQueryHandler(button_handler)],
            S_BROADCAST_TEXT:   [MessageHandler(filters.TEXT & ~filters.COMMAND, broadcast_text_step), CallbackQueryHandler(button_handler)],
        },
        fallbacks=[
            CommandHandler("cancel", cmd_cancel),
            CommandHandler("start",  cmd_start),
        ],
        allow_reentry=True,
    )

    app.add_handler(conv)
    app.add_handler(InlineQueryHandler(inline_query))

    logger.info("CryptoBot v4 işə düşdü ✅")
    app.run_polling(drop_pending_updates=True)


if __name__ == "__main__":
    main()
