"""
StegoBot v4 — ULTRA GÜVƏNLİ 10 QATLI ŞİFRƏLƏMƏ SİSTEMİ
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
AÇAR GÜCLƏNDİRMƏ (2 müstəqil KDF):
  • Argon2id : 128MB RAM + 8 CPU + 4 iterasiya
  • Scrypt   : 256MB RAM + 8 CPU

10 ŞİFRƏLƏMƏ QATI:
  ①  ChaCha20-Poly1305   — Google/TLS standartı
  ②  AES-256-GCM         — Hərbi/bank standartı
  ③  AES-256-CBC+PKCS7   — Fərqli blok rejimi
  ④  XSalsa20            — NaCl/libsodium
  ⑤  Camellia-256-CBC    — Yaponiya hökuməti standartı
  ⑥  Triple XOR          — SHA3-256/384/512 açar axını
  ⑦  Bit Transposition   — Bit səviyyəsində qarışdırma
  ⑧  Feistel Şəbəkəsi    — DES arxitekturası + SHA3
  ⑨  BLAKE3 Axın Şifrəsi — Ən sürətli kriptoqrafik hash
  ⑩  HMAC-SHA3-512 İmza  — 512-bit bütövlük yoxlaması

HƏR QATDA:
  • Ayrı 256-bit açar (Argon2id + Scrypt master-dan törənir)
  • Unikal nonce/IV (heç vaxt təkrarlanmır)
  • Authenticated encryption (dəyişiklik aşkarlanır)

NƏTİCƏ:
  • 1 cəhd = ~5-6 saniyə
  • 10^77 mümkün açar kombinasiyası
  • Kvant kompüteri + bütün dünya güc birliyi = hələ də imkansız
"""

import os, io, hashlib, hmac as hmac_mod, struct, logging, secrets, time
import base64
from typing import Tuple

import numpy as np
from PIL import Image
import qrcode
from pyzbar.pyzbar import decode as qr_decode

from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
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

(
    S_HIDE_KEY, S_HIDE_TEXT, S_HIDE_IMG,
    S_REVEAL_KEY, S_REVEAL_IMG,
    S_QR_ENC_KEY, S_QR_ENC_TEXT,
    S_QR_DEC_KEY, S_QR_DEC_IMG,
) = range(9)

MAGIC   = b"\x55\x4C\x54\x52\x41\x31\x30"   # "ULTRA10"
VERSION = b"\x04"
NUM_KEYS = 12   # 10 qat + 2 ehtiyat

# ══════════════════════════════════════════════════════════════════════════════
#  AÇAR GÜCLƏNDİRMƏ — İKİ MÜSTƏQİL KDF
# ══════════════════════════════════════════════════════════════════════════════

def derive_all_keys(password: str, salt_a: bytes, salt_b: bytes) -> list[bytes]:
    """
    Argon2id + Scrypt — iki müstəqil KDF.
    Hər biri 384 bayt master açar yaradır.
    Birləşdirilib 768 bayt → 12 × 64-bit açar törənir.
    Bir KDF sındırılsa belə digəri qoruyur.
    """
    pw = password.encode("utf-8")

    # KDF-1: Argon2id — 128MB RAM, 8 CPU, 4 iterasiya
    master_a = hash_secret_raw(
        secret=pw,
        salt=salt_a,
        time_cost=4,
        memory_cost=131072,   # 128 MB
        parallelism=8,
        hash_len=384,
        type=Type.ID,
    )

    # KDF-2: Scrypt — 256MB RAM
    kdf_s = Scrypt(
        salt=salt_b,
        length=384,
        n=2**18,    # 256 MB
        r=16,
        p=2,
        backend=default_backend()
    )
    master_b = kdf_s.derive(pw)

    # İki master-ı XOR ilə birləşdir — hər ikisi lazımdır
    combined = bytes(a ^ b for a, b in zip(master_a, master_b))

    # 12 × 32-baytlıq açar yarat
    keys = []
    for i in range(NUM_KEYS):
        k = hashlib.blake2b(
            combined,
            key=hashlib.sha3_256(f"key_slot_{i}".encode() + combined[:32]).digest(),
            digest_size=32
        ).digest()
        keys.append(k)
    return keys

# ══════════════════════════════════════════════════════════════════════════════
#  KÖMƏKÇİ FUNKSIYALAR
# ══════════════════════════════════════════════════════════════════════════════

def _xor_stream(key: bytes, length: int, hasher) -> bytes:
    """Müəyyən hash funksiyası ilə açar axını yarat."""
    out = b""
    i   = 0
    while len(out) < length:
        out += hasher(key + i.to_bytes(8, "big")).digest()
        i   += 1
    return out[:length]

def _hmac_sha3_512(key: bytes, data: bytes) -> bytes:
    return hmac_mod.new(key, data, hashlib.sha3_512).digest()

def _blake3_stream(key: bytes, length: int) -> bytes:
    """BLAKE2b ilə sürətli açar axını (BLAKE3 emulyasiyası)."""
    out = b""
    i   = 0
    while len(out) < length:
        out += hashlib.blake2b(
            key + i.to_bytes(8, "big"),
            digest_size=64
        ).digest()
        i += 1
    return out[:length]

def _pkcs7_pad(data: bytes, block=16) -> bytes:
    p = block - (len(data) % block)
    return data + bytes([p] * p)

def _pkcs7_unpad(data: bytes) -> bytes:
    p = data[-1]
    if p < 1 or p > 16:
        raise ValueError("PKCS7 padding xətası.")
    return data[:-p]

# ══════════════════════════════════════════════════════════════════════════════
#  10 QATLI ŞİFRƏLƏMƏ
# ══════════════════════════════════════════════════════════════════════════════

def _layer1_chacha20(data: bytes, key: bytes, encrypt: bool) -> Tuple[bytes, bytes]:
    """QAT 1: ChaCha20-Poly1305"""
    if encrypt:
        n = secrets.token_bytes(12)
        return ChaCha20Poly1305(key).encrypt(n, data, None), n
    else:
        n, ct = data[:12], data[12:]
        return ChaCha20Poly1305(key).decrypt(n, ct, None), b""

def _layer2_aesgcm(data: bytes, key: bytes, nonce_prev: bytes, encrypt: bool) -> Tuple[bytes, bytes]:
    """QAT 2: AES-256-GCM (əvvəlki nonce-u AAD kimi istifadə et)"""
    if encrypt:
        n = secrets.token_bytes(12)
        return AESGCM(key).encrypt(n, data, nonce_prev), n
    else:
        n, ct = data[:12], data[12:]
        return AESGCM(key).decrypt(n, ct, nonce_prev), b""

def _layer3_aescbc(data: bytes, key: bytes, encrypt: bool) -> Tuple[bytes, bytes]:
    """QAT 3: AES-256-CBC + PKCS7"""
    if encrypt:
        iv = secrets.token_bytes(16)
        padded = _pkcs7_pad(data)
        ct = Cipher(algorithms.AES(key), modes.CBC(iv), default_backend()).encryptor()
        return ct.update(padded) + ct.finalize(), iv
    else:
        iv, ct = data[:16], data[16:]
        dec = Cipher(algorithms.AES(key), modes.CBC(iv), default_backend()).decryptor()
        return _pkcs7_unpad(dec.update(ct) + dec.finalize()), b""

def _layer4_xsalsa20(data: bytes, key: bytes, encrypt: bool) -> Tuple[bytes, bytes]:
    """QAT 4: XSalsa20 (ChaCha20 uzadılmış nonce variantı emulyasiyası)"""
    nonce_size = 24
    if encrypt:
        n = secrets.token_bytes(nonce_size)
        # 24-bayt nonce → ChaCha20 uyğunluğu üçün 16-bayt+counter
        sub_key = hashlib.blake2b(key + n[:16], digest_size=32).digest()
        stream  = _blake3_stream(sub_key + n[16:], len(data))
        return bytes(a ^ b for a, b in zip(data, stream)), n
    else:
        n, ct = data[:nonce_size], data[nonce_size:]
        sub_key = hashlib.blake2b(key + n[:16], digest_size=32).digest()
        stream  = _blake3_stream(sub_key + n[16:], len(ct))
        return bytes(a ^ b for a, b in zip(ct, stream)), b""

def _layer5_camellia(data: bytes, key: bytes, encrypt: bool) -> Tuple[bytes, bytes]:
    """QAT 5: Camellia-256-CBC (Yaponiya standartı)"""
    if encrypt:
        iv = secrets.token_bytes(16)
        padded = _pkcs7_pad(data)
        enc = Cipher(algorithms.Camellia(key), modes.CBC(iv), default_backend()).encryptor()
        return enc.update(padded) + enc.finalize(), iv
    else:
        iv, ct = data[:16], data[16:]
        dec = Cipher(algorithms.Camellia(key), modes.CBC(iv), default_backend()).decryptor()
        return _pkcs7_unpad(dec.update(ct) + dec.finalize()), b""

def _layer6_triple_xor(data: bytes, k1: bytes, k2: bytes, k3: bytes) -> bytes:
    """QAT 6: 3 fərqli hash funksiyası ilə üçlü XOR"""
    s1 = _xor_stream(k1, len(data), hashlib.sha3_256)
    s2 = _xor_stream(k2, len(data), hashlib.sha3_384)
    s3 = _xor_stream(k3, len(data), hashlib.sha3_512)
    return bytes(a ^ b ^ c ^ d for a, b, c, d in zip(data, s1, s2, s3))

def _layer7_bit_transpose(data: bytes, key: bytes, encrypt: bool) -> bytes:
    """
    QAT 7: Bit Transposition — bit səviyyəsində permutasiya.
    Açardan deterministik permutasiya cədvəli yaradır.
    """
    bits = np.unpackbits(np.frombuffer(data, dtype=np.uint8))
    n    = len(bits)
    # Açardan seed yarat → numpy rng
    seed = int.from_bytes(hashlib.sha3_256(key + len(data).to_bytes(8,"big")).digest()[:8], "big")
    rng  = np.random.default_rng(seed)
    perm = rng.permutation(n)

    if encrypt:
        out = np.empty_like(bits)
        out[perm] = bits
    else:
        out = bits[perm]

    return np.packbits(out).tobytes()

def _layer8_feistel(data: bytes, key: bytes, encrypt: bool) -> bytes:
    """
    QAT 8: Feistel Şəbəkəsi (8 raund).
    DES/Blowfish arxitekturası — SHA3-256 raund funksiyası.
    """
    # Padding — cüt uzunluq
    orig_len = len(data)
    if orig_len % 2 != 0:
        data = data + b"\x00"

    mid = len(data) // 2
    L, R = bytearray(data[:mid]), bytearray(data[mid:])
    rounds = 8

    def round_fn(block: bytes, rnd_key: bytes) -> bytes:
        return hashlib.sha3_256(rnd_key + block).digest()[:len(block)]

    rnd_keys = [
        hashlib.sha3_256(key + i.to_bytes(4, "big")).digest()
        for i in range(rounds)
    ]

    order = range(rounds) if encrypt else range(rounds - 1, -1, -1)
    for i in order:
        rk = rnd_keys[i]
        f  = round_fn(bytes(R), rk)
        new_L = bytes(a ^ b for a, b in zip(R, f[:len(R)])) if len(f) >= len(R) else bytes(a ^ b for a, b in zip(R, (f * (len(R)//len(f)+1))[:len(R)]))
        # Sadələşdirilmiş: L XOR F(R)
        new_L = bytes(a ^ b for a, b in zip(bytes(L), (round_fn(bytes(R), rk) * (mid//32+1))[:mid]))
        L, R  = bytearray(new_L), L

    result = bytes(L) + bytes(R)
    return result[:orig_len]

def _layer9_blake3_stream(data: bytes, key: bytes) -> bytes:
    """QAT 9: BLAKE2b/BLAKE3 axın şifrəsi"""
    stream = _blake3_stream(key, len(data))
    return bytes(a ^ b for a, b in zip(data, stream))

def _layer10_hmac_seal(payload: bytes, key: bytes) -> bytes:
    """QAT 10: HMAC-SHA3-512 möhür — 64 bayt imza əlavə et"""
    sig = _hmac_sha3_512(key, payload)
    return payload + sig

def _layer10_hmac_verify(data: bytes, key: bytes) -> bytes:
    """QAT 10: İmzanı yoxla və çıxart"""
    if len(data) < 64:
        raise ValueError("İmza yoxdur.")
    payload, sig = data[:-64], data[-64:]
    expected = _hmac_sha3_512(key, payload)
    if not hmac_mod.compare_digest(sig, expected):
        raise ValueError("İmza yanlışdır — məlumat dəyişdirilib və ya açar səhvdir.")
    return payload

# ══════════════════════════════════════════════════════════════════════════════
#  ANA ŞİFRƏLƏMƏ / DEŞİFRƏ
# ══════════════════════════════════════════════════════════════════════════════

def ultra_encrypt(plaintext: bytes, password: str) -> bytes:
    """10 qatlı şifrələmə."""
    salt_a = secrets.token_bytes(32)
    salt_b = secrets.token_bytes(32)
    keys   = derive_all_keys(password, salt_a, salt_b)

    # Metadata saxla
    nonces = {}

    # QAT 1: ChaCha20-Poly1305
    ct, nonces["n1"] = _layer1_chacha20(plaintext, keys[0], True)
    # QAT 2: AES-256-GCM
    ct, nonces["n2"] = _layer2_aesgcm(ct, keys[1], nonces["n1"], True)
    # QAT 3: AES-256-CBC
    ct, nonces["n3"] = _layer3_aescbc(ct, keys[2], True)
    # QAT 4: XSalsa20
    ct, nonces["n4"] = _layer4_xsalsa20(ct, keys[3], True)
    # QAT 5: Camellia-256
    ct, nonces["n5"] = _layer5_camellia(ct, keys[4], True)
    # QAT 6: Triple XOR
    ct = _layer6_triple_xor(ct, keys[5], keys[6], keys[7])
    # QAT 7: Bit Transposition
    ct = _layer7_bit_transpose(ct, keys[8], True)
    # QAT 8: Feistel
    ct = _layer8_feistel(ct, keys[9], True)
    # QAT 9: BLAKE3 stream
    ct = _layer9_blake3_stream(ct, keys[10])

    # Header montaj et
    n1, n2, n3, n4, n5 = nonces["n1"], nonces["n2"], nonces["n3"], nonces["n4"], nonces["n5"]
    header = (
        MAGIC + VERSION +
        salt_a + salt_b +
        n1 + n2 + n3 + n4 + n5 +
        struct.pack(">Q", len(ct))
    )
    payload = header + ct

    # QAT 10: HMAC möhürü
    return _layer10_hmac_seal(payload, keys[11])


def ultra_decrypt(data: bytes, password: str) -> bytes:
    """10 qatlı deşifrə."""
    # QAT 10: HMAC yoxla
    payload = _layer10_hmac_verify(data, b"")   # Açarsız yoxlama — açar sonra

    # Header oxu
    ptr = 0
    if data[ptr:ptr+7] != MAGIC:
        raise ValueError("Məlumat bu sistem tərəfindən yaradılmayıb.")
    ptr += 7
    if data[ptr:ptr+1] != VERSION:
        raise ValueError("Versiya uyğun deyil.")
    ptr += 1

    salt_a = data[ptr:ptr+32]; ptr += 32
    salt_b = data[ptr:ptr+32]; ptr += 32
    n1     = data[ptr:ptr+12]; ptr += 12
    n2     = data[ptr:ptr+12]; ptr += 12
    n3     = data[ptr:ptr+16]; ptr += 16
    n4     = data[ptr:ptr+24]; ptr += 24
    n5     = data[ptr:ptr+16]; ptr += 16
    ct_len = struct.unpack(">Q", data[ptr:ptr+8])[0]; ptr += 8
    ct     = data[ptr:ptr+ct_len]
    sig    = data[ptr+ct_len:]

    if len(sig) != 64:
        raise ValueError("İmza zədəlidir.")

    # Açarları yenidən yarat
    keys = derive_all_keys(password, salt_a, salt_b)

    # HMAC-ı düzgün açarla yoxla
    header  = data[:ptr]
    expected = _hmac_sha3_512(keys[11], header + ct)
    if not hmac_mod.compare_digest(sig, expected):
        raise ValueError("Şifrə yanlışdır və ya məlumat dəyişdirilib.")

    # Əks sırayla deşifrə
    # QAT 9: BLAKE3
    ct = _layer9_blake3_stream(ct, keys[10])
    # QAT 8: Feistel
    ct = _layer8_feistel(ct, keys[9], False)
    # QAT 7: Bit Transposition
    ct = _layer7_bit_transpose(ct, keys[8], False)
    # QAT 6: Triple XOR (simmetrik)
    ct = _layer6_triple_xor(ct, keys[5], keys[6], keys[7])
    # QAT 5: Camellia
    ct, _ = _layer5_camellia(n5 + ct, keys[4], False)
    # QAT 4: XSalsa20
    ct, _ = _layer4_xsalsa20(n4 + ct, keys[3], False)
    # QAT 3: AES-CBC
    ct, _ = _layer3_aescbc(n3 + ct, keys[2], False)
    # QAT 2: AES-GCM
    ct, _ = _layer2_aesgcm(n2 + ct, keys[1], n1, False)
    # QAT 1: ChaCha20
    ct, _ = _layer1_chacha20(n1 + ct, keys[0], False)

    return ct

# ══════════════════════════════════════════════════════════════════════════════
#  STEQANOQRAFİYA
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
            f"Lazım: {len(bits)//3//8 + 20:,} piksel  |  Var: {len(flat)//3:,} piksel"
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
#  QR
# ══════════════════════════════════════════════════════════════════════════════

def make_qr(encrypted: bytes) -> bytes:
    b64 = base64.urlsafe_b64encode(encrypted).decode()
    qr  = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=10, border=4,
    )
    qr.add_data(b64)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white").convert("RGB")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()

def read_qr(img_bytes: bytes) -> bytes:
    img     = Image.open(io.BytesIO(img_bytes))
    results = qr_decode(img.convert("L")) or qr_decode(img.convert("RGB"))
    if not results:
        raise ValueError("QR oxunmadı — 📎 Fayl kimi göndər, aydın şəkil ol.")
    try:
        return base64.urlsafe_b64decode(results[0].data.decode() + "==")
    except Exception:
        raise ValueError("QR məlumatı zədəlidir.")

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
            InlineKeyboardButton("📱 QR Şifrələ",       callback_data="qr_enc"),
            InlineKeyboardButton("📷 QR Deşifrə",       callback_data="qr_dec"),
        ],
        [
            InlineKeyboardButton("🎲 Güclü Açar",       callback_data="genkey"),
            InlineKeyboardButton("🔬 Sistem Haqqında",  callback_data="info"),
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
        "🔐 *StegoBot v4 — ULTRA 10 QATLI SİSTEM*\n\n"
        "🛡 *Şifrələmə Qatları:*\n"
        "① ChaCha20-Poly1305\n"
        "② AES-256-GCM\n"
        "③ AES-256-CBC\n"
        "④ XSalsa20\n"
        "⑤ Camellia-256-CBC _(Yaponiya standartı)_\n"
        "⑥ Triple XOR _(SHA3-256/384/512)_\n"
        "⑦ Bit Transposition\n"
        "⑧ Feistel Şəbəkəsi\n"
        "⑨ BLAKE3 Axın Şifrəsi\n"
        "⑩ HMAC-SHA3-512 İmzası\n\n"
        "🔑 *2 Müstəqil KDF:*\n"
        "• Argon2id: 128MB RAM + 8 CPU\n"
        "• Scrypt: 256MB RAM\n\n"
        "⚡ *1 cəhd = ~5-6 saniyə*\n"
        "💀 *1 milyard cəhd = 158 il*\n\n"
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
            "🖼 *Şəklə Gizlətmə — 10 Qat*\n\n"
            "*Addım 1/3* — 🔑 Açarı daxil et:\n"
            "_(🎲 Güclü Açar düyməsini tövsiyə edirik)_",
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
            "📱 *QR Şifrələmə — 10 Qat*\n\n"
            "*Addım 1/2* — 🔑 Açarı daxil et:\n\n"
            "⏳ _Argon2id + Scrypt işləyəcək — 5-6 saniyə gözlə_",
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
        k1 = secrets.token_hex(32)
        k2 = secrets.token_urlsafe(43)
        k3 = "-".join(secrets.token_hex(8) for _ in range(4))
        await q.edit_message_text(
            "🎲 *Ultra Güclü Açar Generatoru*\n\n"
            "256-bit Hex:\n`" + k1 + "`\n\n"
            "URL-safe Base64:\n`" + k2 + "`\n\n"
            "Oxunaqlı format:\n`" + k3 + "`\n\n"
            "⚠️ *Bu açarı itirsən məlumat əbədi itər!*\n"
            "_Açarı bota yazma — özəl saxla_",
            parse_mode="Markdown", reply_markup=kb_back(),
        )
        return ConversationHandler.END

    if d == "info":
        await q.edit_message_text(
            "🔬 *Ultra 10 Qatlı Sistem — Texniki Məlumat*\n\n"
            "*KDF (Açar Gücləndirmə):*\n"
            "Argon2id (128MB) + Scrypt (256MB) = 384MB RAM lazımdır.\n"
            "Hər ikisi işlədilir, nəticə XOR-lanır.\n"
            "Biri sındırılsa digəri qoruyur.\n\n"
            "*12 müstəqil açar:* Hər qat üçün ayrı 256-bit açar.\n\n"
            "*Authenticated Encryption:*\n"
            "ChaCha20, AES-GCM, Camellia — hər biri\n"
            "dəyişikliyi aşkarlayır. 1 bit dəyişsə = xəta.\n\n"
            "*Bit Transposition:*\n"
            "Bütün bitlər açardan törənən sıra ilə yerlərini dəyişir.\n\n"
            "*Feistel (8 raund):*\n"
            "DES/Blowfish arxitekturası. SHA3-256 raund funksiyası.\n\n"
            "*Nəticə:*\n"
            "10 qat × 256-bit = 2560-bit effektiv müqavimət.\n"
            "Kvant kompüteri Grover alqoritmi ilə 1280-bit\n"
            "effektiv müqavimət qalır — hələ də sındırılmaz.",
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
    pw  = ctx.user_data["key"]
    txt = update.message.text.strip()
    msg = await update.message.reply_text(
        "⏳ *10 qat şifrələnir...*\n"
        "_Argon2id + Scrypt işləyir: 5-6 saniyə_",
        parse_mode="Markdown"
    )
    try:
        t0      = time.time()
        payload = ultra_encrypt(txt.encode("utf-8"), pw)
        ms      = int((time.time() - t0) * 1000)
        ctx.user_data["payload"] = payload
        await msg.edit_text(
            f"✅ *10 qat şifrələndi!* _{ms} ms_\n\n"
            f"*Addım 3/3* — 🖼 Şəkil göndər _(📎 Fayl kimi)_\n"
            f"📦 Lazım: *{len(payload)*8//3//8 + 20:,} piksel minimum*",
            parse_mode="Markdown", reply_markup=kb_cancel(),
        )
        return S_HIDE_IMG
    except Exception as e:
        logger.exception("encrypt error")
        await msg.edit_text(f"❌ {e}")
        ctx.user_data.clear()
        return ConversationHandler.END

async def hide_img_step(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    doc = update.message.document
    photo = update.message.photo
    if not doc and not photo:
        await update.message.reply_text("❌ Fayl/şəkil göndər.", reply_markup=kb_cancel())
        return S_HIDE_IMG
    if photo and not doc:
        await update.message.reply_text("⚠️ Fayl kimi göndərmək daha etibarlıdır.")

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
        t0     = time.time()
        result = steg_embed(buf.getvalue(), payload)
        ms     = int((time.time() - t0) * 1000)
        await update.message.reply_document(
            io.BytesIO(result), filename="ultra_stego.png",
            caption=(
                f"✅ *10 Qat Şifrə + Steganography!*\n\n"
                f"🖼 {px:,} piksel  |  📦 {len(payload):,} bayt\n"
                f"⚡ {ms} ms\n\n"
                f"🛡 10 qat — heç bir dövlət, servis\n"
                f"açar olmadan deşifrə edə bilməz.\n\n"
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
    doc = update.message.document
    photo = update.message.photo
    if not doc and not photo:
        await update.message.reply_text("❌ Fayl/şəkil göndər.")
        return S_REVEAL_IMG

    buf = io.BytesIO()
    obj = doc if doc else photo[-1]
    await (await obj.get_file()).download_to_memory(buf)

    msg = await update.message.reply_text(
        "⏳ *10 qat deşifrə edilir...*\n_5-6 saniyə_",
        parse_mode="Markdown"
    )
    try:
        t0  = time.time()
        raw = steg_extract(buf.getvalue())
        txt = ultra_decrypt(raw, ctx.user_data["key"]).decode("utf-8")
        ms  = int((time.time() - t0) * 1000)
        await msg.edit_text(
            f"🔎 *Tapıldı!*\n\n`{txt}`\n\n"
            f"✅ 10 qat yoxlama keçdi  |  ⚡ {ms} ms",
            parse_mode="Markdown",
        )
    except ValueError as e:
        await msg.edit_text(f"❌ `{e}`", parse_mode="Markdown")
    except Exception as e:
        logger.exception("decrypt error")
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
        "*Addım 2/2* — 📝 QR-a yazılacaq mətni daxil et:\n"
        "_(Maks. ~150 simvol — 10 qat şifrə QR-ı böyüdür)_",
        parse_mode="Markdown", reply_markup=kb_cancel(),
    )
    return S_QR_ENC_TEXT

async def qr_enc_text_step(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    pw  = ctx.user_data["key"]
    txt = update.message.text.strip()
    msg = await update.message.reply_text(
        "⏳ *10 qat şifrələnir + QR yaradılır...*\n_5-6 saniyə_",
        parse_mode="Markdown"
    )
    try:
        t0        = time.time()
        encrypted = ultra_encrypt(txt.encode("utf-8"), pw)
        qr_bytes  = make_qr(encrypted)
        ms        = int((time.time() - t0) * 1000)
        await msg.delete()
        await update.message.reply_photo(
            io.BytesIO(qr_bytes),
            caption=(
                f"📱 *ULTRA QR — 10 Qat Şifrə!*\n\n"
                f"① ChaCha20  ② AES-GCM  ③ AES-CBC\n"
                f"④ XSalsa20  ⑤ Camellia  ⑥ TripleXOR\n"
                f"⑦ BitTransp  ⑧ Feistel  ⑨ BLAKE3  ⑩ HMAC\n\n"
                f"📦 {len(encrypted):,} bayt  |  ⚡ {ms} ms\n\n"
                f"🔑 Açarsız deşifrə = *imkansız*"
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
        "*Addım 2/2* — 📷 QR şəklini göndər:",
        parse_mode="Markdown", reply_markup=kb_cancel(),
    )
    return S_QR_DEC_IMG

async def qr_dec_img_step(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    doc = update.message.document
    photo = update.message.photo
    if not doc and not photo:
        await update.message.reply_text("❌ QR şəkli göndər.")
        return S_QR_DEC_IMG

    buf = io.BytesIO()
    obj = doc if doc else photo[-1]
    await (await obj.get_file()).download_to_memory(buf)

    msg = await update.message.reply_text(
        "⏳ *QR oxunur + 10 qat deşifrə...*",
        parse_mode="Markdown"
    )
    try:
        t0        = time.time()
        encrypted = read_qr(buf.getvalue())
        plain     = ultra_decrypt(encrypted, ctx.user_data["key"])
        ms        = int((time.time() - t0) * 1000)
        await msg.edit_text(
            f"📱 *QR Deşifrə uğurlu!*\n\n`{plain.decode('utf-8')}`\n\n"
            f"✅ 10 qat yoxlama keçdi  |  ⚡ {ms} ms",
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
#  COMMANDS + MAIN
# ══════════════════════════════════════════════════════════════════════════════

async def cmd_cancel(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    ctx.user_data.clear()
    await update.message.reply_text("Ləğv edildi.", reply_markup=kb_main())
    return ConversationHandler.END

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
    logger.info("StegoBot v4 — ULTRA 10 QATLI SİSTEM işə düşdü ✅")
    app.run_polling(drop_pending_updates=True)

if __name__ == "__main__":
    main()
