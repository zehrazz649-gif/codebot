# 🔐 CryptoBot — AES-256-GCM Telegram Şifrələmə Botu

Güclü AES-256-GCM şifrələmə ilə mətnlərinizi qoruyun.

---

## ⚙️ Qurulum

### 1. Bot Token Al
1. Telegramda [@BotFather](https://t.me/BotFather) aç
2. `/newbot` yaz, bot adını ver
3. Sənə bir **TOKEN** verəcək — onu saxla

### 2. Railway-də Deploy Et

1. [railway.app](https://railway.app) saytına gir
2. **New Project → Deploy from GitHub repo** seç
3. Bu faylları GitHub-a yüklə
4. Railway dashboard-da **Variables** bölməsinə keç:
   ```
   BOT_TOKEN = <BotFather-dən aldığın token>
   MASTER_KEY = <istənilən güclü şifrə - backup üçün>
   ```
5. Deploy et — bot avtomatik işə düşəcək ✅

---

## 🔒 Şifrələmə Texnologiyası

| Komponent | Dəyər |
|-----------|-------|
| Alqoritm | AES-256-GCM |
| Açar törəmə | PBKDF2-SHA256 |
| İterasiya sayı | 600,000 |
| Salt | 256-bit random |
| Nonce | 96-bit random |
| Auth Tag | 128-bit GCM |

**Niyə bu güclüdür?**
- Hər şifrələmə unique salt + nonce istifadə edir
- Eyni mətn ikinci dəfə tamamilə fərqli çıxır
- GCM modu məlumatın dəyişdirilmədiyini təsdiqləyir
- 600,000 PBKDF2 iterasiyası brute-force hücumlarını çətinləşdirir

---

## 📱 İstifadə

```
/start → Ana menyu açılır
🔒 Şifrələ → Açar + Mətn → Şifrəli token alırsın
🔓 Deşifrələ → Açar + Token → Orijinal mətn çıxır
```

---

## 🛡️ Təhlükəsizlik Qeydi

- Şifrə açarı heç bir yerdə saxlanmır
- Bot serverə yalnız şifrəli mətn göndərilmir
- Hər sessiya müstəqildir
