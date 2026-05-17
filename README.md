<div align="center">

# 🛡️ Security Suite
### منصة اختبار الاختراق المدعومة بالذكاء الاصطناعي
### AI-Powered Penetration Testing Platform

[![Docker](https://img.shields.io/badge/Docker-Required-2496ED?style=for-the-badge&logo=docker)](https://www.docker.com/get-started)
[![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=for-the-badge&logo=python)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-Backend-000000?style=for-the-badge&logo=flask)](https://flask.palletsprojects.com)
[![Gemini AI](https://img.shields.io/badge/Gemini_AI-Powered-4285F4?style=for-the-badge&logo=google)](https://aistudio.google.com)

> **مشروع تخرج** — منصة ويب متكاملة لاختبار الاختراق مع تحليل الذكاء الاصطناعي (Google Gemini)،  
> أدوات فحص معزولة بـ Docker، وتوليد تقارير احترافية.

</div>

---

## ✨ المميزات | Features

| الأداة | الوظيفة |
|--------|---------|
| 🔍 **Nmap** | فحص المنافذ والخدمات |
| 💉 **SQLMap** | كشف ثغرات SQL Injection |
| 🐛 **Nikto** | فحص ثغرات تطبيقات الويب |
| 📂 **Wfuzz** | اكتشاف المسارات المخفية |
| 🌐 **theHarvester** | جمع المعلومات (OSINT) |
| 🤖 **Gemini AI** | تحليل ذكي للنتائج |
| 📄 **Reports** | تقارير PDF/JSON/CSV |
| 👥 **Dashboard** | لوحة تحكم للمسؤول والمستخدمين |

---

## 🚀 تشغيل المشروع (للعملاء) | Quick Start

### المتطلبات | Requirements

- ✅ [Docker Desktop](https://www.docker.com/products/docker-desktop/) مثبت ومشغّل
- ✅ [Git](https://git-scm.com/downloads) مثبت
- ✅ مفتاح Gemini AI (مجاني) من [aistudio.google.com](https://aistudio.google.com/app/apikey)

---

### الخطوة 1 — تنزيل المشروع | Clone

```bash
git clone https://github.com/Nasrabdu/Security-Suite.git
cd Security-Suite
```

---

### الخطوة 2 — إعداد المتغيرات | Setup Environment

#### 🪟 Windows:
```powershell
copy .env.example .env
```

#### 🐧 Linux / Mac:
```bash
cp .env.example .env
```

ثم افتح ملف `.env` وضع مفتاح Gemini AI الخاص بك:
```env
GEMINI_API_KEY=your_gemini_api_key_here
```

> 🔑 احصل على مفتاح مجاني من: https://aistudio.google.com/app/apikey

---

### الخطوة 3 — تشغيل المشروع | Start

```bash
docker-compose up -d --build
```

> ⏳ أول مرة يستغرق 5-10 دقائق لتحميل الصور

---

### الخطوة 4 — فتح المنصة | Open

| الخدمة | الرابط |
|--------|--------|
| 🛡️ **Security Suite** | http://localhost:5000 |
| 🎯 **DVWA** (هدف تجريبي) | http://localhost:8080 |
| 🗄️ **pgAdmin** | http://localhost:5050 |

---

### 🔑 بيانات الدخول الافتراضية | Default Credentials

| الحساب | الإيميل | كلمة المرور |
|--------|---------|------------|
| 👑 **Admin** | admin@security.com | القيمة في `.env` → `ADMIN_PASSWORD` |
| 👤 **User** | سجّل حساباً جديداً | — |

---

## 🧪 أهداف الاختبار القانونية | Legal Test Targets

> ⚠️ **تحذير:** استخدم هذه الأهداف **فقط** — لا تفحص أي موقع بدون إذن كتابي

| الأداة | الهدف التجريبي |
|--------|--------------|
| **Nmap** | `scanme.nmap.org` أو `dvwa` |
| **SQLMap** | `http://dvwa/vulnerabilities/sqli/?id=1&Submit=Submit` |
| **Nikto** | `http://dvwa` |
| **Wfuzz** | `http://dvwa/FUZZ` |
| **Harvester** | `google.com` |
| **Ping** | `dvwa` أو `scanme.nmap.org` |

---

## 🛑 إيقاف المشروع | Stop

```bash
docker-compose down
```

لحذف البيانات أيضاً:
```bash
docker-compose down -v
```

---

## 🏗️ هيكل المشروع | Architecture

```
┌────────────────────────────────────────────────────────────┐
│                    BROWSER (User)                          │
│  signin.html → Dashboard → Nmap/SQL/Wfuzz/Nikto/OSINT    │
│                   ↕ REST API calls                         │
├────────────────────────────────────────────────────────────┤
│               Flask Backend (port 5000)                    │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌─────────────┐  │
│  │ Auth API │ │ Scan API │ │Report API│ │  Admin API  │  │
│  └──────────┘ └──────────┘ └──────────┘ └─────────────┘  │
│        ↕             ↕            ↕                        │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐                  │
│  │PostgreSQL│ │ Scanners │ │Gemini AI │                  │
│  └──────────┘ └──────────┘ └──────────┘                  │
├────────────────────────────────────────────────────────────┤
│             Docker Network (pentest_net)                   │
│  ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐  │
│  │ Nmap │ │SQLMap│ │Nikto │ │Wfuzz │ │Harv. │ │ DVWA │  │
│  └──────┘ └──────┘ └──────┘ └──────┘ └──────┘ └──────┘  │
└────────────────────────────────────────────────────────────┘
```

---

## ⚙️ المتغيرات البيئية | Environment Variables

| المتغير | الوصف | مطلوب؟ |
|---------|-------|--------|
| `GEMINI_API_KEY` | مفتاح Google Gemini AI | ✅ مطلوب |
| `SECRET_KEY` | مفتاح تشفير الجلسات | ✅ مطلوب |
| `ADMIN_PASSWORD` | كلمة مرور المسؤول | ✅ مطلوب |
| `POSTGRES_PASSWORD` | كلمة مرور قاعدة البيانات | ✅ مطلوب |
| `CORS_ORIGINS` | أصول CORS المسموحة | اختياري |

---

## 🔧 استكشاف الأخطاء | Troubleshooting

**المشروع لا يعمل؟**
```bash
# تحقق من حالة الـ containers
docker-compose ps

# اطلع على الـ logs
docker-compose logs backend
```

**منفذ محجوز؟**
```bash
# تحقق من المنافذ المستخدمة
netstat -ano | findstr :5000
```

**إعادة بناء من الصفر:**
```bash
docker-compose down -v
docker-compose up -d --build
```

---

## 📝 ملاحظات مهمة | Important Notes

1. 🐳 **Docker** يجب أن يكون مشغّلاً قبل أي أمر
2. 🔑 **لا تشارك** ملف `.env` مع أحد — فيه بيانات سرية
3. ⚖️ **استخدم المشروع بشكل قانوني** — لا تفحص مواقع بدون إذن
4. 🎯 **DVWA** مدمج كهدف تجريبي قانوني آمن
5. 📊 **التقارير** تُحفظ في `Backend/data/scans/reports/`

---

<div align="center">

**مشروع تخرج | Graduation Project 2026**  
Made with ❤️ for Cybersecurity Education

</div>
