# Mini SIEM Dashboard

مشروع تعليمي محلي بلغة Python وFlask. صُمم لشرح فكرة نظام **SIEM** للطالب، وليس لاستبدال أدوات الحماية الاحترافية.

## الفكرة ببساطة

الـ **Log** هو سجل يكتبه الجهاز عن أحداث مثل محاولة تسجيل الدخول أو زيارة صفحة ويب. الـ **SIEM** يقرأ هذه السجلات، يحول كل سطر إلى حدث منظم، ثم يبحث عن أنماط مريبة وينشئ تنبيهات.

```text
ملف Log → parser.py → أحداث في SQLite → detector.py → تنبيهات → Dashboard
```

## التثبيت والتشغيل

من داخل مجلد المشروع:

```bash
python -m venv venv
```

في Windows:

```powershell
venv\Scripts\Activate.ps1
```

في macOS/Linux:

```bash
source venv/bin/activate
```

ثم:

```bash
pip install -r requirements.txt
python app.py
```

افتح المتصفح على `http://127.0.0.1:5000`.

## أنواع السجلات المدعومة

- Linux Authentication: أسطر `Failed password` و`Accepted password` و`Invalid user`.
- Apache/Nginx Access: الصيغة الشائعة لـ access log.
- CSV: يجب أن يحتوي على: `timestamp,source_ip,username,event_type,status`.

## قواعد الكشف

1. **Possible Brute Force (High):** خمس محاولات دخول فاشلة من IP واحد خلال دقيقة.
2. **Username Enumeration (Medium):** ثلاثة أحداث `Invalid user` من IP واحد.
3. **Suspicious Login Success (High):** نجاح تسجيل دخول بعد ثلاث محاولات فاشلة أو أكثر.
4. **Suspicious Web Scanning (Medium):** ثمانية أخطاء 401/403/404 خلال دقيقة.
5. **Suspicious Path Request (Medium):** طلب `/admin` أو `/phpmyadmin` أو `/.env` أو `/wp-login.php`.
6. **High Request Rate (High):** أكثر من 50 طلب ويب من IP واحد خلال دقيقة.

## تجربة المشروع خطوة بخطوة

1. شغّل التطبيق وافتح صفحة **رفع وتحليل**.
2. ارفع `sample_logs/linux_auth.log`. ستظهر تنبيهات Brute Force وUsername Enumeration وSuspicious Login Success.
3. ارفع `sample_logs/web_access.log`. ستظهر تنبيهات المسارات المشبوهة وفحص الويب وكثرة الطلبات.
4. ارفع `sample_logs/mixed_events.csv` لتجربة CSV.
5. اذهب إلى **الأحداث** للبحث والفلترة، ثم **التنبيهات** لقراءة التفاصيل وتغيير الحالة إلى New أو Investigating أو Closed.

## أين توجد الأجزاء المهمة؟

- `parser.py`: يقرأ النص ويستخرج الحقول.
- `detector.py`: يطبق قواعد الكشف فقط.
- `database.py`: يحفظ ويقرأ بيانات SQLite.
- `app.py`: يربط صفحات الويب بكل الأجزاء.

## إضافة Rule جديدة

أضف شرطًا جديدًا داخل الدالة `run_detection` في `detector.py`، ثم استخدم الدالة الداخلية `add` لإنشاء التنبيه. من الأفضل أن تكتب وصفًا واضحًا وتختبره بسجل صغير في `sample_logs`.

## الأمان

المشروع لا ينفذ أي شيء من الملف المرفوع: يقرأه كنص فقط. يقبل `.log` و`.txt` و`.csv` فقط، يحد الحجم إلى 5MB، يستخدم اسم ملف آمن، ولا يستخدم `eval` أو `exec` أو أوامر نظام. كما لا يحفظ الملف الأصلي بعد التحليل.

> تنبيه: هذا مختبر تعليمي. لا ترفعه كما هو إلى الإنترنت ولا تعتمد عليه لاتخاذ قرارات أمنية حقيقية.
