# تشغيل Mini SIEM ومشاركته بأمان

هذا مشروع تعليمي وليس بديلًا عن SIEM احترافي. لا يُحفظ الملف المرفوع نفسه، لكن تُحفظ في SQLite الأحداث المستخرجة، والسطر الأصلي المرتبط بكل حدث، والتنبيهات، ومؤشرات IOC. استخدم قسم الاحتفاظ في لوحة التحكم لحذف التحليلات القديمة.

## قبل النشر العام

1. انسخ `.env.example` إلى `.env` ولا ترفعه إلى Git.
2. عيّن `MINI_SIEM_SECRET_KEY` لقيمة عشوائية ثابتة.
3. أنشئ hash لكلمة مرور قوية وضعه في `MINI_SIEM_ADMIN_PASSWORD_HASH`. عند تركه فارغًا لا تكون الواجهة محمية بتسجيل دخول.
4. اترك `MINI_SIEM_DEV_TOOLS=0` في الإنتاج.
5. اجعل HTTPS مفعّلًا من منصة الاستضافة واحتفظ بنسخة احتياطية من `instance/mini_siem.db` عند الحاجة.

## الصيغ المدعومة

- Linux: sshd failed/accepted/invalid user، sudo authentication، ونص systemd journal المصدّر.
- Apache وNginx: access logs وerror logs الشائعة.
- CSV: `timestamp,event_type` أو `time,message` أو Windows `EventID,TimeCreated`.
- Windows: XML وJSON وCSV وEVTX. يتطلب EVTX مكتبة `python-evtx`؛ وعند تعذرها صدّر السجل إلى XML أو CSV.

## Threat Intelligence

أضف `VIRUSTOTAL_API_KEY` و/أو `ABUSEIPDB_API_KEY` إلى `.env`. لا تعرض الواجهة المفتاح ولا ترسله في السجلات. لا تُرسل الخدمات إلا قيمة IOC المستخرجة، ولا تُرسل ملف السجل الخام.
