"""تنظيف محلي للسجلات قبل مشاركتها؛ لا يستدعي أي خدمة خارجية."""
import re
from collections import defaultdict
PATTERNS=[
 ('email',re.compile(r'\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b')),
 ('ip',re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')),
 ('phone',re.compile(r'(?<!\w)(?:\+?\d[\d .()\-]{7,}\d)(?!\w)')),
 ('mac',re.compile(r'\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b')),
 ('jwt',re.compile(r'\beyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b')),
 ('secret',re.compile(r'(?i)\b(password|token|api[_-]?key|secret|authorization|cookie|session[_-]?id)\s*[=:]\s*([^\s,;]+)')),
]
def sanitize(text, mode='redaction', mask_public_ips=True):
    if mode not in {'redaction','masking','pseudonymization'}:
        raise ValueError('وضع التنظيف غير صالح.')
    maps=defaultdict(dict); counts=defaultdict(int)
    def replace(kind, value):
        counts[kind]+=1
        if mode=='redaction': return f'[REDACTED_{kind.upper()}]'
        if mode=='masking':
            if kind=='email': return value[0]+'***@'+value.split('@',1)[1]
            return value[:3]+'***'
        if value not in maps[kind]: maps[kind][value]=f'{kind.upper()}_{len(maps[kind])+1:03d}'
        return maps[kind][value]
    for kind,pattern in PATTERNS:
        if kind=='secret': text=pattern.sub(lambda m:m.group(1)+'='+replace(kind,m.group(2)),text)
        else: text=pattern.sub(lambda m:replace(kind,m.group(0)),text)
    return text,dict(counts)
