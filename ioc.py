"""استخراج مؤشرات الاختراق من النص فقط، دون إرسال السجل نفسه للخارج."""
import ipaddress, re
URL_RE=re.compile(r"https?://[^\s\"'<>]+",re.I)
HASH_RE=re.compile(r"\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b")
DOMAIN_RE=re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}\b")

def is_public_ip(value):
    try:
        ip=ipaddress.ip_address(value)
        return ip.is_global
    except ValueError: return False

def extract_iocs(text, source_ip=None):
    found=set()
    if source_ip and is_public_ip(source_ip): found.add((source_ip,"ip"))
    for value in URL_RE.findall(text): found.add((value.rstrip(".,;)"),"url"))
    for value in HASH_RE.findall(text): found.add((value.lower(), {32:"md5",40:"sha1",64:"sha256"}[len(value)]))
    for value in DOMAIN_RE.findall(text):
        if not value.lower().endswith((".local",".localhost")): found.add((value.lower(),"domain"))
    return found
