"""عملاء TI محدودون: IOC واحد فقط لكل طلب، timeout وإعادة محاولة واحدة."""
import base64,json,os,time,urllib.error,urllib.parse,urllib.request
from pathlib import Path
BASE=Path(__file__).resolve().parent
def env(name,default=""):
    configured=os.getenv(name)
    if configured is not None:return configured
    path=BASE/'.env'
    if path.exists():
        for line in path.read_text(encoding='utf-8').splitlines():
            if line.startswith(name+'='): return line.split('=',1)[1].strip()
    return default
def fetch(url,headers):
    last=None
    for _ in range(2):
        try:
            req=urllib.request.Request(url,headers=headers)
            with urllib.request.urlopen(req,timeout=8) as r: return json.loads(r.read().decode())
        except (urllib.error.URLError,urllib.error.HTTPError,TimeoutError,json.JSONDecodeError) as e: last=e; time.sleep(.25)
    return {"error":str(last)}
def vt(ioc,kind):
    key=env('VIRUSTOTAL_API_KEY')
    if not key:return {"service":None,"classification":"Observed","reason":"Local observation only; no external verdict was requested."}
    target={"ip":"ip_addresses","domain":"domains","md5":"files","sha1":"files","sha256":"files"}.get(kind)
    if kind=='url': target='urls'; ioc=base64.urlsafe_b64encode(ioc.encode()).decode().rstrip('=')
    data=fetch(f'https://www.virustotal.com/api/v3/{target}/{urllib.parse.quote(ioc,safe="")}',{'x-apikey':key})
    if 'error' in data:return {"service":"VirusTotal","classification":"Unknown","reason":"Service unavailable or quota reached."}
    s=data.get('data',{}).get('attributes',{}).get('last_analysis_stats',{}); bad=s.get('malicious',0); sus=s.get('suspicious',0)
    cls='Malicious' if bad else ('Suspicious' if sus else 'Clean')
    return {"service":"VirusTotal","classification":cls,"reason":f"VirusTotal analysis: {bad} malicious, {sus} suspicious engines.","malicious_count":bad}
def abuse(ip):
    key=env('ABUSEIPDB_API_KEY')
    if not key:return {"service":None,"classification":"Observed","reason":"Local observation only; no external verdict was requested."}
    data=fetch('https://api.abuseipdb.com/api/v2/check?'+urllib.parse.urlencode({'ipAddress':ip,'maxAgeInDays':90}),{'Key':key,'Accept':'application/json'})
    if 'error' in data:return {"service":"AbuseIPDB","classification":"Unknown","reason":"Service unavailable or quota reached."}
    score=data.get('data',{}).get('abuseConfidenceScore',0); cls='Malicious' if score>=80 else ('Suspicious' if score>=25 else 'Clean')
    return {"service":"AbuseIPDB","classification":cls,"reason":f"AbuseIPDB confidence score: {score}.","abuse_score":score}
