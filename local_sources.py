"""قراءة محلية آمنة فقط من قائمة مصادر ثابتة؛ لا توجد مسارات يكتبها المستخدم."""
import os, platform, json
from pathlib import Path
LINUX_SOURCES={
 'linux_auth':('/var/log/auth.log','Linux Auth'), 'syslog':('/var/log/syslog','Linux Syslog'),
 'kern':('/var/log/kern.log','Linux Kernel'), 'apache_access':('/var/log/apache2/access.log','Web Access'),
 'apache_error':('/var/log/apache2/error.log','Web Error'), 'nginx_access':('/var/log/nginx/access.log','Web Access'),
 'nginx_error':('/var/log/nginx/error.log','Web Error'),}
WINDOWS_SOURCES={'windows_security':('Security','Windows Security'),'windows_system':('System','Windows System'),'windows_application':('Application','Windows Application')}
def sources():
    return WINDOWS_SOURCES if platform.system()=='Windows' else LINUX_SOURCES
def source_status(key):
    if key not in sources(): return 'Error'
    if platform.system()=='Windows':
        try:
            import win32evtlog
            win32evtlog.OpenEventLog(None,sources()[key][0]); return 'Connected'
        except ImportError:return 'Unavailable (install pywin32)'
        except PermissionError:return 'Permission Denied'
        except Exception:return 'Error'
    p=Path(sources()[key][0])
    return 'Connected' if p.is_file() and os.access(p,os.R_OK) else ('File Not Found' if not p.exists() else 'Permission Denied')
def read_source(key,limit):
    """يقرأ آخر سطور Linux أو آخر Event Records Windows في الذاكرة فقط."""
    if key not in sources(): raise ValueError('Invalid local log source.')
    limit=max(1,min(int(limit),1000))
    if platform.system()!='Windows':
        p=Path(sources()[key][0]);
        with p.open('r',encoding='utf-8',errors='replace') as f: return ''.join(f.readlines()[-limit:])
    try: import win32evtlog
    except ImportError: raise RuntimeError('pywin32 is required for Windows Event Logs.')
    channel=sources()[key][0]; handle=win32evtlog.OpenEventLog(None,channel); rows=[]
    flags=win32evtlog.EVENTLOG_BACKWARDS_READ|win32evtlog.EVENTLOG_SEQUENTIAL_READ
    while len(rows)<limit:
        events=win32evtlog.ReadEventLog(handle,flags,0)
        if not events: break
        for event in events:
            inserts=list(event.StringInserts or [])
            rows.append({'EventID':event.EventID & 0xffff,'ProviderName':event.SourceName,'Computer':event.ComputerName,
                         'TimeCreated':event.TimeGenerated.Format(),'Message':' | '.join(map(str,inserts))})
            if len(rows)>=limit: break
    win32evtlog.CloseEventLog(handle)
    return json.dumps(list(reversed(rows)),ensure_ascii=False)
