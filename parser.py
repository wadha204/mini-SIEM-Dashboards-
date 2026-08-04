"""محللات نصية آمنة وقابلة للتوسعة للسجلات الشائعة."""
import csv, io, re, json, tempfile
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from models import ParsedEvent

SSH_RE=re.compile(r"(?:sshd(?:\[\d+\])?:\s*)?(Failed password|Accepted (?:password|publickey)|Invalid user)\s+(?:for\s+)?(?P<user>[\w.@-]+)(?:\s+from\s+(?P<ip>[0-9a-fA-F:.]+))?(?:\s+port\s+(?P<port>\d+))?",re.I)
SUDO_RE=re.compile(r"sudo:\s+(?P<user>[\w.-]+).*?(?:authentication failure|COMMAND=)",re.I)
WEB_RE=re.compile(r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+[^\"]+"\s+(?P<status>\d{3})\s+(?P<size>\S+)')
WEB_ERROR_RE=re.compile(r"^\[(?P<time>[^\]]+)\]\s+\[(?P<level>\w+)\](?:\s+\[pid \d+(?::tid \d+)?\])?\s*(?P<message>.*)$",re.I)
NGINX_ERROR_RE=re.compile(r"^(?P<time>\d{4}/\d\d/\d\d \d\d:\d\d:\d\d)\s+\[(?P<level>\w+)\]\s+(?P<message>.*)$",re.I)

def severity_for(event_type,status=None,http_status=None,path=None):
    if status in {'Failed','Error'} or event_type in {'Invalid User','Sudo Authentication Failure'}: return 'Medium'
    if http_status and http_status>=500:return 'High'
    if http_status in {401,403} or path and any(x in path.lower() for x in ('/admin','/.env','/wp-login.php','/etc/passwd')):return 'Medium'
    return 'Low'
def parse_timestamp(value):
    if not value:return None
    normalized=value.strip().replace('Z','+00:00')
    try:
        parsed=datetime.fromisoformat(normalized)
        return parsed.astimezone(timezone.utc).replace(tzinfo=None) if parsed.tzinfo else parsed
    except ValueError:pass
    for fmt in ('%Y-%m-%d %H:%M:%S','%Y-%m-%dT%H:%M:%S','%d/%b/%Y:%H:%M:%S %z','%a %b %d %H:%M:%S %Y'):
        try:return datetime.strptime(value.strip(),fmt).replace(tzinfo=None)
        except (ValueError,AttributeError):pass
    return None
def _time_and_payload(line):
    line=line.strip(); m=re.match(r'^(\d{4}-\d\d-\d\d[ T]\d\d:\d\d:\d\d)\s+(.*)$',line)
    if m:return parse_timestamp(m.group(1)),m.group(2)
    syslog=re.match(r'^(?P<stamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d)\s+\S+\s+(?P<payload>.*)$',line)
    if syslog:
        try: stamp=datetime.strptime(f"{datetime.now().year} {syslog.group('stamp')}",'%Y %b %d %H:%M:%S')
        except ValueError: stamp=None
        return stamp,syslog.group('payload')
    return None,line
def parse_linux_line(line):
    timestamp,payload=_time_and_payload(line); m=SSH_RE.search(payload)
    if m:
        action=m.group(1).lower(); typ='Invalid User' if 'invalid' in action else 'Login'; status='Success' if 'accepted' in action else 'Failed'
        return ParsedEvent(timestamp,'Linux Auth',m.group('ip'),m.group('user'),typ,status,severity_for(typ,status),int(m.group('port')) if m.group('port') else None,raw_line=line.strip()[:2000])
    m=SUDO_RE.search(payload)
    if m:return ParsedEvent(timestamp,'Linux Auth',None,m.group('user'),'Sudo Authentication Failure','Failed',severity_for('Sudo Authentication Failure','Failed'),raw_line=line.strip()[:2000])
    if 'systemd[' in payload or 'journal' in payload.lower(): return ParsedEvent(timestamp,'Systemd Journal',None,None,'System Journal','Info','Low',raw_line=line.strip()[:2000])
    return None
def parse_web_line(line):
    line=line.strip(); m=WEB_RE.match(line)
    if m:
        code=int(m.group('status')); size=m.group('size')
        return ParsedEvent(parse_timestamp(m.group('time')),'Web Access',m.group('ip'),None,'HTTP Request','Error' if code>=400 else 'Success',severity_for('HTTP Request','Error' if code>=400 else 'Success',code,m.group('path')),method=m.group('method'),path=m.group('path'),http_status=code,response_size=int(size) if size.isdigit() else None,raw_line=line[:2000])
    m=WEB_ERROR_RE.match(line) or NGINX_ERROR_RE.match(line)
    if m:
        time_value=m.group('time').replace('/','-',2)
        return ParsedEvent(parse_timestamp(time_value),'Web Error',None,None,'HTTP Error',m.group('level').title(), 'High' if m.group('level').lower() in {'error','crit','alert','emerg'} else 'Medium',raw_line=line[:2000])
    return None
def parse_csv_text(text):
    csv.field_size_limit(64 * 1024)
    reader=csv.DictReader(io.StringIO(text)); fields={x.strip().lower() for x in (reader.fieldnames or []) if x}
    if not fields: raise ValueError('ملف CSV فارغ أو لا يحتوي صف عناوين.')
    if not ({'timestamp','event_type'} <= fields or {'time','message'} <= fields or {'eventid','timecreated'} <= fields): raise ValueError('CSV يحتاج timestamp وevent_type، أو time وmessage، أو EventID وTimeCreated لسجل Windows.')
    events=[]
    for line_number,row in enumerate(reader,2):
        row={str(k).strip().lower():(v or '').strip() for k,v in row.items()}; eid=row.get('eventid') or row.get('event_id'); typ=row.get('event_type') or (f'Windows Event {eid}' if eid else 'CSV Event'); status=row.get('status') or row.get('level') or 'Info'; code=int(row['http_status']) if row.get('http_status','').isdigit() else None
        timestamp=parse_timestamp(row.get('timestamp') or row.get('time') or row.get('timecreated'))
        if eid:
            data={'IpAddress':row.get('ipaddress') or row.get('source_ip'),'TargetUserName':row.get('targetusername') or row.get('username')}
            event=_win(eid,row.get('provider') or row.get('source'),row.get('computer'),timestamp,data,str(row))
            event.line_number=line_number; events.append(event); continue
        events.append(ParsedEvent(timestamp,row.get('provider') or row.get('source') or 'CSV',row.get('source_ip') or row.get('ipaddress') or None,row.get('username') or row.get('targetusername') or None,typ,status,row.get('severity') or severity_for(typ,status,code,row.get('path')),port=int(row['port']) if row.get('port','').isdigit() else None,method=row.get('method') or None,path=row.get('path') or None,http_status=code,raw_line=str(row)[:2000],provider=row.get('provider'),event_id=eid,computer=row.get('computer'),line_number=line_number))
    return events
def parse_file_text(text,filename):
    """يرجع events وملخصًا واضحًا يبيّن السطور المرفوضة وأسبابها."""
    lines=text.splitlines(); events=[]; rejected=[]
    if len(lines)>100000: raise ValueError('الملف يحتوي أكثر من 100,000 سطر؛ قسّميه إلى ملفات أصغر لحماية الخادم.')
    if filename.lower().endswith('.csv'):
        events=parse_csv_text(text); return events,{'total_lines':len(lines),'parsed_lines':len(events),'rejected_lines':max(0,len(lines)-1-len(events)),'rejections':[]}
    if filename.lower().endswith('.xml'):
        events=parse_windows_xml(text); return events,{'total_lines':len(lines),'parsed_lines':len(events),'rejected_lines':0,'rejections':[]}
    if filename.lower().endswith('.json'):
        events=parse_windows_json(text); return events,{'total_lines':len(lines),'parsed_lines':len(events),'rejected_lines':0,'rejections':[]}
    for number,raw in enumerate(lines,1):
        line=raw.strip()
        if not line: continue
        if len(line)>64*1024:
            rejected.append({'line':number,'reason':'السطر أطول من الحد الآمن (64KB).'}); continue
        event=parse_linux_line(line) or parse_web_line(line)
        if event:event.line_number=number; events.append(event)
        else:rejected.append({'line':number,'reason':'صيغة غير مدعومة أو غير مكتملة.'})
    return events,{'total_lines':len(lines),'parsed_lines':len(events),'rejected_lines':len(rejected),'rejections':rejected[:20]}

def _win(eid,provider,computer,time,data,raw):
    mapping={'4624':('Windows Login','Success','Low'),'4625':('Windows Login','Failed','Medium'),'4672':('Special Privileges Assigned','Success','Medium'),'4688':('Process Creation','Info','Medium'),'7045':('Service Installation','Info','High'),'1102':('Audit Log Cleared','Success','High')}
    typ,status,severity=mapping.get(str(eid),(f'Windows Event {eid}','Info','Low'))
    if 'powershell' in (provider or '').lower() and re.search(r'(?i)(-enc|encodedcommand)',raw):typ,severity='PowerShell Encoded Command','High'
    return ParsedEvent(time,'Windows '+(provider or 'Event Log'),data.get('IpAddress') or data.get('SourceNetworkAddress'),data.get('TargetUserName') or data.get('SubjectUserName'),typ,status,severity,raw_line=raw[:2000],provider=provider,event_id=str(eid),computer=computer)
def parse_windows_xml(text):
    try: root=ET.fromstring(text)
    except ET.ParseError as exc: raise ValueError(f'ملف Windows XML غير صالح: {exc}')
    nodes=[root] if root.tag.endswith('Event') else [x for x in root.iter() if x.tag.endswith('Event')]; out=[]
    for node in nodes:
        eid=next((x.text for x in node.iter() if x.tag.endswith('EventID')),None); provider=next((x.attrib.get('Name') for x in node.iter() if x.tag.endswith('Provider')),None); computer=next((x.text for x in node.iter() if x.tag.endswith('Computer')),None); created=next((x.attrib.get('SystemTime') for x in node.iter() if x.tag.endswith('TimeCreated')),None); data={x.attrib.get('Name',''):x.text or '' for x in node.iter() if x.tag.endswith('Data')}
        if eid: out.append(_win(eid,provider,computer,parse_timestamp((created or '').replace('Z','').split('.')[0]),data,ET.tostring(node,encoding='unicode')))
    return out
def parse_windows_json(text):
    try: rows=json.loads(text)
    except json.JSONDecodeError as exc: raise ValueError(f'ملف JSON غير صالح: {exc}')
    if isinstance(rows,dict):rows=rows.get('events') or rows.get('value') or [rows]
    if not isinstance(rows,list):raise ValueError('JSON يجب أن يحتوي على حدث أو قائمة أحداث.')
    return [_win(x.get('EventID') or x.get('event_id'),x.get('ProviderName') or x.get('provider'),x.get('Computer') or x.get('computer'),parse_timestamp(str(x.get('TimeCreated') or x.get('timestamp') or '').replace('Z','').split('.')[0]),x.get('EventData') or x,json.dumps(x,ensure_ascii=False)) for x in rows if isinstance(x,dict) and (x.get('EventID') or x.get('event_id'))]

def parse_evtx_bytes(content):
    try: from Evtx.Evtx import Evtx
    except ImportError: raise ValueError('تعذر تحليل EVTX لأن python-evtx غير مثبت. صدّري السجل من Event Viewer بصيغة XML أو CSV ثم ارفعيه.')
    events=[]
    with tempfile.NamedTemporaryFile(suffix='.evtx') as temp:
        temp.write(content); temp.flush()
        with Evtx(temp.name) as log:
            for number,record in enumerate(log.records(),1):
                if number>50000: raise ValueError('ملف EVTX يحتوي أكثر من 50,000 سجل؛ صدّريه على دفعات أصغر.')
                parsed=parse_windows_xml(record.xml())
                for event in parsed:event.line_number=number
                events.extend(parsed)
    return events
