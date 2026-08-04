"""تعريفات بسيطة للبيانات المتبادلة بين محلل السجلات وقاعدة البيانات."""
from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass
class ParsedEvent:
    timestamp: Optional[datetime]
    source: str
    source_ip: Optional[str]
    username: Optional[str]
    event_type: str
    status: Optional[str]
    severity: str = "Low"
    port: Optional[int] = None
    method: Optional[str] = None
    path: Optional[str] = None
    http_status: Optional[int] = None
    response_size: Optional[int] = None
    raw_line: str = ""
    provider: Optional[str] = None
    event_id: Optional[str] = None
    computer: Optional[str] = None
    line_number: Optional[int] = None
