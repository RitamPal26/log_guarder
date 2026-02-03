from dataclasses import dataclass
from typing import Optional

@dataclass
class LogEntry:
    timestamp: str
    status: str
    username: str
    ip_address: str
    raw_content: str
