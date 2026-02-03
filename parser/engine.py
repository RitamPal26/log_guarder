import re
from typing import Optional
from .models import LogEntry

# Regex with named capture groups to avoid hardcoding indices
LOG_PATTERN = r"(?P<timestamp>\w{3}\s+\d+\s\d{2}:\d{2}:\d{2}).*?(?P<status>Failed|Accepted)\s+password\s+for\s+(?:invalid\s+user\s+)?(?P<user>.*?)\s+from\s+(?P<ip>\S+)"
def parse_line(line: str) -> Optional[LogEntry]:
    line = line.strip()
    match = re.search(LOG_PATTERN, line)
    
    if not match:
        return None
        
    return LogEntry(
        timestamp=match.group("timestamp"),
        status=match.group("status"),
        username=match.group("user"),
        ip_address=match.group("ip"),
        raw_content=line
    )
