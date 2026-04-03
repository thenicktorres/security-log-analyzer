import re
from datetime import datetime

# Example auth.log line:
# Jan 10 10:15:01 server sshd[12345]: Failed password for invalid user admin from 192.168.1.10 port 22 ssh2

LOG_PATTERN = re.compile(
    r'^(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+) '
    r'(?P<hostname>\S+) '
    r'(?P<process>\S+)\[\d+\]: '
    r'(?P<status>Failed|Accepted).* for (invalid user )?(?P<username>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)'
)

def parse_log_line(line, year=None):
    match = LOG_PATTERN.search(line)
    if match:
        data = match.groupdict()
        try:
            # Add year because auth.log doesn't include it
            timestamp_str = data['timestamp']
            if year:
                timestamp = datetime.strptime(f"{year} {timestamp_str}", "%Y %b %d %H:%M:%S")
            else:
                timestamp = datetime.strptime(timestamp_str, "%b %d %H:%M:%S")
            
            return {
                "timestamp": timestamp,
                "hostname": data["hostname"],
                "process": data["process"],
                "status": data["status"],
                "username": data["username"],
                "ip": data["ip"]
            }
        except Exception:
            return None
    return None


def parse_log_file(file_path, year=None):
    """Generator to read file line-by-line"""
    try:
        with open(file_path, "r") as file:
            for line in file:
                parsed = parse_log_line(line, year)
                if parsed:
                    yield parsed
    except FileNotFoundError:
        print(f"[ERROR] Log file not found: {file_path}")
    except Exception as e:
        print(f"[ERROR] Failed to read log file: {e}")