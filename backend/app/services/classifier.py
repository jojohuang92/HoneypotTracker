"""Rule-based intent classifier mapping Cowrie commands to MITRE ATT&CK techniques."""

import re

# Pattern → (intent, MITRE ATT&CK ID)
# Order matters: first match wins. More specific patterns go first.
COMMAND_RULES: list[tuple[str, str, str]] = [
    # Cryptomining
    (r"xmrig|minexmr|hashvault|cryptonight|stratum\+tcp|kdevtmpfsi|kinsing", "cryptomining", "T1496"),

    # Malware deployment (download + execute patterns)
    (r"wget\s+http|curl\s+.*http.*\|\s*sh|curl\s+-[oO].*http|tftp\s+-g", "malware_deployment", "T1105"),
    (r"chmod\s+\+x\s+/tmp|chmod\s+777", "malware_deployment", "T1222"),
    (r"\./[a-z0-9_.]+\s*$|/tmp/\.[a-z]", "malware_deployment", "T1059.004"),
    (r"busybox\s+wget|busybox\s+tftp", "malware_deployment", "T1105"),

    # Obfuscated execution
    (r"base64\s+-d|base64\s+--decode|\|\s*base64\b", "malware_deployment", "T1027"),

    # Persistence
    (r"crontab|/var/spool/cron|/etc/cron", "persistence", "T1053.003"),
    (r"authorized_keys", "persistence", "T1098.004"),
    (r"(chattr|lockr)\s+[-+][ai]+\s+[^\s]*\.ssh", "persistence", "T1098.004"),
    (r"chattr\s+\+i", "persistence", "T1222"),
    (r"nohup\s+.*&|setsid|disown", "persistence", "T1053"),
    (r"/etc/rc\.local|/etc/init\.d|systemctl\s+enable", "persistence", "T1037"),

    # Credential theft
    (r"cat\s+/etc/shadow|/etc/shadow", "credential_theft", "T1003.008"),
    (r"\.ssh/id_rsa|\.pem|\.key", "credential_theft", "T1552.004"),
    (r"\.bash_history|\.mysql_history", "credential_theft", "T1552.003"),
    (r"my\.cnf|\.pgpass|\.env", "credential_theft", "T1552.001"),

    # Sabotage / anti-forensics
    (r"rm\s+-rf\s+/var/log|rm\s+.*\.log", "sabotage", "T1070.002"),
    (r"history\s+-c|unset\s+HISTFILE", "sabotage", "T1070.003"),
    (r"iptables\s+-F|ufw\s+disable", "sabotage", "T1562.004"),
    (r"pkill|killall|kill\s+-9", "sabotage", "T1489"),

    # Reconnaissance (broad patterns — checked last)
    (r"uname|cat\s+/proc/cpuinfo|cat\s+/etc/issue|lsb_release|\barch\b", "reconnaissance", "T1082"),
    (r"\blscpu\b|\bnproc\b|cat\s+/proc/(uptime|meminfo|version|stat|loadavg)", "reconnaissance", "T1082"),
    (r"\buptime\b|\bssh\s+-V\b", "reconnaissance", "T1082"),
    (r"echo\s+-[neE]+\s+[\"']?[^\"']*\\x[0-9a-fA-F]", "reconnaissance", "T1082"),
    (r"/ip\s+(cloud|route|firewall|address)\s+print|/system\s+(resource|identity)", "reconnaissance", "T1082"),
    (r"cat\s+/etc/passwd|/etc/group|lastlog|\blast\b", "reconnaissance", "T1087"),
    # (?<![\w-]) blocks flag look-alikes: "grep -w" must not match the "w" rule,
    # and words like "droid" or "rapid" must not match the "id" rule.
    (r"whoami\b|(?<![\w-])id\b|(?<![\w-])w\b", "reconnaissance", "T1033"),
    (r"ifconfig|ip\s+addr|ip\s+route|hostname", "reconnaissance", "T1016"),
    (r"netstat|ss\s+-", "reconnaissance", "T1049"),
    (r"ps\s+aux|ps\s+-ef|top\b", "reconnaissance", "T1057"),
    (r"df\s+-|free\s+-|du\s+-|mount\b", "reconnaissance", "T1082"),
    (r"\bwhich\s+\w+|\bcommand\s+-v\s+\w+", "reconnaissance", "T1083"),
    (r"for\s+\w+\s+in\s+[^;]*(\$HOME|/var/tmp|/dev/shm|/tmp)", "reconnaissance", "T1083"),
    (r"\bls\b|\bpwd\b|\bfind\s|\blocate\s", "reconnaissance", "T1083"),
    (r"^\s*history\s*$|history\s*\|", "reconnaissance", "T1552.003"),
    (r"^\s*env\s*$|\benv\s*\|", "reconnaissance", "T1082"),
]

# Pre-compile for speed
_COMPILED_RULES = [(re.compile(pattern, re.IGNORECASE), intent, mitre_id)
                   for pattern, intent, mitre_id in COMMAND_RULES]


def classify_command(command: str) -> tuple[str, str]:
    """Classify a command string into an intent and MITRE ATT&CK technique ID.

    Returns:
        (intent, mitre_id) tuple. Defaults to ("unknown", "T1059") if no match.
    """
    if not command:
        return ("unknown", "T1059")

    for regex, intent, mitre_id in _COMPILED_RULES:
        if regex.search(command):
            return (intent, mitre_id)

    return ("unknown", "T1059")


def classify_login(success: bool) -> tuple[str, str]:
    """Classify a login attempt."""
    return ("brute_force", "T1110")
