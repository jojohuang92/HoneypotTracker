"""MITRE ATT&CK technique → tactic mapping.

Only includes techniques the honeypot actually classifies. Names follow the
official MITRE ATT&CK for Enterprise v14 catalog.
"""

from __future__ import annotations

# Tactic order matches MITRE Navigator column order
TACTICS: list[tuple[str, str]] = [
    ("reconnaissance", "Reconnaissance"),
    ("resource-development", "Resource Development"),
    ("initial-access", "Initial Access"),
    ("execution", "Execution"),
    ("persistence", "Persistence"),
    ("privilege-escalation", "Privilege Escalation"),
    ("defense-evasion", "Defense Evasion"),
    ("credential-access", "Credential Access"),
    ("discovery", "Discovery"),
    ("lateral-movement", "Lateral Movement"),
    ("collection", "Collection"),
    ("command-and-control", "Command and Control"),
    ("exfiltration", "Exfiltration"),
    ("impact", "Impact"),
]

TACTIC_NAME_BY_ID: dict[str, str] = dict(TACTICS)

# technique_id → (technique_name, tactic_id)
TECHNIQUES: dict[str, tuple[str, str]] = {
    # Reconnaissance / Discovery
    "T1592": ("Gather Victim Host Information", "reconnaissance"),
    "T1595": ("Active Scanning", "reconnaissance"),
    "T1046": ("Network Service Discovery", "discovery"),
    "T1082": ("System Information Discovery", "discovery"),
    "T1087": ("Account Discovery", "discovery"),
    "T1033": ("System Owner/User Discovery", "discovery"),
    "T1016": ("System Network Configuration Discovery", "discovery"),
    "T1049": ("System Network Connections Discovery", "discovery"),
    "T1057": ("Process Discovery", "discovery"),
    "T1083": ("File and Directory Discovery", "discovery"),

    # Initial Access / Credential Access
    "T1110": ("Brute Force", "credential-access"),
    "T1003": ("OS Credential Dumping", "credential-access"),
    "T1003.008": ("OS Credential Dumping: /etc/passwd and /etc/shadow", "credential-access"),
    "T1552": ("Unsecured Credentials", "credential-access"),
    "T1552.001": ("Unsecured Credentials: Credentials In Files", "credential-access"),
    "T1552.003": ("Unsecured Credentials: Bash History", "credential-access"),
    "T1552.004": ("Unsecured Credentials: Private Keys", "credential-access"),

    # Execution
    "T1059": ("Command and Scripting Interpreter", "execution"),
    "T1059.004": ("Command and Scripting Interpreter: Unix Shell", "execution"),

    # Persistence
    "T1053": ("Scheduled Task/Job", "persistence"),
    "T1053.003": ("Scheduled Task/Job: Cron", "persistence"),
    "T1037": ("Boot or Logon Initialization Scripts", "persistence"),
    "T1098": ("Account Manipulation", "persistence"),
    "T1098.004": ("Account Manipulation: SSH Authorized Keys", "persistence"),

    # Defense Evasion
    "T1222": ("File and Directory Permissions Modification", "defense-evasion"),
    "T1070": ("Indicator Removal", "defense-evasion"),
    "T1070.002": ("Indicator Removal: Clear Linux/Mac Logs", "defense-evasion"),
    "T1070.003": ("Indicator Removal: Clear Command History", "defense-evasion"),
    "T1562": ("Impair Defenses", "defense-evasion"),
    "T1562.004": ("Impair Defenses: Disable or Modify System Firewall", "defense-evasion"),
    "T1027": ("Obfuscated Files or Information", "defense-evasion"),

    # Command and Control
    "T1105": ("Ingress Tool Transfer", "command-and-control"),

    # Lateral Movement
    "T1021": ("Remote Services", "lateral-movement"),

    # Exfiltration
    "T1041": ("Exfiltration Over C2 Channel", "exfiltration"),

    # Impact
    "T1489": ("Service Stop", "impact"),
    "T1485": ("Data Destruction", "impact"),
    "T1496": ("Resource Hijacking", "impact"),
}


def tactic_for(mitre_id: str) -> str | None:
    """Return the tactic ID for a technique ID, falling back to the parent technique."""
    entry = TECHNIQUES.get(mitre_id)
    if entry:
        return entry[1]
    # Try the parent technique (e.g., T1003.008 → T1003)
    parent = mitre_id.split(".")[0]
    entry = TECHNIQUES.get(parent)
    return entry[1] if entry else None


def technique_name_for(mitre_id: str) -> str:
    entry = TECHNIQUES.get(mitre_id)
    if entry:
        return entry[0]
    parent = mitre_id.split(".")[0]
    entry = TECHNIQUES.get(parent)
    return entry[0] if entry else mitre_id
