import os
import tempfile
import unittest

from app import create_app
from auth import authenticate_user
from database import init_db, add_rule, set_default_policy, toggle_rule
from firewall_engine import evaluate_packet


class FirewallRuleEngineTestCase(unittest.TestCase):
    def setUp(self):
        """Creates an isolated temporary SQLite database before each test."""
        self.db_fd, self.db_path = tempfile.mkstemp(suffix=".db")
        init_db(db_path=self.db_path, seed_data=True)
        self.app = create_app(db_path=self.db_path, seed_data=True)
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    def tearDown(self):
        """Removes the temporary test database after each test."""
        os.close(self.db_fd)
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    # 1. Allowed IP & CIDR Matching
    def test_allowed_ip_and_cidr_matching(self):
        packet = {
            "source_ip": "192.168.1.42",
            "dest_ip": "10.0.0.25",
            "source_port": 51000,
            "dest_port": 22,
            "protocol": "TCP",
            "direction": "INBOUND",
        }
        result = evaluate_packet(packet, db_path=self.db_path)
        self.assertTrue(result["valid"])
        self.assertEqual(result["decision"], "ALLOW")
        self.assertIn("SSH from Admin LAN", result["matched_rule"]["description"])

    # 2. Blocked IP Address
    def test_blocked_malicious_ip(self):
        packet = {
            "source_ip": "203.0.113.50",
            "dest_ip": "10.0.0.10",
            "source_port": 49152,
            "dest_port": 443,
            "protocol": "TCP",
            "direction": "INBOUND",
        }
        result = evaluate_packet(packet, db_path=self.db_path)
        self.assertTrue(result["valid"])
        self.assertEqual(result["decision"], "DENY")
        self.assertEqual(result["matched_rule"]["priority"], 10)

    # 3. Port Restrictions (Exact Port & Port Range)
    def test_port_restriction_exact_and_range(self):
        telnet_packet = {
            "source_ip": "192.168.1.50",
            "dest_ip": "10.0.0.10",
            "source_port": 50000,
            "dest_port": 23,
            "protocol": "TCP",
            "direction": "INBOUND",
        }
        res_telnet = evaluate_packet(telnet_packet, db_path=self.db_path)
        self.assertEqual(res_telnet["decision"], "DENY")

        add_rule({
            "source_ip": "ANY",
            "dest_ip": "10.0.0.20",
            "source_port": "ANY",
            "dest_port": "8000-8080",
            "protocol": "TCP",
            "direction": "INBOUND",
            "action": "ALLOW",
            "priority": 15,
            "description": "Allow dev app range",
            "is_enabled": 1,
        }, db_path=self.db_path)

        range_packet = {
            "source_ip": "198.51.100.5",
            "dest_ip": "10.0.0.20",
            "source_port": 55555,
            "dest_port": 8050,
            "protocol": "TCP",
            "direction": "INBOUND",
        }
        res_range = evaluate_packet(range_packet, db_path=self.db_path)
        self.assertEqual(res_range["decision"], "ALLOW")

    # 4. Protocol-Based Filtering (UDP & ICMP)
    def test_protocol_filtering(self):
        dns_packet = {
            "source_ip": "192.168.1.12",
            "dest_ip": "8.8.8.8",
            "source_port": 53000,
            "dest_port": 53,
            "protocol": "UDP",
            "direction": "OUTBOUND",
        }
        self.assertEqual(evaluate_packet(dns_packet, db_path=self.db_path)["decision"], "ALLOW")

        tcp_dns_packet = dict(dns_packet, protocol="TCP")
        self.assertEqual(evaluate_packet(tcp_dns_packet, db_path=self.db_path)["decision"], "DENY")

        icmp_packet = {
            "source_ip": "192.168.1.10",
            "dest_ip": "10.0.0.10",
            "source_port": "",
            "dest_port": "",
            "protocol": "ICMP",
            "direction": "INBOUND",
        }
        self.assertEqual(evaluate_packet(icmp_packet, db_path=self.db_path)["decision"], "ALLOW")

    # 5. Rule Priority Conflicts & Disabled Rules
    def test_priority_conflict_and_disabled_rule(self):
        high_prio_id = add_rule({
            "source_ip": "10.10.10.10",
            "dest_ip": "10.0.0.99",
            "source_port": "ANY",
            "dest_port": "9000",
            "protocol": "TCP",
            "direction": "INBOUND",
            "action": "DENY",
            "priority": 5,
            "description": "High priority DENY override",
            "is_enabled": 1,
        }, db_path=self.db_path)

        add_rule({
            "source_ip": "10.10.10.10",
            "dest_ip": "10.0.0.99",
            "source_port": "ANY",
            "dest_port": "9000",
            "protocol": "TCP",
            "direction": "INBOUND",
            "action": "ALLOW",
            "priority": 100,
            "description": "Low priority ALLOW rule",
            "is_enabled": 1,
        }, db_path=self.db_path)

        packet = {
            "source_ip": "10.10.10.10",
            "dest_ip": "10.0.0.99",
            "source_port": 40000,
            "dest_port": 9000,
            "protocol": "TCP",
            "direction": "INBOUND",
        }

        res1 = evaluate_packet(packet, db_path=self.db_path)
        self.assertEqual(res1["decision"], "DENY")
        self.assertEqual(res1["matched_rule"]["priority"], 5)

        toggle_rule(high_prio_id, db_path=self.db_path)
        res2 = evaluate_packet(packet, db_path=self.db_path)
        self.assertEqual(res2["decision"], "ALLOW")
        self.assertEqual(res2["matched_rule"]["priority"], 100)

    # 6. Configurable Default Policy
    def test_default_policy_handling(self):
        unmatched_packet = {
            "source_ip": "172.16.5.5",
            "dest_ip": "10.0.0.88",
            "source_port": 55000,
            "dest_port": 3306,
            "protocol": "TCP",
            "direction": "INBOUND",
        }

        res_deny = evaluate_packet(unmatched_packet, db_path=self.db_path)
        self.assertTrue(res_deny["default_policy_applied"])
        self.assertEqual(res_deny["decision"], "DENY")

        set_default_policy("ALLOW", db_path=self.db_path)
        res_allow = evaluate_packet(unmatched_packet, db_path=self.db_path)
        self.assertTrue(res_allow["default_policy_applied"])
        self.assertEqual(res_allow["decision"], "ALLOW")

    # 7. Invalid Packet Details
    def test_invalid_packet_details_rejected(self):
        invalid_packet = {
            "source_ip": "999.999.1.1",
            "dest_ip": "10.0.0.10",
            "source_port": 70000,
            "dest_port": 80,
            "protocol": "HTTP",
            "direction": "SIDEWAYS",
        }
        result = evaluate_packet(invalid_packet, db_path=self.db_path)
        self.assertFalse(result["valid"])
        self.assertEqual(result["decision"], "INVALID")
        self.assertGreaterEqual(len(result["errors"]), 3)

    # 8. SQL Injection Prevention & Login Security
    def test_sql_injection_cannot_bypass_login(self):
        sqli_payloads = [
            "' OR '1'='1' --",
            "admin' --",
            "' OR 1=1 --",
            "'; DROP TABLE users; --",
        ]

        for payload in sqli_payloads:
            ok, user, _ = authenticate_user(payload, "anything", db_path=self.db_path)
            self.assertFalse(ok, f"SQLi payload bypassed auth: {payload}")
            self.assertIsNone(user)

            response = self.client.post(
                "/login",
                data={"username": payload, "password": "wrongpassword"},
                follow_redirects=True,
            )
            self.assertIn(b"Invalid username or password", response.data)

        ok, user, _ = authenticate_user("admin", "Admin@123", db_path=self.db_path)
        self.assertTrue(ok)
        self.assertEqual(user["username"], "admin")

    def test_unauthenticated_access_is_blocked(self):
        response = self.client.get("/rules", follow_redirects=False)
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.headers["Location"])


if __name__ == "__main__":
    unittest.main()