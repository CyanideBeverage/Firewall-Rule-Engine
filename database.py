"""
SQLite database layer for the Firewall Rule Engine.
All database queries strictly use parameterized placeholders (?) to prevent SQL Injection.
"""

import sqlite3
from datetime import datetime
from werkzeug.security import generate_password_hash
from config import Config


def get_db_connection(db_path: str = None) -> sqlite3.Connection:
    """Opens a SQLite connection with dictionary-like row access."""
    path = db_path or Config.DATABASE_PATH
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: str = None, seed_data: bool = True) -> None:
    """
    Creates database tables if they do not exist and optionally seeds:
      - Default admin user (with hashed password)
      - Default fallback policy setting ('DENY')
      - Realistic starter firewall rules for immediate demonstration
    """
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS firewall_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_ip TEXT NOT NULL,
            dest_ip TEXT NOT NULL,
            source_port TEXT NOT NULL,
            dest_port TEXT NOT NULL,
            protocol TEXT NOT NULL,
            direction TEXT NOT NULL,
            action TEXT NOT NULL,
            priority INTEGER NOT NULL,
            description TEXT NOT NULL,
            is_enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS packet_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            dest_ip TEXT NOT NULL,
            source_port TEXT NOT NULL,
            dest_port TEXT NOT NULL,
            protocol TEXT NOT NULL,
            direction TEXT NOT NULL,
            decision TEXT NOT NULL,
            matched_rule_id INTEGER,
            matched_rule_desc TEXT NOT NULL,
            reason TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    """)

    cursor.execute(
        "INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)",
        ("default_policy", Config.DEFAULT_POLICY),
    )

    if seed_data:
        cursor.execute("SELECT COUNT(*) AS cnt FROM users")
        if cursor.fetchone()["cnt"] == 0:
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute(
                "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
                (
                    Config.DEFAULT_ADMIN_USERNAME,
                    generate_password_hash(Config.DEFAULT_ADMIN_PASSWORD),
                    now,
                ),
            )

        cursor.execute("SELECT COUNT(*) AS cnt FROM firewall_rules")
        if cursor.fetchone()["cnt"] == 0:
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            sample_rules = [
                ("203.0.113.50", "ANY", "ANY", "ANY", "ANY", "INBOUND", "DENY", 10,
                 "Block known malicious external host", 1, now),
                ("ANY", "10.0.0.10", "ANY", "443", "TCP", "INBOUND", "ALLOW", 20,
                 "Allow inbound HTTPS traffic to Web Server", 1, now),
                ("ANY", "10.0.0.10", "ANY", "80", "TCP", "INBOUND", "ALLOW", 30,
                 "Allow inbound HTTP traffic to Web Server", 1, now),
                ("192.168.1.0/24", "10.0.0.0/24", "ANY", "22", "TCP", "INBOUND", "ALLOW", 40,
                 "Allow SSH from Admin LAN subnet only", 1, now),
                ("ANY", "10.0.0.0/24", "ANY", "22", "TCP", "INBOUND", "DENY", 50,
                 "Deny unauthorized SSH access from external networks", 1, now),
                ("192.168.1.0/24", "ANY", "ANY", "53", "UDP", "OUTBOUND", "ALLOW", 60,
                 "Allow outbound DNS resolution from internal LAN", 1, now),
                ("ANY", "ANY", "ANY", "23", "TCP", "INBOUND", "DENY", 70,
                 "Block legacy unencrypted Telnet traffic", 1, now),
                ("192.168.1.0/24", "10.0.0.0/24", "ANY", "ANY", "ICMP", "INBOUND", "ALLOW", 80,
                 "Allow ICMP ping from Admin LAN to server subnet", 1, now),
            ]
            cursor.executemany("""
                INSERT INTO firewall_rules (
                    source_ip, dest_ip, source_port, dest_port, protocol,
                    direction, action, priority, description, is_enabled, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, sample_rules)

    conn.commit()
    conn.close()


# ---------------------------
# User Queries
# ---------------------------

def get_user_by_username(username: str, db_path: str = None):
    """Fetches a user safely using a parameterized query."""
    conn = get_db_connection(db_path)
    user = conn.execute(
        "SELECT id, username, password_hash, created_at FROM users WHERE username = ?",
        (username,),
    ).fetchone()
    conn.close()
    return dict(user) if user else None


def create_user(username: str, password: str, db_path: str = None) -> int:
    """Creates a new user with a securely hashed password."""
    conn = get_db_connection(db_path)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor = conn.execute(
        "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
        (username, generate_password_hash(password), now),
    )
    user_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return user_id


# ---------------------------
# Settings (Default Policy)
# ---------------------------

def get_default_policy(db_path: str = None) -> str:
    """Retrieves the configured default policy ('DENY' or 'ALLOW')."""
    conn = get_db_connection(db_path)
    row = conn.execute(
        "SELECT value FROM settings WHERE key = ?",
        ("default_policy",),
    ).fetchone()
    conn.close()
    return row["value"] if row else Config.DEFAULT_POLICY


def set_default_policy(policy: str, db_path: str = None) -> None:
    """Updates the default policy safely."""
    normalized = policy.strip().upper()
    if normalized not in ("ALLOW", "DENY"):
        raise ValueError("Default policy must be 'ALLOW' or 'DENY'.")
    conn = get_db_connection(db_path)
    conn.execute(
        "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
        ("default_policy", normalized),
    )
    conn.commit()
    conn.close()


# ---------------------------
# Firewall Rule Queries
# ---------------------------

def get_all_rules(db_path: str = None) -> list:
    """Returns all firewall rules sorted by priority ascending (highest precedence first)."""
    conn = get_db_connection(db_path)
    rows = conn.execute(
        "SELECT * FROM firewall_rules ORDER BY priority ASC, id ASC"
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_enabled_rules(db_path: str = None) -> list:
    """Returns only enabled rules sorted by priority ascending."""
    conn = get_db_connection(db_path)
    rows = conn.execute(
        "SELECT * FROM firewall_rules WHERE is_enabled = 1 ORDER BY priority ASC, id ASC"
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_rule_by_id(rule_id: int, db_path: str = None):
    """Returns a single firewall rule by ID."""
    conn = get_db_connection(db_path)
    row = conn.execute(
        "SELECT * FROM firewall_rules WHERE id = ?",
        (rule_id,),
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def add_rule(rule_data: dict, db_path: str = None) -> int:
    """Inserts a validated firewall rule into SQLite."""
    conn = get_db_connection(db_path)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor = conn.execute("""
        INSERT INTO firewall_rules (
            source_ip, dest_ip, source_port, dest_port, protocol,
            direction, action, priority, description, is_enabled, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        rule_data["source_ip"],
        rule_data["dest_ip"],
        rule_data["source_port"],
        rule_data["dest_port"],
        rule_data["protocol"],
        rule_data["direction"],
        rule_data["action"],
        rule_data["priority"],
        rule_data["description"],
        rule_data.get("is_enabled", 1),
        now,
    ))
    rule_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return rule_id


def update_rule(rule_id: int, rule_data: dict, db_path: str = None) -> bool:
    """Updates an existing firewall rule."""
    conn = get_db_connection(db_path)
    cursor = conn.execute("""
        UPDATE firewall_rules
        SET source_ip = ?, dest_ip = ?, source_port = ?, dest_port = ?,
            protocol = ?, direction = ?, action = ?, priority = ?,
            description = ?, is_enabled = ?
        WHERE id = ?
    """, (
        rule_data["source_ip"],
        rule_data["dest_ip"],
        rule_data["source_port"],
        rule_data["dest_port"],
        rule_data["protocol"],
        rule_data["direction"],
        rule_data["action"],
        rule_data["priority"],
        rule_data["description"],
        rule_data.get("is_enabled", 1),
        rule_id,
    ))
    updated = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return updated


def delete_rule(rule_id: int, db_path: str = None) -> bool:
    """Deletes a firewall rule by ID."""
    conn = get_db_connection(db_path)
    cursor = conn.execute("DELETE FROM firewall_rules WHERE id = ?", (rule_id,))
    deleted = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return deleted


def toggle_rule(rule_id: int, db_path: str = None) -> bool:
    """Toggles a rule between enabled (1) and disabled (0)."""
    conn = get_db_connection(db_path)
    cursor = conn.execute(
        "UPDATE firewall_rules SET is_enabled = CASE WHEN is_enabled = 1 THEN 0 ELSE 1 END WHERE id = ?",
        (rule_id,),
    )
    toggled = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return toggled


# ---------------------------
# Packet Log & Dashboard Queries
# ---------------------------

def add_packet_log(packet: dict, decision: str, matched_rule, reason: str, db_path: str = None) -> int:
    """Records a packet evaluation event in the audit log table."""
    conn = get_db_connection(db_path)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    matched_rule_id = matched_rule["id"] if matched_rule else None
    matched_rule_desc = (
        f"Rule #{matched_rule['id']} (P{matched_rule['priority']}): {matched_rule['description']}"
        if matched_rule
        else "Default Policy"
    )

    src_port_str = str(packet["source_port"]) if packet["source_port"] is not None else "N/A"
    dst_port_str = str(packet["dest_port"]) if packet["dest_port"] is not None else "N/A"

    cursor = conn.execute("""
        INSERT INTO packet_logs (
            timestamp, source_ip, dest_ip, source_port, dest_port,
            protocol, direction, decision, matched_rule_id, matched_rule_desc, reason
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        timestamp,
        packet["source_ip"],
        packet["dest_ip"],
        src_port_str,
        dst_port_str,
        packet["protocol"],
        packet["direction"],
        decision,
        matched_rule_id,
        matched_rule_desc,
        reason,
    ))
    log_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return log_id


def get_packet_logs(decision_filter: str = None, limit: int = 200, db_path: str = None) -> list:
    """Retrieves packet logs, optionally filtered by ALLOW or DENY."""
    conn = get_db_connection(db_path)
    if decision_filter in ("ALLOW", "DENY"):
        rows = conn.execute(
            "SELECT * FROM packet_logs WHERE decision = ? ORDER BY id DESC LIMIT ?",
            (decision_filter, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM packet_logs ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def clear_packet_logs(db_path: str = None) -> None:
    """Clears all packet audit logs."""
    conn = get_db_connection(db_path)
    conn.execute("DELETE FROM packet_logs")
    conn.commit()
    conn.close()


def get_protocol_stats(db_path: str = None) -> dict:
    """Returns packet counts grouped by protocol (TCP, UDP, ICMP)."""
    conn = get_db_connection(db_path)
    rows = conn.execute(
        "SELECT protocol, COUNT(*) AS cnt FROM packet_logs GROUP BY protocol"
    ).fetchall()
    conn.close()
    counts = {"TCP": 0, "UDP": 0, "ICMP": 0}
    for row in rows:
        proto = row["protocol"].upper()
        if proto in counts:
            counts[proto] = row["cnt"]
    return counts


def get_dashboard_stats(db_path: str = None) -> dict:
    """Returns summary metrics for the administrator dashboard."""
    conn = get_db_connection(db_path)
    total_packets = conn.execute("SELECT COUNT(*) AS cnt FROM packet_logs").fetchone()["cnt"]
    allowed_packets = conn.execute(
        "SELECT COUNT(*) AS cnt FROM packet_logs WHERE decision = ?", ("ALLOW",)
    ).fetchone()["cnt"]
    denied_packets = conn.execute(
        "SELECT COUNT(*) AS cnt FROM packet_logs WHERE decision = ?", ("DENY",)
    ).fetchone()["cnt"]
    active_rules = conn.execute(
        "SELECT COUNT(*) AS cnt FROM firewall_rules WHERE is_enabled = 1"
    ).fetchone()["cnt"]
    total_rules = conn.execute("SELECT COUNT(*) AS cnt FROM firewall_rules").fetchone()["cnt"]
    recent_logs = conn.execute(
        "SELECT * FROM packet_logs ORDER BY id DESC LIMIT 6"
    ).fetchall()
    conn.close()

    block_rate = round((denied_packets / total_packets) * 100, 1) if total_packets > 0 else 0.0

    return {
        "total_packets": total_packets,
        "allowed_packets": allowed_packets,
        "denied_packets": denied_packets,
        "active_rules": active_rules,
        "total_rules": total_rules,
        "block_rate": block_rate,
        "protocol_stats": get_protocol_stats(db_path=db_path),
        "recent_logs": [dict(r) for r in recent_logs],
    }