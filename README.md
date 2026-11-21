# Firewall Rule Engine – Rule-Based Network Traffic Filtering and Simulation System

An educational B.Tech CSE cybersecurity project simulating a stateless Layer 3/Layer 4 packet-filtering firewall with a web-based management console.

> **Disclaimer:** This is a safe educational simulation. It does not modify your computer's OS firewall or intercept real network traffic.

## Key Features
- **Secure Administrator Authentication:** Password hashing (`werkzeug.security`), Flask session management, and parameterized SQL queries preventing SQL injection (`' OR '1'='1' --`).
- **Firewall Rule Management:** Full CRUD + enable/disable controls with IP/CIDR validation (`ipaddress` module), single/range ports, protocols (`TCP`, `UDP`, `ICMP`, `ANY`), traffic direction (`INBOUND`/`OUTBOUND`), priority ordering, and configurable default policy (`DENY`/`ALLOW`).
- **Packet Filtering Engine:** Implements **Priority-Based First-Match-Wins** evaluation with a complete step-by-step evaluation trace.
- **Interactive Packet Simulator:** Craft custom packets or use built-in viva presets to inspect rule matching in real time.
- **Traffic Activity Logs & Dashboard:** Persistent SQLite audit logs with `ALLOW`/`DENY` filtering, KPI summaries, and a live Chart.js traffic breakdown.
- **Automated Unit & Security Tests:** Comprehensive `unittest` suite covering rule matching, priorities, default policies, invalid packets, and SQL injection defense.

## Technology Stack
- **Backend:** Python 3, Flask, `ipaddress`, `sqlite3`, `werkzeug.security`
- **Frontend:** HTML5, CSS3, JavaScript, Bootstrap 5, Chart.js
- **Database:** SQLite (`firewall.db`)

## Quick Start
```bash
python -m venv venv
# Windows: venv\Scripts\activate
# macOS/Linux: source venv/bin/activate
pip install -r requirements.txt
python app.py