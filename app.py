"""
Main Flask web application for the Firewall Rule Engine.
Connects the web UI, authentication layer, database layer, and rule evaluation engine.
"""

import csv
import io
import json
from flask import Flask, render_template, request, redirect, url_for, session, flash, Response
from config import Config
from database import (
    init_db,
    get_all_rules,
    get_rule_by_id,
    add_rule,
    update_rule,
    delete_rule,
    toggle_rule,
    get_packet_logs,
    clear_packet_logs,
    get_dashboard_stats,
    get_default_policy,
    set_default_policy,
)
from auth import authenticate_user, login_required
from validators import validate_rule_data
from firewall_engine import evaluate_packet


def create_app(db_path: str = None, seed_data: bool = True) -> Flask:
    """Application factory enabling clean configuration for both production and unit tests."""
    app = Flask(__name__)
    app.config.from_object(Config)

    active_db = db_path or Config.DATABASE_PATH
    app.config["DATABASE_PATH"] = active_db

    init_db(db_path=active_db, seed_data=seed_data)

    # ---------------------------
    # Public / About Route
    # ---------------------------

    @app.route("/about")
    def about():
        return render_template("about.html")

    # ---------------------------
    # Authentication Routes
    # ---------------------------

    @app.route("/")
    def index():
        if "user_id" in session:
            return redirect(url_for("dashboard"))
        return redirect(url_for("login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if "user_id" in session:
            return redirect(url_for("dashboard"))

        if request.method == "POST":
            username = request.form.get("username", "")
            password = request.form.get("password", "")

            success, user, message = authenticate_user(
                username, password, db_path=app.config["DATABASE_PATH"]
            )
            if success:
                session.clear()
                session["user_id"] = user["id"]
                session["username"] = user["username"]
                flash(f"Welcome back, {user['username']}!", "success")
                return redirect(url_for("dashboard"))

            flash(message, "danger")

        return render_template("login.html")

    @app.route("/logout", methods=["POST"])
    @login_required
    def logout():
        session.clear()
        flash("You have been logged out securely.", "info")
        return redirect(url_for("login"))

    # ---------------------------
    # Dashboard Route
    # ---------------------------

    @app.route("/dashboard")
    @login_required
    def dashboard():
        db = app.config["DATABASE_PATH"]
        stats = get_dashboard_stats(db_path=db)
        default_policy = get_default_policy(db_path=db)
        return render_template(
            "dashboard.html",
            stats=stats,
            default_policy=default_policy,
        )

    # ---------------------------
    # Firewall Rules Management
    # ---------------------------

    @app.route("/rules")
    @login_required
    def rules_list():
        db = app.config["DATABASE_PATH"]
        rules = get_all_rules(db_path=db)
        default_policy = get_default_policy(db_path=db)
        return render_template(
            "rules.html",
            rules=rules,
            default_policy=default_policy,
        )

    @app.route("/rules/export")
    @login_required
    def export_rules():
        db = app.config["DATABASE_PATH"]
        rules = get_all_rules(db_path=db)
        payload = json.dumps(rules, indent=2)
        return Response(
            payload,
            mimetype="application/json",
            headers={"Content-Disposition": "attachment;filename=firewall_rules_backup.json"},
        )

    @app.route("/rules/add", methods=["GET", "POST"])
    @login_required
    def add_rule_view():
        db = app.config["DATABASE_PATH"]
        form_data = {
            "source_ip": "ANY",
            "dest_ip": "ANY",
            "source_port": "ANY",
            "dest_port": "ANY",
            "protocol": "TCP",
            "direction": "INBOUND",
            "action": "ALLOW",
            "priority": 100,
            "description": "",
            "is_enabled": 1,
        }

        if request.method == "POST":
            form_data = {
                "source_ip": request.form.get("source_ip", ""),
                "dest_ip": request.form.get("dest_ip", ""),
                "source_port": request.form.get("source_port", "ANY"),
                "dest_port": request.form.get("dest_port", "ANY"),
                "protocol": request.form.get("protocol", "TCP"),
                "direction": request.form.get("direction", "INBOUND"),
                "action": request.form.get("action", "ALLOW"),
                "priority": request.form.get("priority", ""),
                "description": request.form.get("description", ""),
                "is_enabled": 1 if request.form.get("is_enabled") else 0,
            }
            is_valid, cleaned, errors = validate_rule_data(form_data)
            if is_valid:
                add_rule(cleaned, db_path=db)
                flash("Firewall rule created successfully.", "success")
                return redirect(url_for("rules_list"))

            for err in errors:
                flash(err, "danger")

        return render_template("rule_form.html", mode="add", rule=form_data)

    @app.route("/rules/edit/<int:rule_id>", methods=["GET", "POST"])
    @login_required
    def edit_rule_view(rule_id: int):
        db = app.config["DATABASE_PATH"]
        existing = get_rule_by_id(rule_id, db_path=db)
        if not existing:
            flash("Firewall rule not found.", "warning")
            return redirect(url_for("rules_list"))

        if request.method == "POST":
            form_data = {
                "id": rule_id,
                "source_ip": request.form.get("source_ip", ""),
                "dest_ip": request.form.get("dest_ip", ""),
                "source_port": request.form.get("source_port", "ANY"),
                "dest_port": request.form.get("dest_port", "ANY"),
                "protocol": request.form.get("protocol", "TCP"),
                "direction": request.form.get("direction", "INBOUND"),
                "action": request.form.get("action", "ALLOW"),
                "priority": request.form.get("priority", ""),
                "description": request.form.get("description", ""),
                "is_enabled": 1 if request.form.get("is_enabled") else 0,
            }
            is_valid, cleaned, errors = validate_rule_data(form_data)
            if is_valid:
                update_rule(rule_id, cleaned, db_path=db)
                flash(f"Firewall rule #{rule_id} updated successfully.", "success")
                return redirect(url_for("rules_list"))

            for err in errors:
                flash(err, "danger")
            return render_template("rule_form.html", mode="edit", rule=form_data)

        return render_template("rule_form.html", mode="edit", rule=existing)

    @app.route("/rules/delete/<int:rule_id>", methods=["POST"])
    @login_required
    def delete_rule_view(rule_id: int):
        db = app.config["DATABASE_PATH"]
        if delete_rule(rule_id, db_path=db):
            flash(f"Firewall rule #{rule_id} deleted.", "info")
        else:
            flash("Rule not found.", "warning")
        return redirect(url_for("rules_list"))

    @app.route("/rules/toggle/<int:rule_id>", methods=["POST"])
    @login_required
    def toggle_rule_view(rule_id: int):
        db = app.config["DATABASE_PATH"]
        if toggle_rule(rule_id, db_path=db):
            flash(f"Rule #{rule_id} status updated.", "info")
        else:
            flash("Rule not found.", "warning")
        return redirect(url_for("rules_list"))

    @app.route("/settings/default-policy", methods=["POST"])
    @login_required
    def update_default_policy():
        db = app.config["DATABASE_PATH"]
        policy = request.form.get("default_policy", "").upper()
        if policy in ("ALLOW", "DENY"):
            set_default_policy(policy, db_path=db)
            flash(f"Default fallback policy updated to {policy}.", "success")
        else:
            flash("Invalid default policy selection.", "danger")
        return redirect(request.referrer or url_for("rules_list"))

    # ---------------------------
    # Packet Simulator Routes
    # ---------------------------

    @app.route("/simulator", methods=["GET", "POST"])
    @login_required
    def simulator():
        db = app.config["DATABASE_PATH"]
        default_policy = get_default_policy(db_path=db)
        result = None
        packet_input = {
            "source_ip": "192.168.1.25",
            "dest_ip": "10.0.0.10",
            "source_port": "54321",
            "dest_port": "443",
            "protocol": "TCP",
            "direction": "INBOUND",
        }

        if request.method == "POST":
            packet_input = {
                "source_ip": request.form.get("source_ip", ""),
                "dest_ip": request.form.get("dest_ip", ""),
                "source_port": request.form.get("source_port", ""),
                "dest_port": request.form.get("dest_port", ""),
                "protocol": request.form.get("protocol", "TCP"),
                "direction": request.form.get("direction", "INBOUND"),
            }
            result = evaluate_packet(packet_input, db_path=db, log_result=True)
            if not result["valid"]:
                for err in result["errors"]:
                    flash(err, "danger")

        return render_template(
            "simulator.html",
            result=result,
            packet_input=packet_input,
            default_policy=default_policy,
        )

    @app.route("/simulator/batch", methods=["POST"])
    @login_required
    def simulator_batch():
        """Simulates a realistic 8-packet mixed traffic burst for live demo & analytics."""
        db = app.config["DATABASE_PATH"]
        sample_burst = [
            {"source_ip": "192.168.1.25", "dest_ip": "10.0.0.10", "source_port": 51010, "dest_port": 443, "protocol": "TCP", "direction": "INBOUND"},
            {"source_ip": "203.0.113.50", "dest_ip": "10.0.0.10", "source_port": 44120, "dest_port": 443, "protocol": "TCP", "direction": "INBOUND"},
            {"source_ip": "192.168.1.40", "dest_ip": "10.0.0.12", "source_port": 52100, "dest_port": 22, "protocol": "TCP", "direction": "INBOUND"},
            {"source_ip": "185.220.101.4", "dest_ip": "10.0.0.12", "source_port": 61200, "dest_port": 22, "protocol": "TCP", "direction": "INBOUND"},
            {"source_ip": "192.168.1.18", "dest_ip": "8.8.8.8", "source_port": 53411, "dest_port": 53, "protocol": "UDP", "direction": "OUTBOUND"},
            {"source_ip": "45.33.32.156", "dest_ip": "10.0.0.10", "source_port": 49900, "dest_port": 23, "protocol": "TCP", "direction": "INBOUND"},
            {"source_ip": "192.168.1.15", "dest_ip": "10.0.0.10", "source_port": "", "dest_port": "", "protocol": "ICMP", "direction": "INBOUND"},
            {"source_ip": "172.16.8.90", "dest_ip": "10.0.0.99", "source_port": 59001, "dest_port": 3306, "protocol": "UDP", "direction": "INBOUND"},
        ]
        for pkt in sample_burst:
            evaluate_packet(pkt, db_path=db, log_result=True)

        flash("Simulated 8 mixed network packets (TCP, UDP, ICMP). Dashboard and logs updated!", "success")
        return redirect(request.referrer or url_for("dashboard"))

    # ---------------------------
    # Traffic Activity Logs Routes
    # ---------------------------

    @app.route("/logs")
    @login_required
    def logs_view():
        db = app.config["DATABASE_PATH"]
        decision_filter = request.args.get("decision", "ALL").upper()
        if decision_filter not in ("ALL", "ALLOW", "DENY"):
            decision_filter = "ALL"

        logs = get_packet_logs(
            decision_filter=None if decision_filter == "ALL" else decision_filter,
            db_path=db,
        )
        return render_template(
            "logs.html",
            logs=logs,
            current_filter=decision_filter,
        )

    @app.route("/logs/export")
    @login_required
    def export_logs():
        db = app.config["DATABASE_PATH"]
        logs = get_packet_logs(limit=1000, db_path=db)

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "ID", "Timestamp", "Direction", "Source IP", "Source Port",
            "Destination IP", "Destination Port", "Protocol", "Decision",
            "Matched Rule", "Reason"
        ])
        for log in logs:
            writer.writerow([
                log["id"], log["timestamp"], log["direction"], log["source_ip"],
                log["source_port"], log["dest_ip"], log["dest_port"], log["protocol"],
                log["decision"], log["matched_rule_desc"], log["reason"]
            ])

        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment;filename=firewall_traffic_logs.csv"},
        )

    @app.route("/logs/clear", methods=["POST"])
    @login_required
    def clear_logs_view():
        clear_packet_logs(db_path=app.config["DATABASE_PATH"])
        flash("All traffic logs cleared.", "info")
        return redirect(url_for("logs_view"))

    return app


app = create_app()

if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)