"""
Core Firewall Rule Evaluation Engine.

Algorithm Overview:
  1. Validate incoming simulated packet details.
  2. Retrieve all ENABLED firewall rules sorted by priority ascending (1 = highest).
  3. Sequentially evaluate packet headers against each rule:
       - Direction match (INBOUND / OUTBOUND)
       - Protocol match (exact or ANY)
       - Source IP membership (exact IP, CIDR subnet, or ANY)
       - Destination IP membership (exact IP, CIDR subnet, or ANY)
       - Source Port match (exact port, port range, or ANY)
       - Destination Port match (exact port, port range, or ANY)
  4. Apply FIRST-MATCH-WINS: stop at the first matching rule and return its action.
  5. If no rule matches, apply the configurable default policy (DENY or ALLOW).
  6. Log the evaluation result to SQLite and return a full step-by-step trace.
"""

import ipaddress
from validators import validate_packet_data
from database import get_enabled_rules, get_default_policy, add_packet_log


def ip_matches(packet_ip: str, rule_ip: str) -> bool:
    """Checks whether a single packet IP falls inside a rule's IP or CIDR range."""
    if rule_ip.upper() == "ANY":
        return True

    pkt_addr = ipaddress.ip_address(packet_ip)
    rule_net = ipaddress.ip_network(rule_ip, strict=False)

    if pkt_addr.version != rule_net.version:
        return False

    return pkt_addr in rule_net


def port_matches(packet_port, rule_port: str) -> bool:
    """
    Checks whether a packet port matches a rule port specification.
    Supports 'ANY', single port ('443'), and inclusive ranges ('8000-8080').
    """
    if rule_port.upper() == "ANY":
        return True

    if packet_port is None:
        return False

    pkt_port_int = int(packet_port)
    if "-" in rule_port:
        start_port, end_port = map(int, rule_port.split("-"))
        return start_port <= pkt_port_int <= end_port

    return pkt_port_int == int(rule_port)


def protocol_matches(packet_protocol: str, rule_protocol: str) -> bool:
    """Checks whether packet protocol matches rule protocol or 'ANY'."""
    if rule_protocol.upper() == "ANY":
        return True
    return packet_protocol.upper() == rule_protocol.upper()


def evaluate_single_rule(packet: dict, rule: dict):
    """
    Compares a single firewall rule against a validated packet.

    Returns:
        tuple: (matched: bool, mismatch_reasons: list[str])
    """
    mismatches = []

    if packet["direction"] != rule["direction"]:
        mismatches.append(f"Direction mismatch (packet: {packet['direction']}, rule: {rule['direction']})")

    if not protocol_matches(packet["protocol"], rule["protocol"]):
        mismatches.append(f"Protocol mismatch (packet: {packet['protocol']}, rule: {rule['protocol']})")

    if not ip_matches(packet["source_ip"], rule["source_ip"]):
        mismatches.append(f"Source IP {packet['source_ip']} not in {rule['source_ip']}")

    if not ip_matches(packet["dest_ip"], rule["dest_ip"]):
        mismatches.append(f"Destination IP {packet['dest_ip']} not in {rule['dest_ip']}")

    if not port_matches(packet["source_port"], rule["source_port"]):
        mismatches.append(f"Source Port {packet['source_port']} != {rule['source_port']}")

    if not port_matches(packet["dest_port"], rule["dest_port"]):
        mismatches.append(f"Destination Port {packet['dest_port']} != {rule['dest_port']}")

    return len(mismatches) == 0, mismatches


def evaluate_packet(packet_data: dict, db_path: str = None, log_result: bool = True) -> dict:
    """
    Central firewall rule evaluation function.
    """
    # Step 1: Validate packet fields
    is_valid, packet, errors = validate_packet_data(packet_data)
    if not is_valid:
        return {
            "valid": False,
            "errors": errors,
            "packet": packet_data,
            "decision": "INVALID",
            "matched_rule": None,
            "reason": "Packet validation failed.",
            "evaluation_trace": [],
            "default_policy_applied": False,
        }

    # Step 2: Load active rules ordered by priority (lowest number = highest priority)
    enabled_rules = get_enabled_rules(db_path=db_path)
    evaluation_trace = []
    matched_rule = None

    # Step 3 & 4: Evaluate rules sequentially (First-Match-Wins)
    for step_index, rule in enumerate(enabled_rules, start=1):
        is_match, mismatches = evaluate_single_rule(packet, rule)

        evaluation_trace.append({
            "step": step_index,
            "rule_id": rule["id"],
            "priority": rule["priority"],
            "action": rule["action"],
            "description": rule["description"],
            "matched": is_match,
            "details": "All packet criteria matched. Evaluation stopped (First-Match-Wins)."
            if is_match
            else "; ".join(mismatches),
        })

        if is_match:
            matched_rule = rule
            break

    # Step 5: Determine final verdict or fallback to default policy
    if matched_rule:
        decision = matched_rule["action"]
        default_policy_applied = False
        reason = (
            f"Matched Rule #{matched_rule['id']} (Priority {matched_rule['priority']}): "
            f"{matched_rule['description']} -> Action: {decision}"
        )
    else:
        decision = get_default_policy(db_path=db_path)
        default_policy_applied = True
        reason = (
            f"No active firewall rules matched this packet. "
            f"Applied system default policy: {decision}."
        )

    # Step 6: Save audit log entry
    if log_result:
        add_packet_log(packet, decision, matched_rule, reason, db_path=db_path)

    return {
        "valid": True,
        "errors": [],
        "packet": packet,
        "decision": decision,
        "matched_rule": matched_rule,
        "reason": reason,
        "evaluation_trace": evaluation_trace,
        "default_policy_applied": default_policy_applied,
    }