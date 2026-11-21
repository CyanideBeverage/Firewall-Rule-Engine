"""
Input validation module for firewall rules and simulated network packets.
Uses Python's built-in `ipaddress` module for strict IPv4/IPv6 and CIDR validation.
"""

import ipaddress

VALID_RULE_PROTOCOLS = {"TCP", "UDP", "ICMP", "ANY"}
VALID_PACKET_PROTOCOLS = {"TCP", "UDP", "ICMP"}
VALID_DIRECTIONS = {"INBOUND", "OUTBOUND"}
VALID_ACTIONS = {"ALLOW", "DENY"}


def validate_ip_or_cidr(value: str):
    """
    Validates a rule IP field. Accepts 'ANY', a single IP address (e.g., 192.168.1.10),
    or a CIDR subnet (e.g., 192.168.1.0/24).

    Returns:
        tuple: (is_valid: bool, normalized_value_or_error: str)
    """
    if value is None or not str(value).strip():
        return False, "IP address or CIDR cannot be empty."

    cleaned = str(value).strip().upper()
    if cleaned == "ANY":
        return True, "ANY"

    raw_ip = str(value).strip()
    try:
        network = ipaddress.ip_network(raw_ip, strict=False)
        if "/" not in raw_ip:
            return True, str(ipaddress.ip_address(raw_ip))
        return True, str(network)
    except ValueError:
        return False, f"Invalid IP address or CIDR range: '{raw_ip}'."


def validate_single_ip(value: str):
    """
    Validates a simulated packet IP address. Must be a single valid IPv4 or IPv6 address
    (CIDR masks and 'ANY' are not valid for an actual packet header).
    """
    if value is None or not str(value).strip():
        return False, "Packet IP address is required."

    raw_ip = str(value).strip()
    try:
        ip_obj = ipaddress.ip_address(raw_ip)
        return True, str(ip_obj)
    except ValueError:
        return False, f"Invalid packet IP address: '{raw_ip}'."


def validate_rule_port(value: str):
    """
    Validates a firewall rule port field.
    Accepts:
      - 'ANY'
      - A single port number: 1 to 65535 (e.g., '80', '443')
      - A port range: start-end (e.g., '8000-8080')
    """
    if value is None or not str(value).strip():
        return True, "ANY"

    cleaned = str(value).strip().upper()
    if cleaned == "ANY":
        return True, "ANY"

    if "-" in cleaned:
        parts = cleaned.split("-")
        if len(parts) != 2 or not parts[0].isdigit() or not parts[1].isdigit():
            return False, f"Invalid port range format: '{value}'. Use format like 8000-8080."
        start_port, end_port = int(parts[0]), int(parts[1])
        if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535):
            return False, "Port numbers must be between 1 and 65535."
        if start_port > end_port:
            return False, f"Invalid port range '{value}': start port cannot exceed end port."
        return True, f"{start_port}-{end_port}"

    if not cleaned.isdigit():
        return False, f"Invalid port value: '{value}'. Enter a number (1-65535), range, or ANY."

    port_num = int(cleaned)
    if not (1 <= port_num <= 65535):
        return False, f"Port {port_num} out of valid range (1-65535)."

    return True, str(port_num)


def validate_packet_port(value, protocol: str):
    """
    Validates a simulated packet port.
    - For ICMP packets, ports are not applicable (empty, None, or '0' is accepted as None).
    - For TCP/UDP packets, an integer port between 1 and 65535 is required.
    """
    proto = str(protocol).strip().upper()

    if proto == "ICMP":
        if value is None or str(value).strip() in ("", "0", "N/A", "NONE"):
            return True, None
        return False, "ICMP does not use ports. Leave port fields blank or set to 0."

    if value is None or str(value).strip() == "":
        return False, f"Port is required for {proto} packets."

    raw = str(value).strip()
    if not raw.isdigit():
        return False, f"Invalid port '{raw}'. Must be a number between 1 and 65535."

    port_num = int(raw)
    if not (1 <= port_num <= 65535):
        return False, f"Port {port_num} is out of valid range (1-65535)."

    return True, port_num


def validate_rule_data(data: dict):
    """
    Validates all fields required to create or update a firewall rule.

    Returns:
        tuple: (is_valid: bool, cleaned_data_dict: dict, errors: list[str])
    """
    errors = []
    cleaned = {}

    ok, res = validate_ip_or_cidr(data.get("source_ip"))
    if ok:
        cleaned["source_ip"] = res
    else:
        errors.append(f"Source IP: {res}")

    ok, res = validate_ip_or_cidr(data.get("dest_ip"))
    if ok:
        cleaned["dest_ip"] = res
    else:
        errors.append(f"Destination IP: {res}")

    protocol = str(data.get("protocol", "")).strip().upper()
    if protocol not in VALID_RULE_PROTOCOLS:
        errors.append(f"Protocol must be one of: {', '.join(sorted(VALID_RULE_PROTOCOLS))}.")
    else:
        cleaned["protocol"] = protocol

    if protocol == "ICMP":
        cleaned["source_port"] = "ANY"
        cleaned["dest_port"] = "ANY"
    else:
        ok, res = validate_rule_port(data.get("source_port", "ANY"))
        if ok:
            cleaned["source_port"] = res
        else:
            errors.append(f"Source Port: {res}")

        ok, res = validate_rule_port(data.get("dest_port", "ANY"))
        if ok:
            cleaned["dest_port"] = res
        else:
            errors.append(f"Destination Port: {res}")

    direction = str(data.get("direction", "")).strip().upper()
    if direction not in VALID_DIRECTIONS:
        errors.append("Direction must be INBOUND or OUTBOUND.")
    else:
        cleaned["direction"] = direction

    action = str(data.get("action", "")).strip().upper()
    if action not in VALID_ACTIONS:
        errors.append("Action must be ALLOW or DENY.")
    else:
        cleaned["action"] = action

    raw_priority = str(data.get("priority", "")).strip()
    if not raw_priority.isdigit() or int(raw_priority) < 1 or int(raw_priority) > 10000:
        errors.append("Priority must be an integer between 1 and 10000 (lower = higher priority).")
    else:
        cleaned["priority"] = int(raw_priority)

    description = str(data.get("description", "")).strip()
    if not description:
        errors.append("Description is required.")
    elif len(description) > 255:
        errors.append("Description cannot exceed 255 characters.")
    else:
        cleaned["description"] = description

    is_enabled = data.get("is_enabled", True)
    if isinstance(is_enabled, str):
        cleaned["is_enabled"] = 1 if is_enabled.lower() in ("1", "true", "on", "yes") else 0
    else:
        cleaned["is_enabled"] = 1 if is_enabled else 0

    return len(errors) == 0, cleaned, errors


def validate_packet_data(data: dict):
    """
    Validates all fields of an incoming/outgoing simulated packet.

    Returns:
        tuple: (is_valid: bool, cleaned_packet: dict, errors: list[str])
    """
    errors = []
    cleaned = {}

    ok, res = validate_single_ip(data.get("source_ip"))
    if ok:
        cleaned["source_ip"] = res
    else:
        errors.append(f"Source IP: {res}")

    ok, res = validate_single_ip(data.get("dest_ip"))
    if ok:
        cleaned["dest_ip"] = res
    else:
        errors.append(f"Destination IP: {res}")

    protocol = str(data.get("protocol", "")).strip().upper()
    if protocol not in VALID_PACKET_PROTOCOLS:
        errors.append(f"Protocol must be one of: {', '.join(sorted(VALID_PACKET_PROTOCOLS))}.")
    else:
        cleaned["protocol"] = protocol

    if protocol in VALID_PACKET_PROTOCOLS:
        ok, res = validate_packet_port(data.get("source_port"), protocol)
        if ok:
            cleaned["source_port"] = res
        else:
            errors.append(f"Source Port: {res}")

        ok, res = validate_packet_port(data.get("dest_port"), protocol)
        if ok:
            cleaned["dest_port"] = res
        else:
            errors.append(f"Destination Port: {res}")

    direction = str(data.get("direction", "")).strip().upper()
    if direction not in VALID_DIRECTIONS:
        errors.append("Traffic direction must be INBOUND or OUTBOUND.")
    else:
        cleaned["direction"] = direction

    return len(errors) == 0, cleaned, errors