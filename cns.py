class Firewall:
    def __init__(self):
        self.rules = []  # List of rules

    def add_rule(self, ip, port, protocol, action):
        """Adds a rule to the firewall."""
        self.rules.append({
            "ip": ip,
            "port": port,
            "protocol": protocol,
            "action": action  # Allow or Block
        })

    def check_packet(self, ip, port, protocol):
        """Checks if a packet should be allowed or blocked."""
        for rule in self.rules:
            if rule["ip"] == ip and rule["port"] == port and rule["protocol"] == protocol:
                return rule["action"]
        return "ALLOW"  # Default action if no rule matches

# Example Usage
firewall = Firewall()
firewall.add_rule("192.168.1.10", 80, "TCP", "BLOCK")
firewall.add_rule("192.168.1.15", 22, "TCP", "ALLOW")

# Simulate checking packets
packets = [
    {"ip": "192.168.1.10", "port": 80, "protocol": "TCP"},
    {"ip": "192.168.1.15", "port": 22, "protocol": "TCP"},
    {"ip": "192.168.1.20", "port": 443, "protocol": "TCP"}
]

for packet in packets:
    result = firewall.check_packet(packet["ip"], packet["port"], packet["protocol"])
    print(f"Packet from {packet['ip']}:{packet['port']} ({packet['protocol']}) -> {result}")
