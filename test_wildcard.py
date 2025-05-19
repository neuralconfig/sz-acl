#!/usr/bin/env python3
"""
Test script for the wildcard feature in create_l3_acl.py
"""

import json

# Test data with X placeholders
test_rules = [
    {
        "description": "Test rule with wildcard in source IP",
        "protocol": "TCP",
        "action": "ALLOW",
        "direction": "INBOUND",
        "sourceIp": "10.X.100.0",
        "sourceIpMask": "255.255.255.0",
        "enableSourceIpSubnet": True,
        "destinationIp": "192.168.1.0",
        "destinationIpMask": "255.255.255.0",
        "enableDestinationIpSubnet": True
    },
    {
        "description": "Test rule with wildcard in destination IP",
        "protocol": "TCP",
        "action": "ALLOW",
        "direction": "INBOUND",
        "sourceIp": "192.168.1.0",
        "sourceIpMask": "255.255.255.0",
        "enableSourceIpSubnet": True,
        "destinationIp": "10.x.200.128",
        "destinationIpMask": "255.255.255.255",
        "enableDestinationIpSubnet": False,
        "destinationMinPort": 8080,
        "destinationMaxPort": 8080,
        "enableDestinationPortRange": False
    },
    {
        "description": "Test rule with wildcard in both IPs",
        "protocol": "UDP",
        "action": "ALLOW",
        "direction": "DUAL",
        "sourceIp": "172.X.0.0",
        "sourceIpMask": "255.255.0.0",
        "enableSourceIpSubnet": True,
        "destinationIp": "172.X.100.0",
        "destinationIpMask": "255.255.255.0",
        "enableDestinationIpSubnet": True
    },
    {
        "description": "Test rule without wildcards",
        "protocol": "TCP",
        "action": "ALLOW",
        "direction": "INBOUND",
        "sourceIp": "10.0.0.0",
        "sourceIpMask": "255.0.0.0",
        "enableSourceIpSubnet": True,
        "destinationIp": "192.168.10.0",
        "destinationIpMask": "255.255.255.0",
        "enableDestinationIpSubnet": True
    }
]

# Save test rules to a JSON file
with open('test_wildcard_rules.json', 'w') as f:
    json.dump(test_rules, f, indent=2)

print("Test wildcard rules saved to test_wildcard_rules.json")
print("\nExample usage:")
print("python create_l3_acl.py --host <host> --username <user> --password <pass> --name 'Test Wildcard Policy' --rule-file test_wildcard_rules.json --wildcard 48")
print("\nThis will replace all 'X' with '48' in the IP addresses:")
print("  10.X.100.0 -> 10.48.100.0")
print("  10.x.200.128 -> 10.48.200.128")
print("  172.X.0.0 -> 172.48.0.0")
print("  172.X.100.0 -> 172.48.100.0")