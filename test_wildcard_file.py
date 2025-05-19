#!/usr/bin/env python3
"""
Test script for the wildcard file feature in create_l3_acl.py
"""

import json
import os

# Test data with X placeholders (same as in test_wildcard.py)
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
    }
]

# Save test rules to a JSON file
with open('test_wildcard_rules.json', 'w') as f:
    json.dump(test_rules, f, indent=2)

print("Test wildcard rules saved to test_wildcard_rules.json")
print("Wildcard site files are available at:")
print("  - wildcard_sites_numeric.csv: 42 sites with numeric octets")
print("  - wildcard_sites_alpha.csv: 3 sites (A, B, C) with octets 10, 20, 30")

print("\nExample usage with wildcard-file:")
print("python create_l3_acl.py --host <host> --username <user> --password <pass> --rule-file test_wildcard_rules.json --wildcard-file wildcard_sites_alpha.csv")
print("\nThis will create 3 policies:")
print("  - 'Site A' with octet 10")
print("  - 'Site B' with octet 20")
print("  - 'Site C' with octet 30")

print("\nOr using the large site list:")
print("python create_l3_acl.py --host <host> --username <user> --password <pass> --rule-file test_wildcard_rules.json --wildcard-file wildcard_sites_numeric.csv")
print("This will create 42 policies, one for each site in the wildcard file.")