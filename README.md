# SmartZoneACL

A Python library and command-line tools for managing L3 Access Control Policies on Ruckus SmartZone controllers. Supports both JSON and CSV formats for defining ACL rules.

## Overview

SmartZoneACL allows you to create, retrieve, update, and delete Layer 3 Access Control Policies on Ruckus SmartZone controllers using the REST API. L3 ACL policies provide packet filtering capabilities based on IP addresses, protocols, and ports.

## Features

* Create new L3 ACL policies with rules
* Retrieve existing L3 ACL policies
* Update existing L3 ACL policies
* Delete L3 ACL policies
* List all L3 ACL policies in a domain
* Command-line interface for all operations
* Python API for programmatic use
* Support for both JSON and CSV formats for defining ACL rules
* CSV template for easy rule creation in Excel

## Requirements

* Python 3.6+
* Requests library
* Access to a Ruckus SmartZone controller with API access

## Installation

1. Clone this repository or download the files
2. Install the required dependencies:

```bash
pip install requests
```

### CSV Format

Alternatively, you can define rules in a CSV file, which is easier to edit in spreadsheet applications like Excel:

```csv
description,protocol,action,direction,sourceIp,sourceIpMask,enableSourceIpSubnet,destinationIp,destinationIpMask,enableDestinationIpSubnet,sourceMinPort,sourceMaxPort,enableSourcePortRange,destinationMinPort,destinationMaxPort,enableDestinationPortRange,customProtocol
Allow specific TCP subnet traffic,TCP,ALLOW,DUAL,172.17.26.55,255.255.255.0,TRUE,172.17.26.60,255.255.0.0,FALSE,80,80,FALSE,,,,
Block specific UDP subnet traffic,UDP,BLOCK,INBOUND,192.168.1.0,255.255.255.0,TRUE,10.0.0.0,255.0.0.0,FALSE,,,,,,, 
Allow HTTPS traffic to web servers,TCP,ALLOW,INBOUND,,,FALSE,192.168.10.0,255.255.255.0,TRUE,,,,443,443,TRUE,
```

A CSV template file (`acl_rules_template.csv`) is included in the project to help you get started.

### CSV Utilities

The project includes a utility script for working with CSV files:

```bash
# Create a CSV template file
python csv_utils.py --create-template --output my_template.csv

# Convert a CSV file to JSON
python csv_utils.py --csv-to-json my_rules.csv --output my_rules.json

# Convert a JSON file to CSV
python csv_utils.py --json-to-csv my_rules.json --output my_rules.csv
```

## Command-line Usage

### Creating L3 ACL Policies

```bash
python create_l3_acl.py --host <hostname> --username <username> --password <password> --name "My ACL Policy" --description "My description" --domain <domain_name> --rule-file rules.json
```

You can also use a CSV file for defining rules:

```bash
python create_l3_acl.py --host <hostname> --username <username> --password <password> --name "My ACL Policy" --description "My description" --domain <domain_name> --rule-file rules.csv
```

Optional arguments:
- `--default-action`: Default action for the policy (ALLOW or BLOCK, default: ALLOW)
- `--debug`: Enable debug output
- `--api-version`: API version to use (default: v13_0)
- `--show-domains`: Show available domains

### Retrieving L3 ACL Policies

```bash
python retrieve_l3_acls.py --host <hostname> --username <username> --password <password> --domain <domain_name>
```

Optional arguments:
- `--policy-id`: Retrieve a specific policy by ID
- `--save`: Save results to a JSON file
- `--output`: Output file name (default: l3_acl_policies_list.json)
- `--debug`: Enable debug output
- `--api-version`: API version to use (default: v13_0)

## Programmatic Usage

```python
from create_l3_acl import vSZ_calls

# Initialize API handler
vsz = vSZ_calls()
vsz.api_version = "v13_0"

# Get authentication token
token = vsz.getToken(host, username, password)

# Create a policy
payload = {
    "domainId": "domain-id-here",
    "name": "My ACL Policy",
    "description": "My description",
    "defaultAction": "ALLOW",
    "l3AclRuleList": [
        {
            "description": "Allow specific TCP subnet traffic",
            "enableSourceIpSubnet": True,
            "sourceIp": "172.17.26.55",
            "sourceIpMask": "255.255.255.0",
            "protocol": "TCP",
            "action": "ALLOW",
            "direction": "DUAL"
        }
    ]
}
response = vsz.createL3ACLPolicy(host, token, payload)

# List policies
policies = vsz.listL3ACLPolicies(host, token, domain_id)

# Get a specific policy
policy = vsz.getL3ACLPolicy(host, token, policy_id)

# Update a policy
vsz.updateL3ACLPolicy(host, token, policy_id, updated_payload)

# Delete a policy
vsz.deleteL3ACLPolicy(host, token, policy_id)

# Always release the token when done
vsz.deleteToken(host, token)
```

## L3 ACL Rules Format

### JSON Format

Here's an example of a JSON rules file that can be used with the `--rule-file` parameter:

```json
[
  {
    "description": "Allow specific TCP subnet traffic",
    "enableSourceIpSubnet": true,
    "sourceIp": "172.17.26.55",
    "sourceIpMask": "255.255.255.0",
    "enableSourcePortRange": false,
    "sourceMinPort": 80,
    "destinationIp": "172.17.26.60",
    "destinationIpMask": "255.255.0.0",
    "protocol": "TCP",
    "action": "ALLOW",
    "direction": "DUAL"
  },
  {
    "description": "Block specific UDP subnet traffic",
    "enableSourceIpSubnet": true,
    "sourceIp": "192.168.1.0",
    "sourceIpMask": "255.255.255.0",
    "destinationIp": "10.0.0.0",
    "destinationIpMask": "255.0.0.0",
    "protocol": "UDP",
    "action": "BLOCK",
    "direction": "INBOUND"
  }
]
```

## Example Script

The included `example.py` script demonstrates how to use the library programmatically. It performs the following actions:

1. Lists available domains
2. Lists existing L3 ACL policies
3. Creates a new L3 ACL policy with example rules
4. Retrieves the created policy
5. Updates the policy with a new rule
6. Optionally deletes the policy

To run the example:

```bash
python example.py
```

Make sure to update the variables at the top of the script with your SmartZone controller details before running.

## Supported Rule Parameters

- `description`: Description of the rule
- `enableSourceIpSubnet`: Boolean indicating if source IP subnet is enabled
- `sourceIp`: Source IP address
- `sourceIpMask`: Source IP subnet mask
- `enableSourcePortRange`: Boolean indicating if source port range is enabled
- `sourceMinPort`: Minimum source port number
- `sourceMaxPort`: Maximum source port number
- `enableDestinationPortRange`: Boolean indicating if destination port range is enabled
- `destinationIp`: Destination IP address
- `destinationIpMask`: Destination IP subnet mask
- `destinationMinPort`: Minimum destination port number
- `destinationMaxPort`: Maximum destination port number
- `protocol`: Protocol (TCP, UDP, UDPLITE, ICMP_ICMPV4, ICMPV6, IGMP, ESP, AH, SCTP, CUSTOM)
- `customProtocol`: Custom protocol number (1-255, when protocol is set to CUSTOM)
- `action`: Action to take (ALLOW or BLOCK)
- `direction`: Traffic direction (INBOUND, OUTBOUND, DUAL)

## License

This project is licensed under the MIT License.
