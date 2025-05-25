# SmartZoneACL

A Python library and command-line tools for managing L3 Access Control Policies and Firewall Profiles on Ruckus SmartZone controllers. Supports both JSON and CSV formats for defining ACL rules.

## Overview

SmartZoneACL allows you to create, retrieve, update, and delete Layer 3 Access Control Policies and Firewall Profiles on Ruckus SmartZone controllers using the REST API. L3 ACL policies provide packet filtering capabilities based on IP addresses, protocols, and ports, while Firewall Profiles provide comprehensive network security configurations that can include L3 ACL policies, rate limiting, and other security features.

## Features

### L3 ACL Policy Management
* Create new L3 ACL policies with rules
* Retrieve existing L3 ACL policies
* Update existing L3 ACL policies
* Delete L3 ACL policies
* List all L3 ACL policies in a domain

### Firewall Profile Management
* Create Firewall Profiles with embedded L3 ACL policies
* Configure optional uplink/downlink rate limiting
* Automatic L3 ACL policy creation and association
* Bulk creation using wildcard files
* Cleanup of both Firewall Profiles and associated L3 ACL policies

### General Features
* Command-line interface for all operations
* Web application interface (deployable to Google Cloud)
* Python API for programmatic use
* Support for both JSON and CSV formats for defining ACL rules
* CSV template for easy rule creation in Excel
* Wildcard replacement for multi-site deployments
* Cleanup utilities for bulk deletion with pattern matching

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

## Quick Start

### Creating a Firewall Profile with L3 ACL

```bash
# Create a firewall profile with L3 ACL policy from JSON rules
python3 create_firewall_profile.py --host <hostname> --username <username> --password <password> --name "My Firewall Profile" --description "My description" --domain <domain_name> --rule-file rules.json

# Create a firewall profile with rate limiting
python3 create_firewall_profile.py --host <hostname> --username <username> --password <password> --name "Limited Profile" --domain <domain_name> --rule-file rules.csv --uplink-rate 100.0 --downlink-rate 50.0

# Bulk creation using wildcard file
python3 create_firewall_profile.py --host <hostname> --username <username> --password <password> --domain <domain_name> --rule-file template.csv --wildcard-file sites.csv
```

### Creating L3 ACL Policies Only

```bash
# Create L3 ACL policy from JSON rules
python3 create_l3_acl.py --host <hostname> --username <username> --password <password> --name "My ACL Policy" --description "My description" --domain <domain_name> --rule-file rules.json

# Create L3 ACL policy from CSV rules
python3 create_l3_acl.py --host <hostname> --username <username> --password <password> --name "My ACL Policy" --description "My description" --domain <domain_name> --rule-file rules.csv
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
python3 csv_utils.py --create-template --output my_template.csv

# Convert a CSV file to JSON
python3 csv_utils.py --csv-to-json my_rules.csv --output my_rules.json

# Convert a JSON file to CSV
python3 csv_utils.py --json-to-csv my_rules.json --output my_rules.csv
```

## Command-line Usage

### Creating Firewall Profiles

Create a Firewall Profile that automatically includes an L3 ACL policy:

```bash
python3 create_firewall_profile.py --host <hostname> --username <username> --password <password> --name "My Firewall Profile" --description "My description" --domain <domain_name> --rule-file rules.json
```

You can also use a CSV file for defining rules:

```bash
python3 create_firewall_profile.py --host <hostname> --username <username> --password <password> --name "My Firewall Profile" --description "My description" --domain <domain_name> --rule-file rules.csv
```

#### Firewall Profile Optional Arguments:
- `--uplink-rate`: Uplink rate limiting in Mbps (optional)
- `--downlink-rate`: Downlink rate limiting in Mbps (optional)
- `--default-action`: Default action for the L3 ACL policy (ALLOW or BLOCK, default: ALLOW)
- `--debug`: Enable debug output
- `--api-version`: API version to use (default: v13_0)
- `--show-domains`: Show available domains
- `--wildcard`: Replace X in IP addresses with specified octet value (0-255)
- `--wildcard-file`: CSV file with site names and octets (format: name,octet). Creates multiple firewall profiles, one for each site in the file

### Creating L3 ACL Policies Only

```bash
python3 create_l3_acl.py --host <hostname> --username <username> --password <password> --name "My ACL Policy" --description "My description" --domain <domain_name> --rule-file rules.json
```

You can also use a CSV file for defining rules:

```bash
python3 create_l3_acl.py --host <hostname> --username <username> --password <password> --name "My ACL Policy" --description "My description" --domain <domain_name> --rule-file rules.csv
```

#### L3 ACL Optional Arguments:
- `--default-action`: Default action for the policy (ALLOW or BLOCK, default: ALLOW)
- `--debug`: Enable debug output
- `--api-version`: API version to use (default: v13_0)
- `--show-domains`: Show available domains
- `--wildcard`: Replace X in IP addresses with specified octet value (0-255). For example, `--wildcard 48` will replace "10.X.200.128" with "10.48.200.128"
- `--wildcard-file`: CSV file with site names and octets (format: name,octet). Creates multiple policies, one for each site in the file. When using this option, `--name` is not required.

### Retrieving L3 ACL Policies

```bash
python3 retrieve_l3_acls.py --host <hostname> --username <username> --password <password> --domain <domain_name>
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

### Wildcard Feature

The `--wildcard` and `--wildcard-file` options allow you to use placeholder IP addresses in your rules and replace them with specific octet values at runtime. This is useful when managing ACL policies across multiple networks with similar structure but different subnet identifiers.

#### Single Wildcard Replacement

##### How it works:
- Use "X" (uppercase or lowercase) as a placeholder in IP addresses in your rule files
- Specify the replacement octet value with `--wildcard` (0-255)
- All instances of "X" or "x" in source and destination IP addresses will be replaced

##### Example:
```csv
description,protocol,action,direction,sourceIp,sourceIpMask,enableSourceIpSubnet,destinationIp,destinationIpMask,enableDestinationIpSubnet,sourceMinPort,sourceMaxPort,enableSourcePortRange,destinationMinPort,destinationMaxPort,enableDestinationPortRange,customProtocol
Proxies_new,TCP,ALLOW,INBOUND,,,FALSE,10.x.200.128,,FALSE,,,FALSE,8080,,FALSE,
```

When using `--wildcard 48`, the destination IP "10.x.200.128" becomes "10.48.200.128".

```bash
python3 create_l3_acl.py --host <hostname> --username <username> --password <password> --name "Network-48-Policy" --rule-file rules.csv --wildcard 48
```

#### Bulk Wildcard Replacement

The `--wildcard-file` option allows you to create multiple ACL policies from a single template, each with different octet values and policy names.

##### How it works:
- Create a CSV file with two columns: `name` and `octet`
- Each row represents a site with its name and octet value
- The script creates one policy per row, using the site name as the policy name and the octet value for replacement
- When using `--wildcard-file`, the `--name` parameter is not required (and will be ignored)

##### Wildcard File Format:
```csv
name,octet
"test1",10
"test2",20
"test3",30
```

##### Example:
```bash
python3 create_l3_acl.py --host <hostname> --username <username> --password <password> --rule-file rules.csv --wildcard-file sites.csv
```

This will create three policies:
- "test1" with octet value 10 (replacing all "X" with "10")
- "test2" with octet value 20 (replacing all "X" with "20")
- "test3" with octet value 30 (replacing all "X" with "30")

The feature allows efficient deployment of standardized ACL policies across multiple sites with different subnet numbering.

## Cleanup Tools

### Firewall Profile Cleanup

The `cleanup_test_firewall_profiles.py` script provides a way to clean up Firewall Profiles and their associated L3 ACL policies that match a specified pattern.

```bash
python3 cleanup_test_firewall_profiles.py --host <hostname> --username <username> --password <password> --pattern "test.*" --domain <domain_name>
```

#### Key Features
* Delete firewall profiles based on a regex pattern matching the profile name
* Automatically delete associated L3 ACL policies (can be disabled with `--keep-l3-acls`)
* Delete profiles based on IDs in a previously saved results file
* Limit the number of profiles to delete in a single run
* Configurable delay between deletions to avoid overloading the controller

#### Optional Arguments:
- `--pattern`: Regex pattern to match profile names (default: `^test.*`)
- `--results-file`: JSON file containing test results to delete
- `--max-deletions`: Maximum number of profiles to delete
- `--delay`: Delay between profile deletions in seconds (default: 0.5)
- `--force`: Do not ask for confirmation before deleting
- `--keep-l3-acls`: Do not delete associated L3 ACL policies

### L3 ACL Policy Cleanup

The `cleanup_test_acls.py` script provides a way to clean up L3 ACL policies that match a specified pattern. This is particularly useful after running scale tests or creating multiple policies with the wildcard feature.

```bash
python3 cleanup_test_acls.py --host <hostname> --username <username> --password <password> --pattern "test-acl-" --domain <domain_name>
```

#### Key Features
* Delete policies based on a regex pattern matching the policy name
* Delete policies based on IDs in a previously saved results file
* Limit the number of policies to delete in a single run
* Configurable delay between deletions to avoid overloading the controller

#### Optional Arguments:
- `--pattern`: Regex pattern to match policy names (default: `^test\d+$`)
- `--results-file`: JSON file containing test results to delete
- `--max-deletions`: Maximum number of policies to delete
- `--delay`: Delay between policy deletions in seconds (default: 0.5)
- `--force`: Do not ask for confirmation before deleting

### Naming Convention for Easy Cleanup

To make it easier to clean up policies after testing, it's recommended to follow a consistent naming convention. By default, the cleanup script will match policy names that:

1. Start with "test" followed by one or more digits (matching the default pattern `^test\d+$`)
2. Examples: "test1", "test42", "test123"

## Web Application

SmartZoneACL includes a web application interface that can be run locally or deployed to Google Cloud Platform.

### Features
* User-friendly web interface for creating firewall profiles
* CSV template downloads with proper formatting
* Interactive domain selection
* Bulk profile creation with wildcard CSV files
* Cleanup functionality with pattern matching
* Real-time error feedback from API
* neural[config] themed UI

### Local Development
```bash
# Install dependencies
pip install -r requirements.txt

# Run the Flask development server
python3 app.py
```

Visit http://localhost:8080 to access the web interface.

### Google Cloud Deployment
The application is configured for deployment on Google App Engine (free tier):

```bash
# Deploy to App Engine
./deploy.sh

# Or manually
gcloud app deploy app.yaml --project YOUR_PROJECT_ID
```

See [DEPLOYMENT.md](DEPLOYMENT.md) for detailed deployment instructions including custom domain setup.

When creating test policies, you can choose to:

1. Use this default pattern (e.g., "test1", "test2", "test3")
2. Specify your own pattern when running the cleanup script

For example, if you use a different naming scheme:

```bash
# Delete all policies that start with "testsite-"
python3 cleanup_test_acls.py --host <hostname> --username <username> --password <password> --pattern "^testsite-.*$"

# Delete all policies matching the pattern "acl-test-*"
python3 cleanup_test_acls.py --host <hostname> --username <username> --password <password> --pattern "^acl-test-.*$"
```

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
