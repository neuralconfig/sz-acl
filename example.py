#!/usr/bin/env python3
"""
Example script demonstrating how to use the SmartZone L3 ACL API programmatically
"""

from create_l3_acl import vSZ_calls
import json
import time
import sys
import os

# Try to import CSV utilities
try:
    from csv_utils import csv_to_json
    CSV_SUPPORT = True
except ImportError:
    CSV_SUPPORT = False

# SmartZone controller details
HOST = "vsz.example.net"  # Your SmartZone hostname
USERNAME = "admin"              # Your username
PASSWORD = "password"           # Your password - update this to match your password!

# Domain details
DOMAIN_NAME = "domain-name"           # Your domain name - update this to match your environment

# API version to use
API_VERSION = "v13_0"           # Specify the correct API version for your controller

# Example L3 ACL Policy details
ACL_POLICY_NAME = "Example-L3-ACL-Policy"
ACL_POLICY_DESCRIPTION = "Example L3 ACL Policy created via API"

# Path to example rules file (can be JSON or CSV)
EXAMPLE_RULES_FILE = "example_rules.json"  # or "acl_rules_template.csv"

# Example ACL rules (used if the file is not found)
EXAMPLE_RULES = [
    {
        "description": "Allow specific TCP subnet traffic",
        "enableSourceIpSubnet": True,
        "sourceIp": "172.17.26.55",
        "sourceIpMask": "255.255.255.0",
        "enableSourcePortRange": False,
        "sourceMinPort": 80,
        "destinationIp": "172.17.26.60",
        "destinationIpMask": "255.255.0.0",
        "protocol": "TCP",
        "action": "ALLOW",
        "direction": "DUAL"
    },
    {
        "description": "Block specific UDP subnet traffic",
        "enableSourceIpSubnet": True,
        "sourceIp": "192.168.1.0",
        "sourceIpMask": "255.255.255.0",
        "destinationIp": "10.0.0.0",
        "destinationIpMask": "255.0.0.0",
        "protocol": "UDP",
        "action": "BLOCK",
        "direction": "INBOUND"
    }
]

def list_domains(vsz, host, token):
    """List all available domains"""
    print("\n=== LISTING DOMAINS ===")
    
    domains = vsz.listDomains(host, token)
    
    if domains:
        print(f"Found {len(domains)} domains:")
        for domain in domains:
            print(f"  - Name: {domain['name']}, ID: {domain['id']}")
        return domains
    else:
        print("No domains found or error retrieving domains")
        return []

def create_l3_acl_policy(vsz, host, token, domain_id):
    """Create an L3 ACL Policy example"""
    print("\n=== CREATING L3 ACL POLICY ===")
    
    # Load rules from file if it exists
    rules = EXAMPLE_RULES
    if os.path.exists(EXAMPLE_RULES_FILE):
        try:
            # Handle CSV files
            if EXAMPLE_RULES_FILE.lower().endswith('.csv') and CSV_SUPPORT:
                print(f"Loading rules from CSV file: {EXAMPLE_RULES_FILE}")
                json_str = csv_to_json(EXAMPLE_RULES_FILE)
                if json_str:
                    file_rules = json.loads(json_str)
                    rules = file_rules
                    print(f"Successfully loaded {len(rules)} rules from CSV file")
            # Handle JSON files
            else:
                print(f"Loading rules from JSON file: {EXAMPLE_RULES_FILE}")
                with open(EXAMPLE_RULES_FILE, 'r') as f:
                    file_rules = json.load(f)
                if isinstance(file_rules, list):
                    rules = file_rules
                    print(f"Successfully loaded {len(rules)} rules from JSON file")
                elif isinstance(file_rules, dict) and 'l3AclRuleList' in file_rules:
                    rules = file_rules['l3AclRuleList']
                    print(f"Successfully loaded {len(rules)} rules from JSON file")
        except Exception as e:
            print(f"Error loading rules from file: {str(e)}")
            print("Using default example rules instead")
    else:
        print(f"Rules file {EXAMPLE_RULES_FILE} not found. Using default example rules.")
    
    # Prepare L3 ACL policy payload
    payload = {
        "domainId": domain_id,
        "name": ACL_POLICY_NAME,
        "description": ACL_POLICY_DESCRIPTION,
        "defaultAction": "ALLOW",
        "l3AclRuleList": rules
    }
    
    print(f"Creating L3 ACL Policy '{ACL_POLICY_NAME}'...")
    print(f"Payload: {json.dumps(payload, indent=2)}")
    
    # Create the policy
    response = vsz.createL3ACLPolicy(host, token, payload)
    
    if response.status_code == 201 or response.status_code == 200:
        policy_result = response.json()
        policy_id = policy_result.get('id')
        print("\nL3 ACL Policy created successfully!")
        print(f"Policy ID: {policy_id}")
        return policy_id
    else:
        print(f"Failed to create L3 ACL Policy. Status code: {response.status_code}")
        print(f"Response: {response.text}")
        return None

def list_l3_acl_policies(vsz, host, token, domain_id=None):
    """List all L3 ACL Policies"""
    print("\n=== LISTING L3 ACL POLICIES ===")
    
    policies = vsz.listL3ACLPolicies(host, token, domain_id)
    
    if policies:
        total_count = policies.get('totalCount', 0)
        policy_list = policies.get('list', [])
        
        print(f"Found {total_count} L3 ACL Policies:")
        
        if total_count > 0:
            for policy in policy_list:
                policy_id = policy.get('id', 'N/A')
                name = policy.get('name', 'N/A')
                default_action = policy.get('defaultAction', 'N/A')
                rule_count = len(policy.get('l3AclRuleList', []))
                
                print(f"  - ID: {policy_id}")
                print(f"    Name: {name}")
                print(f"    Default Action: {default_action}")
                print(f"    Rule Count: {rule_count}")
                print()
            
            return policy_list
        else:
            print("No L3 ACL Policies found")
            return []
    else:
        print("Failed to retrieve L3 ACL Policies")
        return None

def get_l3_acl_policy(vsz, host, token, policy_id):
    """Get details of a specific L3 ACL Policy"""
    print(f"\n=== GETTING L3 ACL POLICY DETAILS: {policy_id} ===")
    
    policy = vsz.getL3ACLPolicy(host, token, policy_id)
    
    if policy:
        print("\nL3 ACL Policy details:")
        print(f"  - ID: {policy.get('id', 'N/A')}")
        print(f"  - Name: {policy.get('name', 'N/A')}")
        print(f"  - Description: {policy.get('description', 'N/A')}")
        print(f"  - Default Action: {policy.get('defaultAction', 'N/A')}")
        
        rules = policy.get('l3AclRuleList', [])
        print(f"  - Rules Count: {len(rules)}")
        
        if rules:
            print("\nACL Rules:")
            for i, rule in enumerate(rules):
                print(f"  Rule #{i+1}:")
                print(f"    Description: {rule.get('description', 'N/A')}")
                print(f"    Protocol: {rule.get('protocol', 'N/A')}")
                print(f"    Action: {rule.get('action', 'N/A')}")
                print(f"    Direction: {rule.get('direction', 'N/A')}")
                print(f"    Source IP: {rule.get('sourceIp', 'N/A')}/{rule.get('sourceIpMask', 'N/A')}")
                print(f"    Destination IP: {rule.get('destinationIp', 'N/A')}/{rule.get('destinationIpMask', 'N/A')}")
                print()
                
        return policy
    else:
        print(f"Policy with ID {policy_id} not found or error retrieving policy")
        return None

def update_l3_acl_policy(vsz, host, token, policy_id, policy):
    """Update an L3 ACL Policy example"""
    print(f"\n=== UPDATING L3 ACL POLICY: {policy_id} ===")
    
    # Make a change to the policy
    if 'description' in policy:
        policy['description'] = f"{policy['description']} - Updated on {time.strftime('%Y-%m-%d %H:%M:%S')}"
    else:
        policy['description'] = f"Updated on {time.strftime('%Y-%m-%d %H:%M:%S')}"
    
    # Add a new rule
    new_rule = {
        "description": "New rule added via API update",
        "enableSourceIpSubnet": True,
        "sourceIp": "172.18.0.0",
        "sourceIpMask": "255.255.0.0",
        "protocol": "TCP",
        "action": "ALLOW",
        "direction": "OUTBOUND"
    }
    
    if 'l3AclRuleList' in policy:
        policy['l3AclRuleList'].append(new_rule)
    else:
        policy['l3AclRuleList'] = [new_rule]
    
    print(f"Updating L3 ACL Policy with new description and additional rule...")
    print(f"Updated payload: {json.dumps(policy, indent=2)}")
    
    # Update the policy
    success = vsz.updateL3ACLPolicy(host, token, policy_id, policy)
    
    if success:
        print("\nL3 ACL Policy updated successfully!")
        return True
    else:
        print("Failed to update L3 ACL Policy")
        return False

def delete_l3_acl_policy(vsz, host, token, policy_id):
    """Delete an L3 ACL Policy example"""
    print(f"\n=== DELETING L3 ACL POLICY: {policy_id} ===")
    
    print(f"Deleting L3 ACL Policy with ID: {policy_id}...")
    
    success = vsz.deleteL3ACLPolicy(host, token, policy_id)
    
    if success:
        print("\nL3 ACL Policy deleted successfully!")
        return True
    else:
        print("Failed to delete L3 ACL Policy")
        return False


def main():
    # Initialize API handler
    vsz = vSZ_calls()
    vsz.api_version = API_VERSION
    
    print(f"API version: {vsz.api_version}")
    
    try:
        # Get authentication token
        print(f"Connecting to SmartZone controller {HOST}...")
        token = vsz.getToken(HOST, USERNAME, PASSWORD)
        print("Authentication successful!")
        
        # 1. List domains to find the correct domain ID
        domains = list_domains(vsz, HOST, token)
        
        # Find our target domain
        domain_id = None
        for domain in domains:
            if domain['name'] == DOMAIN_NAME:
                domain_id = domain['id']
                print(f"Found domain '{DOMAIN_NAME}' with ID: {domain_id}")
                break
                
        if not domain_id and domains:
            # Use the first domain as fallback
            domain_id = domains[0]['id']
            domain_name = domains[0]['name']
            print(f"Domain '{DOMAIN_NAME}' not found. Using '{domain_name}' with ID: {domain_id}")
        elif not domain_id:
            print("No domains found. Cannot continue.")
            return
        
        # 2. List existing L3 ACL policies
        print("Listing existing L3 ACL policies...")
        existing_policies = list_l3_acl_policies(vsz, HOST, token, domain_id)
        
        # 3. Create a new L3 ACL policy
        print("\nCreating a new L3 ACL policy...")
        new_policy_id = create_l3_acl_policy(vsz, HOST, token, domain_id)
        
        if new_policy_id:
            # 4. Wait a moment for the policy to be registered
            print("\nWaiting for the policy to be registered in the system...")
            time.sleep(3)
            
            # 5. Get the details of the newly created policy
            new_policy = get_l3_acl_policy(vsz, HOST, token, new_policy_id)
            
            if new_policy:
                # 6. Update the policy
                print("\nUpdating the policy...")
                if update_l3_acl_policy(vsz, HOST, token, new_policy_id, new_policy):
                    # 7. Get the updated policy details
                    print("\nRetrieving updated policy details...")
                    time.sleep(2)
                    updated_policy = get_l3_acl_policy(vsz, HOST, token, new_policy_id)
                    
                    # 8. Ask if we should delete the policy
                    choice = input("\nDelete the created policy? (y/n): ")
                    if choice.lower() == 'y':
                        delete_l3_acl_policy(vsz, HOST, token, new_policy_id)
                        
                        # 9. Verify the policy is deleted
                        print("\nVerifying deletion...")
                        time.sleep(2)
                        list_l3_acl_policies(vsz, HOST, token, domain_id)
                    else:
                        print(f"\nPolicy '{ACL_POLICY_NAME}' (ID: {new_policy_id}) has been kept in the system.")
            else:
                print("Could not retrieve the created policy. Skipping update and deletion steps.")
        else:
            print("Failed to create a new policy. Exiting.")
    
    except Exception as e:
        print(f"Error: {str(e)}")
        import traceback
        traceback.print_exc()
    
    finally:
        # Release token
        if 'token' in locals():
            print("\nReleasing authentication token...")
            vsz.deleteToken(HOST, token)
            print("Done")


if __name__ == "__main__":
    main()
