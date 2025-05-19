#!/usr/bin/env python3
"""
SmartZone L3 ACL Policy Creator
This script creates L3 Access Control Policies on a SmartZone controller using the API.
"""

import requests
import json
import argparse
import sys
from datetime import datetime
import os
try:
    from csv_utils import csv_to_json
    CSV_SUPPORT = True
except ImportError:
    CSV_SUPPORT = False

# Disable SSL warnings for self-signed certificates
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class vSZ_calls:
    def __init__(self):
        self.session = requests.Session()
        self.api_version = "v13_0"  # Default API version for L3 ACL policy

    # Get authentication token
    def getToken(self, host, username, password):
        # Format host properly
        if not host.startswith('http'):
            host = f"https://{host}:8443"
        
        url = f"{host}/wsg/api/public/{self.api_version}/serviceTicket"
        body = {'username': username, 'password': password}
        
        try:
            # Use session for all requests
            r = self.session.post(url, json=body, verify=False)
            
            if r.status_code != 200:
                print(f"Authentication failed with status code: {r.status_code}")
                print(f"Response: {r.text}")
                raise Exception("Failed to authenticate with the server")
            
            response_json = r.json()
            
            if 'serviceTicket' in response_json:
                token = response_json['serviceTicket']
                return token
            else:
                print("Authentication successful but 'serviceTicket' field not found in response.")
                print("Available fields in response: " + ", ".join(response_json.keys()))
                raise Exception("Authentication token not found in server response")
                
        except Exception as e:
            print(f"Error during authentication: {str(e)}")
            raise

    # Release authentication token
    def deleteToken(self, host, token):
        if not host.startswith('http'):
            host = f"https://{host}:8443"
            
        url = f"{host}/wsg/api/public/{self.api_version}/serviceTicket?serviceTicket={token}"
        try:
            r = self.session.delete(url, verify=False)
            if r.status_code != 200 and r.status_code != 204:
                print(f"Warning: Failed to release token. Status code: {r.status_code}")
        except Exception as e:
            print(f"Warning: Error releasing token: {str(e)}")
        return

    # Get domain ID by name
    def getDomainIDByName(self, host, domainName, token):
        if not host.startswith('http'):
            host = f"https://{host}:8443"
        
        # First try the direct API call with current API version
        url = f"{host}/wsg/api/public/{self.api_version}/domains/byName/{domainName}?serviceTicket={token}"
        r = self.session.get(url, verify=False)
        
        if r.status_code == 200:
            response_data = r.json()
            
            # Check if response has direct ID field
            if 'id' in response_data:
                return response_data['id']
            
            # Check if response has a list structure
            if 'list' in response_data and len(response_data['list']) > 0:
                # Since we looked up by name, the first item should be our domain
                # Just return the ID of the first item in the list
                return response_data['list'][0].get('id')
        
        # If direct lookup failed, try the domains list method
        print(f"Direct domain lookup failed, trying domain list method...")
        domains = self.listDomains(host, token)
        
        if domains:
            for domain in domains:
                if domain.get('name') == domainName:
                    print(f"Found domain '{domainName}' in domain list")
                    return domain.get('id')
        
        # If we get here, the domain wasn't found
        print(f"Error retrieving domain: Status {r.status_code}")
        print(f"Response: {r.text}")
        return None

    # List domains
    def listDomains(self, host, token):
        if not host.startswith('http'):
            host = f"https://{host}:8443"
            
        listSize = 1000
        index = 0
        hasMore = True
        domainList = []
        
        while hasMore:
            url = f"{host}/wsg/api/public/{self.api_version}/domains?listSize={listSize}&index={index}&serviceTicket={token}"
            r = self.session.get(url, verify=False)
            
            if r.status_code != 200:
                print(f"Error retrieving domains: {r.status_code}")
                print(f"Response: {r.text}")
                return None
            
            response_json = r.json()
            domainList.extend(response_json['list'])
            
            if not response_json.get('hasMore', False):
                hasMore = False
            
            index += listSize
        
        return domainList

    # Create L3 ACL Policy
    def createL3ACLPolicy(self, host, token, payload):
        if not host.startswith('http'):
            host = f"https://{host}:8443"
            
        # Try with different API versions if needed
        versions = ["v13_0"]
        
        for version in versions:
            url = f"{host}/wsg/api/public/{version}/l3AccessControlPolicies?serviceTicket={token}"
            try:
                r = self.session.post(url, json=payload, verify=False)
                if r.status_code == 201 or r.status_code == 200:
                    return r
                print(f"Failed with API version {version}. Status: {r.status_code}")
                if r.status_code != 404:  # Only show response text for non-404 errors
                    print(f"Response: {r.text}")
            except Exception as e:
                print(f"Error with API version {version}: {str(e)}")
        
        # If all versions failed, return the last response
        return r

    # Get L3 ACL Policy by ID
    def getL3ACLPolicy(self, host, token, policy_id):
        if not host.startswith('http'):
            host = f"https://{host}:8443"
            
        url = f"{host}/wsg/api/public/{self.api_version}/l3AccessControlPolicies/{policy_id}?serviceTicket={token}"
        try:
            r = self.session.get(url, verify=False)
            if r.status_code == 200:
                return r.json()
            else:
                print(f"Failed to get L3 ACL policy. Status: {r.status_code}")
                print(f"Response: {r.text}")
                return None
        except Exception as e:
            print(f"Error getting L3 ACL policy: {str(e)}")
            return None

    # List L3 ACL Policies
    def listL3ACLPolicies(self, host, token, domain_id=None):
        if not host.startswith('http'):
            host = f"https://{host}:8443"
            
        # Construct URL with domain filter if provided
        if domain_id:
            url = f"{host}/wsg/api/public/{self.api_version}/l3AccessControlPolicies?serviceTicket={token}&domainId={domain_id}"
        else:
            url = f"{host}/wsg/api/public/{self.api_version}/l3AccessControlPolicies?serviceTicket={token}"
            
        try:
            r = self.session.get(url, verify=False)
            if r.status_code == 200:
                return r.json()
            else:
                print(f"Failed to list L3 ACL policies. Status: {r.status_code}")
                print(f"Response: {r.text}")
                return None
        except Exception as e:
            print(f"Error listing L3 ACL policies: {str(e)}")
            return None

    # Delete an L3 ACL Policy
    def deleteL3ACLPolicy(self, host, token, policy_id):
        if not host.startswith('http'):
            host = f"https://{host}:8443"
            
        url = f"{host}/wsg/api/public/{self.api_version}/l3AccessControlPolicies/{policy_id}?serviceTicket={token}"
        try:
            r = self.session.delete(url, verify=False)
            if r.status_code == 204 or r.status_code == 200:
                return True
            else:
                print(f"Failed to delete L3 ACL policy. Status: {r.status_code}")
                print(f"Response: {r.text}")
                return False
        except Exception as e:
            print(f"Error deleting L3 ACL policy: {str(e)}")
            return False

    # Update an L3 ACL Policy
    def updateL3ACLPolicy(self, host, token, policy_id, payload):
        if not host.startswith('http'):
            host = f"https://{host}:8443"
            
        url = f"{host}/wsg/api/public/{self.api_version}/l3AccessControlPolicies/{policy_id}?serviceTicket={token}"
        try:
            r = self.session.put(url, json=payload, verify=False)
            if r.status_code == 200 or r.status_code == 204:
                return True
            else:
                print(f"Failed to update L3 ACL policy. Status: {r.status_code}")
                print(f"Response: {r.text}")
                return False
        except Exception as e:
            print(f"Error updating L3 ACL policy: {str(e)}")
            return False


def main():
    parser = argparse.ArgumentParser(description='Create SmartZone L3 Access Control Policies')
    parser.add_argument('--host', required=True, help='SmartZone hostname or IP address')
    parser.add_argument('--username', required=True, help='SmartZone admin username')
    parser.add_argument('--password', required=True, help='SmartZone admin password')
    parser.add_argument('--domain', help='Domain name (optional - if not specified, no domain will be included in the request)')
    parser.add_argument('--name', help='Name for the L3 ACL policy')
    parser.add_argument('--description', help='Description for the L3 ACL policy')
    parser.add_argument('--default-action', choices=['ALLOW', 'BLOCK'], default='ALLOW', 
                        help='Default action for the policy (default: ALLOW)')
    parser.add_argument('--rule-file', help='JSON or CSV file containing ACL rules')
    parser.add_argument('--debug', action='store_true', help='Enable debug output')
    parser.add_argument('--api-version', default='v13_0', help='API version to use (default: v13_0)')
    parser.add_argument('--show-domains', action='store_true', help='Show available domains')
    parser.add_argument('--wildcard', type=int, help='Replace X in IP addresses with this octet value (0-255)')
    parser.add_argument('--wildcard-file', help='CSV file with site names and octets in format: name,octet')
    
    args = parser.parse_args()
    
    # Check if --name is provided when not using wildcard-file
    if not args.wildcard_file and not args.name:
        parser.error("--name is required when not using --wildcard-file")
    
    # Check for mutually exclusive arguments
    if args.wildcard is not None and args.wildcard_file:
        parser.error("--wildcard and --wildcard-file cannot be used together")
    
    # Process wildcard file if specified
    wildcard_entries = []
    if args.wildcard_file:
        try:
            import csv
            with open(args.wildcard_file, 'r', newline='') as f:
                reader = csv.DictReader(f)
                if 'name' not in reader.fieldnames or 'octet' not in reader.fieldnames:
                    parser.error(f"Wildcard file must have 'name' and 'octet' columns")
                wildcard_entries = list(reader)
                
                if not wildcard_entries:
                    parser.error(f"Wildcard file {args.wildcard_file} has no entries")
                
                # Validate octets
                for entry in wildcard_entries:
                    try:
                        octet = int(entry['octet'])
                        if octet < 0 or octet > 255:
                            parser.error(f"Octet value {octet} in wildcard file is out of range (0-255)")
                    except ValueError:
                        parser.error(f"Invalid octet value '{entry['octet']}' in wildcard file")
                
                print(f"Loaded {len(wildcard_entries)} site entries from {args.wildcard_file}")
                for entry in wildcard_entries:
                    print(f"  - {entry['name']}: {entry['octet']}")
        except FileNotFoundError:
            parser.error(f"Wildcard file {args.wildcard_file} not found")
        except Exception as e:
            parser.error(f"Error reading wildcard file: {str(e)}")
    
    # Initialize API handler
    vsz = vSZ_calls()
    vsz.api_version = args.api_version
    
    # Get authentication token
    print(f"Connecting to SmartZone controller {args.host}...")
    try:
        token = vsz.getToken(args.host, args.username, args.password)
        print("Authentication successful")
        if args.debug:
            print(f"Auth token: {token}")
    except Exception as e:
        print(f"Error authenticating: {str(e)}")
        sys.exit(1)
    
    try:
        # Show domains list if requested
        if args.show_domains or args.debug:
            print("\nAvailable domains:")
            domains = vsz.listDomains(args.host, token)
            if domains:
                for domain in domains:
                    print(f"  - {domain['name']} (ID: {domain['id']})")
            else:
                print("  No domains found or error retrieving domains")
            print()  # Add empty line for better readability
        
        # Get domain ID if specified
        domain_id = None
        if args.domain:
            print(f"Getting domain ID for {args.domain}...")
            domain_id = vsz.getDomainIDByName(args.host, args.domain, token)
            
            if not domain_id:
                print(f"Domain {args.domain} not found")
                vsz.deleteToken(args.host, token)
                sys.exit(1)
            print(f"Domain ID: {domain_id}")
        
        # Initialize L3 ACL payload
        payload = {
            "name": args.name,
            "defaultAction": args.default_action,
            "l3AclRuleList": []
        }
        
        # Add domain ID if specified
        if domain_id:
            payload["domainId"] = domain_id
            
        # Add description if specified
        if args.description:
            payload["description"] = args.description
            
        # Load rules from file if specified
        if args.rule_file:
            try:
                # Check if the file is a CSV file
                is_csv = False
                if args.rule_file.lower().endswith('.csv'):
                    is_csv = True
                    if not CSV_SUPPORT:
                        print("CSV support is not available. Please make sure the csv_utils.py file is in the same directory.")
                        print("Falling back to treating the file as JSON.")
                        is_csv = False
                
                # Handle CSV file
                if is_csv and CSV_SUPPORT:
                    print(f"Detected CSV file. Converting {args.rule_file} to JSON format...")
                    # Convert CSV to JSON string
                    json_data = csv_to_json(args.rule_file)
                    if not json_data:
                        raise ValueError("Failed to convert CSV file to JSON")
                    
                    # Parse the JSON string
                    rules_data = json.loads(json_data)
                    payload["l3AclRuleList"] = rules_data
                    print(f"Successfully loaded {len(rules_data)} rules from the CSV file.")
                
                # Handle JSON file
                else:
                    with open(args.rule_file, 'r') as f:
                        rules_data = json.load(f)
                    
                    # If the file contains a full policy structure, extract just the rules
                    if isinstance(rules_data, dict) and 'l3AclRuleList' in rules_data:
                        payload["l3AclRuleList"] = rules_data["l3AclRuleList"]
                        
                        # Check if we should override other fields
                        if 'name' in rules_data and not args.name:
                            payload["name"] = rules_data["name"]
                        if 'description' in rules_data and not args.description:
                            payload["description"] = rules_data["description"]
                        if 'defaultAction' in rules_data and args.default_action == 'ALLOW':  # Only override if using default
                            payload["defaultAction"] = rules_data["defaultAction"]
                        if 'domainId' in rules_data and not domain_id:
                            payload["domainId"] = rules_data["domainId"]
                            
                    # Otherwise treat the file contents as just the rule list
                    elif isinstance(rules_data, list):
                        payload["l3AclRuleList"] = rules_data
                    else:
                        print(f"Warning: Unexpected format in rules file. Expected a list or an object with 'l3AclRuleList'.")
                        print(f"Will continue with empty rule list.")
                    
            except Exception as e:
                print(f"Error loading rules from {args.rule_file}: {str(e)}")
                print("Will continue with empty rule list.")
        
        # Function to apply wildcard replacement
        def apply_wildcard_replacement(rules, wildcard_value):
            wildcard_str = str(wildcard_value)
            print(f"Applying wildcard replacement: X -> {wildcard_str}")
            
            replacements_count = 0
            for rule in rules:
                # Replace X in source IP
                if "sourceIp" in rule and rule["sourceIp"]:
                    original_ip = rule["sourceIp"]
                    new_ip = original_ip.replace("x", wildcard_str).replace("X", wildcard_str)
                    if original_ip != new_ip:
                        rule["sourceIp"] = new_ip
                        print(f"  Replaced sourceIp: {original_ip} -> {new_ip}")
                        replacements_count += 1
                
                # Replace X in destination IP
                if "destinationIp" in rule and rule["destinationIp"]:
                    original_ip = rule["destinationIp"]
                    new_ip = original_ip.replace("x", wildcard_str).replace("X", wildcard_str)
                    if original_ip != new_ip:
                        rule["destinationIp"] = new_ip
                        print(f"  Replaced destinationIp: {original_ip} -> {new_ip}")
                        replacements_count += 1
            
            return replacements_count
        
        # Apply wildcard replacement if using the --wildcard argument
        if args.wildcard is not None:
            if args.wildcard < 0 or args.wildcard > 255:
                print(f"Error: Wildcard value must be between 0 and 255 (got {args.wildcard})")
                vsz.deleteToken(args.host, token)
                sys.exit(1)
            
            apply_wildcard_replacement(payload.get("l3AclRuleList", []), args.wildcard)
            
        # Apply wildcard replacement if using the --wildcard-file argument
        if args.wildcard_file:
            # We'll create a policy for each entry in the wildcard file
            for entry in wildcard_entries:
                site_name = entry['name'].strip('"')  # Remove quotes if present
                octet_value = int(entry['octet'])
                
                # Make a deep copy of the original payload
                import copy
                site_payload = copy.deepcopy(payload)
                
                # Set the policy name to the site name
                site_payload["name"] = site_name
                
                # Apply the wildcard replacement
                print(f"\nProcessing site: {site_name} with octet: {octet_value}")
                replacements = apply_wildcard_replacement(site_payload.get("l3AclRuleList", []), octet_value)
                
                if replacements == 0:
                    print(f"Warning: No IP replacements were made for site {site_name}. Make sure your rules contain 'X' or 'x' in IP addresses.")
                
                if args.debug:
                    print(f"\nL3 ACL Policy payload for {site_name}:")
                    print(json.dumps(site_payload, indent=2))
                
                # Create L3 ACL Policy for this site
                print(f"Creating L3 ACL Policy for {site_name}...")
                response = vsz.createL3ACLPolicy(args.host, token, site_payload)
                
                # Check response
                if response.status_code == 201 or response.status_code == 200:
                    policy_result = response.json()
                    policy_id = policy_result.get('id')
                    print(f"\nL3 ACL Policy for {site_name} created successfully!")
                    print(f"Policy ID: {policy_id}")
                    
                    # Save policy ID to file
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    filename = f"l3_acl_policy_{site_name.replace(' ', '_')}_{timestamp}.json"
                    with open(filename, 'w') as f:
                        json.dump({"id": policy_id, "payload": site_payload}, f, indent=2)
                    print(f"Policy details saved to {filename}")
                    
                else:
                    print(f"\nError creating L3 ACL Policy for {site_name}!")
                    print(f"Status code: {response.status_code}")
                    print(f"Response: {response.text}")
            
            # Return early since we've already processed all sites
            vsz.deleteToken(args.host, token)
            return
        
        if args.debug:
            print("\nL3 ACL Policy payload:")
            print(json.dumps(payload, indent=2))
        
        # Create L3 ACL Policy
        print(f"Creating L3 ACL Policy: {payload['name']}...")
        response = vsz.createL3ACLPolicy(args.host, token, payload)
        
        # Check response
        if response.status_code == 201 or response.status_code == 200:
            policy_result = response.json()
            policy_id = policy_result.get('id')
            print("\nL3 ACL Policy created successfully!")
            print(f"Policy ID: {policy_id}")
            
            # Save policy ID to file
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            policy_name = payload['name'].replace(' ', '_')
            filename = f"l3_acl_policy_{policy_name}_{timestamp}.json"
            with open(filename, 'w') as f:
                json.dump({"id": policy_id, "payload": payload}, f, indent=2)
            print(f"\nPolicy details saved to {filename}")
            
            # Retrieve the full policy
            print("\nRetrieving created policy details...")
            full_policy = vsz.getL3ACLPolicy(args.host, token, policy_id)
            if full_policy:
                print("\nCreated L3 ACL Policy details:")
                print(json.dumps(full_policy, indent=2))
        else:
            print(f"\nFailed to create L3 ACL Policy. Status code: {response.status_code}")
            print(f"Response: {response.text}")
    
    except Exception as e:
        print(f"Error: {str(e)}")
        if args.debug:
            import traceback
            traceback.print_exc()
    
    finally:
        # Release token
        print("\nReleasing authentication token...")
        vsz.deleteToken(args.host, token)
        print("Done")


if __name__ == "__main__":
    main()
