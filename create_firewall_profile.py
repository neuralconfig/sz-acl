#!/usr/bin/env python3
"""
SmartZone Firewall Profile Creator
This script creates Firewall Profiles on a SmartZone controller using the API.
It creates an L3 ACL Policy first, then creates a Firewall Profile that references it.
"""

import requests
import json
import argparse
import sys
from datetime import datetime
import os
import copy
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

    # Create Firewall Profile
    def createFirewallProfile(self, host, token, payload):
        if not host.startswith('http'):
            host = f"https://{host}:8443"
            
        url = f"{host}/wsg/api/public/{self.api_version}/firewallProfiles?serviceTicket={token}"
        try:
            r = self.session.post(url, json=payload, verify=False)
            if r.status_code == 201 or r.status_code == 200:
                return r
            else:
                print(f"Failed to create firewall profile. Status: {r.status_code}")
                print(f"Response: {r.text}")
                return r
        except Exception as e:
            print(f"Error creating firewall profile: {str(e)}")
            return None

    # List Firewall Profiles
    def listFirewallProfiles(self, host, token, domain_id=None):
        if not host.startswith('http'):
            host = f"https://{host}:8443"
            
        listSize = 1000
        index = 0
        hasMore = True
        profileList = []
        
        while hasMore:
            # Construct URL with pagination and domain filter if provided
            if domain_id:
                url = f"{host}/wsg/api/public/{self.api_version}/firewallProfiles?listSize={listSize}&index={index}&serviceTicket={token}&domainId={domain_id}"
            else:
                url = f"{host}/wsg/api/public/{self.api_version}/firewallProfiles?listSize={listSize}&index={index}&serviceTicket={token}"
                
            try:
                r = self.session.get(url, verify=False)
                if r.status_code == 200:
                    response_json = r.json()
                    profileList.extend(response_json.get('list', []))
                    
                    if not response_json.get('hasMore', False):
                        hasMore = False
                    
                    index += listSize
                else:
                    print(f"Failed to list firewall profiles. Status: {r.status_code}")
                    print(f"Response: {r.text}")
                    return None
            except Exception as e:
                print(f"Error listing firewall profiles: {str(e)}")
                return None
        
        return {"list": profileList}

    # Get Firewall Profile by ID
    def getFirewallProfile(self, host, token, profile_id):
        if not host.startswith('http'):
            host = f"https://{host}:8443"
            
        url = f"{host}/wsg/api/public/{self.api_version}/firewallProfiles/{profile_id}?serviceTicket={token}"
        try:
            r = self.session.get(url, verify=False)
            if r.status_code == 200:
                return r.json()
            else:
                print(f"Failed to get firewall profile. Status: {r.status_code}")
                print(f"Response: {r.text}")
                return None
        except Exception as e:
            print(f"Error getting firewall profile: {str(e)}")
            return None

    # Delete a Firewall Profile
    def deleteFirewallProfile(self, host, token, profile_id):
        if not host.startswith('http'):
            host = f"https://{host}:8443"
            
        url = f"{host}/wsg/api/public/{self.api_version}/firewallProfiles/{profile_id}?serviceTicket={token}"
        try:
            r = self.session.delete(url, verify=False)
            if r.status_code == 204 or r.status_code == 200:
                return True
            else:
                print(f"Failed to delete firewall profile. Status: {r.status_code}")
                print(f"Response: {r.text}")
                return False
        except Exception as e:
            print(f"Error deleting firewall profile: {str(e)}")
            return False

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


def main():
    parser = argparse.ArgumentParser(description='Create SmartZone Firewall Profiles with L3 Access Control Policies')
    parser.add_argument('--host', required=True, help='SmartZone hostname or IP address')
    parser.add_argument('--username', required=True, help='SmartZone admin username')
    parser.add_argument('--password', required=True, help='SmartZone admin password')
    parser.add_argument('--domain', help='Domain name (optional - if not specified, no domain will be included in the request)')
    parser.add_argument('--name', help='Name for the firewall profile and L3 ACL policy')
    parser.add_argument('--description', help='Description for the firewall profile and L3 ACL policy')
    parser.add_argument('--default-action', choices=['ALLOW', 'BLOCK'], default='ALLOW', 
                        help='Default action for the L3 ACL policy (default: ALLOW)')
    parser.add_argument('--rule-file', help='JSON or CSV file containing ACL rules')
    parser.add_argument('--debug', action='store_true', help='Enable debug output')
    parser.add_argument('--api-version', default='v13_0', help='API version to use (default: v13_0)')
    parser.add_argument('--show-domains', action='store_true', help='Show available domains')
    parser.add_argument('--wildcard', type=int, help='Replace X in IP addresses with this octet value (0-255)')
    parser.add_argument('--wildcard-file', help='CSV file with site names and octets in format: name,octet')
    parser.add_argument('--uplink-rate', type=float, 
                        help='Uplink rate limiting in Mbps (optional)')
    parser.add_argument('--downlink-rate', type=float,
                        help='Downlink rate limiting in Mbps (optional)')
    
    args = parser.parse_args()
    
    # Check if --name is provided when not using wildcard-file
    if not args.wildcard_file and not args.name:
        parser.error("--name is required when not using --wildcard-file")
    
    # Check for mutually exclusive arguments
    if args.wildcard is not None and args.wildcard_file:
        parser.error("--wildcard and --wildcard-file cannot be used together")
    
    # Validate rate limiting values if provided
    if args.uplink_rate is not None and (args.uplink_rate < 0.1 or args.uplink_rate > 200):
        parser.error("Uplink rate must be between 0.1 and 200 Mbps")
    if args.downlink_rate is not None and (args.downlink_rate < 0.1 or args.downlink_rate > 200):
        parser.error("Downlink rate must be between 0.1 and 200 Mbps")
    
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
        l3_acl_payload = {
            "name": args.name,
            "defaultAction": args.default_action,
            "l3AclRuleList": []
        }
        
        # Add domain ID if specified
        if domain_id:
            l3_acl_payload["domainId"] = domain_id
            
        # Add description if specified
        if args.description:
            l3_acl_payload["description"] = args.description
            
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
                    l3_acl_payload["l3AclRuleList"] = rules_data
                    print(f"Successfully loaded {len(rules_data)} rules from the CSV file.")
                
                # Handle JSON file
                else:
                    with open(args.rule_file, 'r') as f:
                        rules_data = json.load(f)
                    
                    # If the file contains a full policy structure, extract just the rules
                    if isinstance(rules_data, dict) and 'l3AclRuleList' in rules_data:
                        l3_acl_payload["l3AclRuleList"] = rules_data["l3AclRuleList"]
                        
                        # Check if we should override other fields
                        if 'name' in rules_data and not args.name:
                            l3_acl_payload["name"] = rules_data["name"]
                        if 'description' in rules_data and not args.description:
                            l3_acl_payload["description"] = rules_data["description"]
                        if 'defaultAction' in rules_data and args.default_action == 'ALLOW':  # Only override if using default
                            l3_acl_payload["defaultAction"] = rules_data["defaultAction"]
                        if 'domainId' in rules_data and not domain_id:
                            l3_acl_payload["domainId"] = rules_data["domainId"]
                            
                    # Otherwise treat the file contents as just the rule list
                    elif isinstance(rules_data, list):
                        l3_acl_payload["l3AclRuleList"] = rules_data
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
        
        # Function to create both L3 ACL and Firewall Profile
        def create_l3_acl_and_firewall_profile(acl_payload, profile_name):
            # Create L3 ACL Policy first
            print(f"Creating L3 ACL Policy: {acl_payload['name']}...")
            l3_response = vsz.createL3ACLPolicy(args.host, token, acl_payload)
            
            if l3_response.status_code == 201 or l3_response.status_code == 200:
                l3_policy_result = l3_response.json()
                l3_policy_id = l3_policy_result.get('id')
                print(f"L3 ACL Policy created successfully! Policy ID: {l3_policy_id}")
                
                # Create Firewall Profile payload
                firewall_payload = {
                    "name": profile_name,
                    "l3AccessControlPolicyId": l3_policy_id
                }
                
                # Add rate limiting if specified
                if args.uplink_rate is not None:
                    firewall_payload["uplinkRateLimitingMbps"] = args.uplink_rate
                if args.downlink_rate is not None:
                    firewall_payload["downlinkRateLimitingMbps"] = args.downlink_rate
                
                # Add domain ID if specified
                if domain_id:
                    firewall_payload["domainId"] = domain_id
                
                # Add description if specified
                if args.description:
                    firewall_payload["description"] = args.description
                
                # Create Firewall Profile
                print(f"Creating Firewall Profile: {profile_name}...")
                firewall_response = vsz.createFirewallProfile(args.host, token, firewall_payload)
                
                if firewall_response and (firewall_response.status_code == 201 or firewall_response.status_code == 200):
                    firewall_result = firewall_response.json()
                    firewall_id = firewall_result.get('id')
                    print(f"Firewall Profile created successfully! Profile ID: {firewall_id}")
                    
                    # Save details to file
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    filename = f"firewall_profile_{profile_name.replace(' ', '_')}_{timestamp}.json"
                    with open(filename, 'w') as f:
                        json.dump({
                            "firewall_profile_id": firewall_id,
                            "l3_acl_policy_id": l3_policy_id,
                            "firewall_payload": firewall_payload,
                            "l3_acl_payload": acl_payload
                        }, f, indent=2)
                    print(f"Profile details saved to {filename}")
                    
                    return firewall_id, l3_policy_id
                else:
                    print(f"Error creating Firewall Profile!")
                    if firewall_response:
                        print(f"Status code: {firewall_response.status_code}")
                        print(f"Response: {firewall_response.text}")
                    
                    # Clean up the L3 ACL policy since firewall profile creation failed
                    print(f"Cleaning up L3 ACL policy {l3_policy_id}...")
                    vsz.deleteL3ACLPolicy(args.host, token, l3_policy_id)
                    return None, None
            else:
                print(f"Error creating L3 ACL Policy!")
                print(f"Status code: {l3_response.status_code}")
                print(f"Response: {l3_response.text}")
                return None, None
        
        # Apply wildcard replacement if using the --wildcard argument
        if args.wildcard is not None:
            if args.wildcard < 0 or args.wildcard > 255:
                print(f"Error: Wildcard value must be between 0 and 255 (got {args.wildcard})")
                vsz.deleteToken(args.host, token)
                sys.exit(1)
            
            apply_wildcard_replacement(l3_acl_payload.get("l3AclRuleList", []), args.wildcard)
            
        # Apply wildcard replacement if using the --wildcard-file argument
        if args.wildcard_file:
            # We'll create a profile for each entry in the wildcard file
            for entry in wildcard_entries:
                site_name = entry['name'].strip('"')  # Remove quotes if present
                octet_value = int(entry['octet'])
                
                # Make a deep copy of the original payload
                site_acl_payload = copy.deepcopy(l3_acl_payload)
                
                # Set the policy name to the site name
                site_acl_payload["name"] = site_name
                
                # Apply the wildcard replacement
                print(f"\nProcessing site: {site_name} with octet: {octet_value}")
                replacements = apply_wildcard_replacement(site_acl_payload.get("l3AclRuleList", []), octet_value)
                
                if replacements == 0:
                    print(f"Warning: No IP replacements were made for site {site_name}. Make sure your rules contain 'X' or 'x' in IP addresses.")
                
                if args.debug:
                    print(f"\nL3 ACL Policy payload for {site_name}:")
                    print(json.dumps(site_acl_payload, indent=2))
                
                # Create L3 ACL and Firewall Profile for this site
                firewall_id, l3_policy_id = create_l3_acl_and_firewall_profile(site_acl_payload, site_name)
                
                if firewall_id and l3_policy_id:
                    print(f"\nSuccessfully created firewall profile and L3 ACL for {site_name}")
                    print(f"Firewall Profile ID: {firewall_id}")
                    print(f"L3 ACL Policy ID: {l3_policy_id}")
                else:
                    print(f"\nFailed to create firewall profile for {site_name}")
            
            # Return early since we've already processed all sites
            vsz.deleteToken(args.host, token)
            return
        
        if args.debug:
            print("\nL3 ACL Policy payload:")
            print(json.dumps(l3_acl_payload, indent=2))
        
        # Create L3 ACL and Firewall Profile for single entry
        firewall_id, l3_policy_id = create_l3_acl_and_firewall_profile(l3_acl_payload, args.name)
        
        if firewall_id and l3_policy_id:
            print(f"\nSuccessfully created firewall profile and L3 ACL!")
            print(f"Firewall Profile ID: {firewall_id}")
            print(f"L3 ACL Policy ID: {l3_policy_id}")
        else:
            print(f"\nFailed to create firewall profile")
    
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