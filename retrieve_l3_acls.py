#!/usr/bin/env python3
"""
SmartZone L3 ACL Policy Retrieval Script
This script retrieves a list of L3 Access Control Policies from a SmartZone controller.
"""

import argparse
import json
import sys
import requests
from create_l3_acl import vSZ_calls

def main():
    parser = argparse.ArgumentParser(description='Retrieve SmartZone L3 Access Control Policies')
    parser.add_argument('--host', required=True, help='SmartZone hostname or IP address')
    parser.add_argument('--username', required=True, help='SmartZone admin username')
    parser.add_argument('--password', required=True, help='SmartZone admin password')
    parser.add_argument('--domain', help='Filter by domain name')
    parser.add_argument('--policy-id', help='Retrieve a specific policy by ID')
    parser.add_argument('--save', action='store_true', help='Save results to a JSON file')
    parser.add_argument('--output', default=None, help='Output file name (default: l3_acl_policies_list.json)')
    parser.add_argument('--debug', action='store_true', help='Enable debug output')
    parser.add_argument('--api-version', default='v13_0', help='API version to use (default: v13_0)')
    
    args = parser.parse_args()
    
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
        # If retrieving a specific policy by ID
        if args.policy_id:
            print(f"Retrieving L3 ACL Policy with ID: {args.policy_id}...")
            policy = vsz.getL3ACLPolicy(args.host, token, args.policy_id)
            
            if policy:
                print("\nL3 ACL Policy details:")
                print(json.dumps(policy, indent=2))
                
                # Save to file if requested
                if args.save:
                    output_file = args.output or f"l3_acl_policy_{args.policy_id}.json"
                    with open(output_file, 'w') as f:
                        json.dump(policy, f, indent=2)
                    print(f"\nPolicy details saved to {output_file}")
            else:
                print(f"Policy with ID {args.policy_id} not found or error retrieving policy")
                
        # Otherwise list policies, optionally filtered by domain
        else:
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
            
            # List policies
            print("Retrieving L3 ACL Policies...")
            policies = vsz.listL3ACLPolicies(args.host, token, domain_id)
            
            if policies:
                total_count = policies.get('totalCount', 0)
                policy_list = policies.get('list', [])
                
                print(f"\nRetrieved {total_count} L3 ACL Policies")
                
                # Display policies in a formatted table
                if total_count > 0:
                    print("\nL3 ACL Policies:")
                    print("-" * 100)
                    print(f"{'ID':<40} {'Name':<30} {'Default Action':<15} {'Rule Count':<10}")
                    print("-" * 100)
                    
                    for policy in policy_list:
                        policy_id = policy.get('id', 'N/A')
                        name = policy.get('name', 'N/A')
                        default_action = policy.get('defaultAction', 'N/A')
                        rule_count = len(policy.get('l3AclRuleList', []))
                        
                        print(f"{policy_id:<40} {name:<30} {default_action:<15} {rule_count:<10}")
                    
                    # Save to file if requested
                    if args.save:
                        output_file = args.output or "l3_acl_policies_list.json"
                        with open(output_file, 'w') as f:
                            json.dump(policies, f, indent=2)
                        print(f"\nPolicies saved to {output_file}")
                    
                    # Offer to display all details
                    choice = input("\nDisplay full details of all policies? (y/n): ")
                    if choice.lower() == 'y':
                        print("\nFull L3 ACL Policy Details:")
                        print(json.dumps(policies, indent=2))
                else:
                    print("No L3 ACL Policies found with the specified criteria")
            else:
                print("Failed to retrieve L3 ACL Policies or no policies found")
    
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
