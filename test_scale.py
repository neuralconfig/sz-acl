#!/usr/bin/env python3
"""
SmartZone L3 ACL Scale Test Script
This script tests the scalability of L3 ACL policy creation by generating multiple policies
until it encounters an error or reaches the specified limit.
"""

import argparse
import json
import sys
import time
import os
from datetime import datetime
from create_l3_acl import vSZ_calls

# Try to import CSV utilities
try:
    from csv_utils import csv_to_json
    CSV_SUPPORT = True
except ImportError:
    CSV_SUPPORT = False
    print("Warning: CSV support is not available. Make sure csv_utils.py is in the same directory.")
    sys.exit(1)

def create_acl_policy(vsz, host, token, domain_id, policy_name, rules_file, description="L3 ACL created by scale test"):
    """Create an L3 ACL policy with the specified name and rules"""
    
    # First check if CSV file exists
    if not os.path.exists(rules_file):
        print(f"Error: Rules file {rules_file} not found.")
        return False, None
    
    # Load rules from the CSV file
    print(f"Loading rules from CSV file: {rules_file}")
    try:
        json_str = csv_to_json(rules_file)
        if not json_str:
            print("Error: Failed to convert CSV to JSON.")
            return False, None
        
        rules = json.loads(json_str)
        print(f"Successfully loaded {len(rules)} rules from CSV file")
    except Exception as e:
        print(f"Error loading rules from file: {str(e)}")
        return False, None
    
    # Prepare L3 ACL policy payload
    payload = {
        "name": policy_name,
        "description": description,
        "defaultAction": "ALLOW",
        "l3AclRuleList": rules
    }
    
    # Add domain ID if specified
    if domain_id:
        payload["domainId"] = domain_id
    
    # Create the policy
    print(f"Creating L3 ACL Policy '{policy_name}'...")
    response = vsz.createL3ACLPolicy(host, token, payload)
    
    if response.status_code == 201 or response.status_code == 200:
        policy_result = response.json()
        policy_id = policy_result.get('id')
        print(f"Policy '{policy_name}' created successfully with ID: {policy_id}")
        return True, policy_id
    else:
        print(f"Failed to create policy '{policy_name}'. Status code: {response.status_code}")
        print(f"Response: {response.text}")
        return False, None

def main():
    parser = argparse.ArgumentParser(description='Test SmartZone L3 ACL policy creation at scale')
    parser.add_argument('--host', required=True, help='SmartZone hostname or IP address')
    parser.add_argument('--username', required=True, help='SmartZone admin username')
    parser.add_argument('--password', required=True, help='SmartZone admin password')
    parser.add_argument('--domain', help='Domain name (optional)')
    parser.add_argument('--rules-file', default='acl_rules_template.csv', help='CSV file containing ACL rules (default: acl_rules_template.csv)')
    parser.add_argument('--max-policies', type=int, default=256, help='Maximum number of policies to create (default: 256)')
    parser.add_argument('--prefix', default='test', help='Prefix for policy names (default: test)')
    parser.add_argument('--start-index', type=int, default=1, help='Starting index for policy names (default: 1)')
    parser.add_argument('--delay', type=float, default=0.5, help='Delay between policy creations in seconds (default: 0.5)')
    parser.add_argument('--output', default='scale_test_results.json', help='Output file for test results (default: scale_test_results.json)')
    
    args = parser.parse_args()
    
    # Initialize API handler
    vsz = vSZ_calls()
    
    # Get authentication token
    print(f"Connecting to SmartZone controller {args.host}...")
    try:
        token = vsz.getToken(args.host, args.username, args.password)
        print("Authentication successful")
    except Exception as e:
        print(f"Error authenticating: {str(e)}")
        sys.exit(1)
    
    try:
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
        
        # Initialize results tracking
        results = {
            "startTime": datetime.now().isoformat(),
            "host": args.host,
            "domain": args.domain,
            "rulesFile": args.rules_file,
            "maxPolicies": args.max_policies,
            "prefix": args.prefix,
            "startIndex": args.start_index,
            "policies": [],
            "totalCreated": 0,
            "status": "incomplete"
        }
        
        # Start creating policies
        success_count = 0
        error_count = 0
        
        print(f"\nStarting scale test - Creating up to {args.max_policies} L3 ACL policies...")
        
        for i in range(args.start_index, args.start_index + args.max_policies):
            # Format policy name with leading zeros (e.g., test001)
            policy_name = f"{args.prefix}{i:03d}"
            
            # Create the policy
            success, policy_id = create_acl_policy(
                vsz, args.host, token, domain_id, policy_name, args.rules_file
            )
            
            # Track result
            policy_result = {
                "name": policy_name,
                "success": success,
                "id": policy_id,
                "timestamp": datetime.now().isoformat()
            }
            results["policies"].append(policy_result)
            
            # Update counters
            if success:
                success_count += 1
            else:
                error_count += 1
                # Stop on first error if it's not a temporary issue
                print("Encountered an error. Stopping test.")
                break
            
            # Report progress
            if success_count % 10 == 0:
                print(f"Progress: Created {success_count} policies successfully")
            
            # Add delay between requests to prevent overloading the server
            if i < args.start_index + args.max_policies - 1:
                time.sleep(args.delay)
        
        # Update final results
        results["totalCreated"] = success_count
        results["totalErrors"] = error_count
        results["endTime"] = datetime.now().isoformat()
        
        if success_count >= args.max_policies:
            results["status"] = "completed"
        else:
            results["status"] = "stopped_on_error"
        
        # Save results to file
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        
        # Print summary
        print("\nScale Test Summary:")
        print(f"Total policies successfully created: {success_count}")
        print(f"Total errors encountered: {error_count}")
        print(f"Test result: {results['status']}")
        print(f"Detailed results saved to: {args.output}")
        
    except Exception as e:
        print(f"Error during scale test: {str(e)}")
        import traceback
        traceback.print_exc()
    
    finally:
        # Release token
        print("\nReleasing authentication token...")
        vsz.deleteToken(args.host, token)
        print("Done")


if __name__ == "__main__":
    main()
