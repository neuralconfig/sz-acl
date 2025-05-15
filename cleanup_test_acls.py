#!/usr/bin/env python3
"""
SmartZone L3 ACL Cleanup Script
This script deletes L3 ACL policies created by the scale test or matching a specified pattern.
"""

import argparse
import json
import sys
import time
import re
from datetime import datetime
from create_l3_acl import vSZ_calls

def delete_acl_policies(vsz, host, token, domain_id=None, pattern=None, results_file=None, 
                        max_deletions=None, delay=0.5):
    """Delete L3 ACL policies matching a pattern or from a results file"""
    
    # Get the list of current L3 ACL policies
    print("Retrieving existing L3 ACL policies...")
    policies = vsz.listL3ACLPolicies(host, token, domain_id)
    
    if not policies or 'list' not in policies or not policies['list']:
        print("No policies found or error retrieving policies")
        return 0
    
    policy_list = policies['list']
    print(f"Found {len(policy_list)} L3 ACL policies")
    
    # Determine which policies to delete
    to_delete = []
    
    # If we have a results file, extract policy IDs from it
    if results_file:
        try:
            with open(results_file, 'r') as f:
                results_data = json.load(f)
            
            policy_ids_from_file = set()
            for policy in results_data.get('policies', []):
                if policy.get('id') and policy.get('success'):
                    policy_ids_from_file.add(policy['id'])
            
            # Match policies by ID
            for policy in policy_list:
                if policy['id'] in policy_ids_from_file:
                    to_delete.append(policy)
                    
            print(f"Found {len(to_delete)} policies to delete from results file")
            
        except Exception as e:
            print(f"Error processing results file: {str(e)}")
            return 0
    
    # Otherwise use the pattern to match policy names
    elif pattern:
        regex = re.compile(pattern)
        for policy in policy_list:
            if regex.search(policy['name']):
                to_delete.append(policy)
                
        print(f"Found {len(to_delete)} policies matching pattern '{pattern}'")
    
    # If no match criteria, error out
    else:
        print("Error: Either a pattern or results file must be specified")
        return 0
    
    # Apply max deletions limit if specified
    if max_deletions and len(to_delete) > max_deletions:
        print(f"Limiting to {max_deletions} deletions as specified")
        to_delete = to_delete[:max_deletions]
    
    # Delete the policies
    success_count = 0
    error_count = 0
    
    print(f"\nStarting deletion of {len(to_delete)} policies...")
    
    for policy in to_delete:
        policy_id = policy['id']
        policy_name = policy['name']
        
        print(f"Deleting policy '{policy_name}' (ID: {policy_id})...")
        success = vsz.deleteL3ACLPolicy(host, token, policy_id)
        
        if success:
            success_count += 1
            print(f"Policy '{policy_name}' deleted successfully")
        else:
            error_count += 1
            print(f"Failed to delete policy '{policy_name}'")
        
        # Report progress
        if success_count % 10 == 0:
            print(f"Progress: Deleted {success_count} policies successfully")
        
        # Add delay between requests to prevent overloading the server
        if policy != to_delete[-1]:  # Skip delay after last policy
            time.sleep(delay)
    
    # Print summary
    print("\nCleanup Summary:")
    print(f"Total policies successfully deleted: {success_count}")
    print(f"Total errors encountered: {error_count}")
    
    return success_count

def main():
    parser = argparse.ArgumentParser(description='Delete SmartZone L3 ACL policies created by scale tests')
    parser.add_argument('--host', required=True, help='SmartZone hostname or IP address')
    parser.add_argument('--username', required=True, help='SmartZone admin username')
    parser.add_argument('--password', required=True, help='SmartZone admin password')
    parser.add_argument('--domain', help='Domain name (optional)')
    parser.add_argument('--pattern', default='^test\\d+$', help='Regex pattern to match policy names (default: ^test\\d+$)')
    parser.add_argument('--results-file', help='JSON file containing test results to delete')
    parser.add_argument('--max-deletions', type=int, help='Maximum number of policies to delete')
    parser.add_argument('--delay', type=float, default=0.5, help='Delay between policy deletions in seconds (default: 0.5)')
    parser.add_argument('--force', action='store_true', help='Do not ask for confirmation before deleting')
    
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
        
        # Get confirmation unless --force is specified
        if not args.force:
            # Be clear about what we're going to delete
            if args.results_file:
                confirm_msg = f"This will delete all policies from results file '{args.results_file}'."
            else:
                confirm_msg = f"This will delete all policies with names matching pattern '{args.pattern}'."
                
            if args.max_deletions:
                confirm_msg += f" Limiting to a maximum of {args.max_deletions} deletions."
            
            confirm_msg += "\nAre you sure you want to continue? (y/n): "
            confirm = input(confirm_msg)
            
            if confirm.lower() != 'y':
                print("Operation canceled.")
                vsz.deleteToken(args.host, token)
                sys.exit(0)
        
        # Perform the deletion
        deleted_count = delete_acl_policies(
            vsz, args.host, token, domain_id,
            pattern=args.pattern,
            results_file=args.results_file,
            max_deletions=args.max_deletions,
            delay=args.delay
        )
        
        print(f"\nCleanup completed. {deleted_count} policies deleted.")
        
    except Exception as e:
        print(f"Error during cleanup: {str(e)}")
        import traceback
        traceback.print_exc()
    
    finally:
        # Release token
        print("\nReleasing authentication token...")
        vsz.deleteToken(args.host, token)
        print("Done")


if __name__ == "__main__":
    main()
