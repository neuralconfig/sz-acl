#!/usr/bin/env python3
"""
SmartZone Firewall Profile Cleanup Script
This script deletes Firewall Profiles and their associated L3 ACL policies created by tests or matching a specified pattern.
"""

import argparse
import json
import sys
import time
import re
from datetime import datetime
from create_firewall_profile import vSZ_calls

def delete_firewall_profiles(vsz, host, token, domain_id=None, pattern=None, results_file=None, 
                            max_deletions=None, delay=0.5, delete_l3_acls=True):
    """Delete Firewall Profiles and optionally their associated L3 ACL policies"""
    
    # Get the list of current Firewall Profiles
    print("Retrieving existing Firewall Profiles...")
    profiles = vsz.listFirewallProfiles(host, token, domain_id)
    
    if not profiles or 'list' not in profiles or not profiles['list']:
        print("No firewall profiles found or error retrieving profiles")
        return 0
    
    profile_list = profiles['list']
    print(f"Found {len(profile_list)} Firewall Profiles")
    
    # Determine which profiles to delete
    to_delete = []
    
    # If we have a results file, extract profile IDs from it
    if results_file:
        try:
            with open(results_file, 'r') as f:
                results_data = json.load(f)
            
            profile_ids_from_file = set()
            for profile in results_data.get('firewall_profiles', []):
                if profile.get('firewall_profile_id') and profile.get('success'):
                    profile_ids_from_file.add(profile['firewall_profile_id'])
            
            # Match profiles by ID
            for profile in profile_list:
                if profile['id'] in profile_ids_from_file:
                    to_delete.append(profile)
                    
            print(f"Found {len(to_delete)} firewall profiles to delete from results file")
            
        except Exception as e:
            print(f"Error processing results file: {str(e)}")
            return 0
    
    # Otherwise use the pattern to match profile names
    elif pattern:
        regex = re.compile(pattern)
        for profile in profile_list:
            if regex.search(profile['name']):
                to_delete.append(profile)
                
        print(f"Found {len(to_delete)} firewall profiles matching pattern '{pattern}'")
    
    # If no match criteria, error out
    else:
        print("Error: Either a pattern or results file must be specified")
        return 0
    
    # Apply max deletions limit if specified
    if max_deletions and len(to_delete) > max_deletions:
        print(f"Limiting to {max_deletions} deletions as specified")
        to_delete = to_delete[:max_deletions]
    
    # Delete the profiles
    success_count = 0
    error_count = 0
    l3_acl_success_count = 0
    l3_acl_error_count = 0
    
    print(f"\nStarting deletion of {len(to_delete)} firewall profiles...")
    
    for profile in to_delete:
        profile_id = profile['id']
        profile_name = profile['name']
        
        # Get full profile details to retrieve L3 ACL policy ID
        l3_acl_policy_id = None
        if delete_l3_acls:
            print(f"Retrieving full profile details for '{profile_name}'...")
            full_profile = vsz.getFirewallProfile(host, token, profile_id)
            if full_profile:
                l3_acl_policy_id = full_profile.get('l3AccessControlPolicyId', '')
                if l3_acl_policy_id:
                    print(f"  Found L3 ACL policy ID: {l3_acl_policy_id}")
                else:
                    print(f"  No L3 ACL policy ID found in firewall profile")
            else:
                print(f"  Failed to retrieve full profile details")
        
        print(f"Deleting firewall profile '{profile_name}' (ID: {profile_id})...")
        success = vsz.deleteFirewallProfile(host, token, profile_id)
        
        if success:
            success_count += 1
            print(f"Firewall profile '{profile_name}' deleted successfully")
            
            # If profile deletion was successful and we want to delete L3 ACLs
            if delete_l3_acls and l3_acl_policy_id:
                print(f"  Deleting associated L3 ACL policy (ID: {l3_acl_policy_id})...")
                l3_success = vsz.deleteL3ACLPolicy(host, token, l3_acl_policy_id)
                
                if l3_success:
                    l3_acl_success_count += 1
                    print(f"  L3 ACL policy deleted successfully")
                else:
                    l3_acl_error_count += 1
                    print(f"  Failed to delete L3 ACL policy")
                
        else:
            error_count += 1
            print(f"Failed to delete firewall profile '{profile_name}'")
        
        # Report progress
        if success_count % 10 == 0 and success_count > 0:
            print(f"Progress: Deleted {success_count} firewall profiles successfully")
        
        # Add delay between requests to prevent overloading the server
        if profile != to_delete[-1]:  # Skip delay after last profile
            time.sleep(delay)
    
    # Print summary
    print("\nCleanup Summary:")
    print(f"Total firewall profiles successfully deleted: {success_count}")
    print(f"Total firewall profile deletion errors: {error_count}")
    if delete_l3_acls:
        print(f"Total L3 ACL policies successfully deleted: {l3_acl_success_count}")
        print(f"Total L3 ACL policy deletion errors: {l3_acl_error_count}")
    
    return success_count

def main():
    parser = argparse.ArgumentParser(description='Delete SmartZone Firewall Profiles and associated L3 ACL policies')
    parser.add_argument('--host', required=True, help='SmartZone hostname or IP address')
    parser.add_argument('--username', required=True, help='SmartZone admin username')
    parser.add_argument('--password', required=True, help='SmartZone admin password')
    parser.add_argument('--domain', help='Domain name (optional)')
    parser.add_argument('--pattern', default='^test.*', help='Regex pattern to match firewall profile names (default: ^test.*)')
    parser.add_argument('--results-file', help='JSON file containing test results to delete')
    parser.add_argument('--max-deletions', type=int, help='Maximum number of firewall profiles to delete')
    parser.add_argument('--delay', type=float, default=0.5, help='Delay between profile deletions in seconds (default: 0.5)')
    parser.add_argument('--force', action='store_true', help='Do not ask for confirmation before deleting')
    parser.add_argument('--keep-l3-acls', action='store_true', help='Do not delete associated L3 ACL policies (default: delete them)')
    
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
                confirm_msg = f"This will delete all firewall profiles from results file '{args.results_file}'."
            else:
                confirm_msg = f"This will delete all firewall profiles with names matching pattern '{args.pattern}'."
                
            if args.max_deletions:
                confirm_msg += f" Limiting to a maximum of {args.max_deletions} deletions."
            
            if not args.keep_l3_acls:
                confirm_msg += "\nThis will also delete the associated L3 ACL policies."
            
            confirm_msg += "\nAre you sure you want to continue? (y/n): "
            confirm = input(confirm_msg)
            
            if confirm.lower() != 'y':
                print("Operation canceled.")
                vsz.deleteToken(args.host, token)
                sys.exit(0)
        
        # Perform the deletion
        deleted_count = delete_firewall_profiles(
            vsz, args.host, token, domain_id,
            pattern=args.pattern,
            results_file=args.results_file,
            max_deletions=args.max_deletions,
            delay=args.delay,
            delete_l3_acls=not args.keep_l3_acls
        )
        
        print(f"\nCleanup completed. {deleted_count} firewall profiles deleted.")
        
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