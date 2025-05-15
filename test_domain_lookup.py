#!/usr/bin/env python3
"""
SmartZone Domain Lookup Test Script
This script helps troubleshoot domain lookup issues by listing all available domains
and testing specific domain lookups with detailed debugging.
"""

import argparse
import json
import sys
import requests
from create_l3_acl import vSZ_calls

def main():
    parser = argparse.ArgumentParser(description='Test SmartZone domain lookup functionality')
    parser.add_argument('--host', required=True, help='SmartZone hostname or IP address')
    parser.add_argument('--username', required=True, help='SmartZone admin username')
    parser.add_argument('--password', required=True, help='SmartZone admin password')
    parser.add_argument('--domain', help='Domain name to look up (optional)')
    parser.add_argument('--api-version', default='v13_0', help='API version to use (default: v13_0)')
    parser.add_argument('--verbose', action='store_true', help='Show verbose API request/response details')
    
    args = parser.parse_args()
    
    # Initialize API handler
    vsz = vSZ_calls()
    vsz.api_version = args.api_version
    
    # Get authentication token
    print(f"Connecting to SmartZone controller {args.host}...")
    try:
        token = vsz.getToken(args.host, args.username, args.password)
        print("Authentication successful")
    except Exception as e:
        print(f"Error authenticating: {str(e)}")
        sys.exit(1)
    
    try:
        # Format host URL correctly
        if not args.host.startswith('http'):
            host_url = f"https://{args.host}:8443"
        else:
            host_url = args.host
            
        # 1. List all domains using the built-in function
        print("\n=== LISTING ALL DOMAINS ===")
        domains = vsz.listDomains(args.host, token)
        
        if domains:
            print(f"Found {len(domains)} domains using built-in listDomains function:")
            for i, domain in enumerate(domains, 1):
                print(f"  {i}. Name: {domain.get('name', 'N/A')}, ID: {domain.get('id', 'N/A')}")
        else:
            print("No domains found or error retrieving domains using built-in function")
        
        # 2. Try direct API call to list domains for more details
        print("\n=== DIRECT API CALL TO LIST DOMAINS ===")
        try:
            url = f"{host_url}/wsg/api/public/{vsz.api_version}/domains?serviceTicket={token}"
            print(f"API URL: {url}")
            
            response = requests.get(url, verify=False)
            print(f"Status code: {response.status_code}")
            
            if response.status_code == 200:
                domain_data = response.json()
                if args.verbose:
                    print("Full API response:")
                    print(json.dumps(domain_data, indent=2))
                
                domain_list = domain_data.get('list', [])
                print(f"Found {len(domain_list)} domains in direct API call:")
                for i, domain in enumerate(domain_list, 1):
                    print(f"  {i}. Name: {domain.get('name', 'N/A')}, ID: {domain.get('id', 'N/A')}")
                    # Show additional domain details
                    print(f"     Description: {domain.get('description', 'N/A')}")
                    print(f"     Created: {domain.get('createdTime', 'N/A')}")
                    if domain.get('parentDomainId'):
                        print(f"     Parent Domain ID: {domain.get('parentDomainId', 'N/A')}")
            else:
                print(f"Error response: {response.text}")
        except Exception as e:
            print(f"Error in direct API call: {str(e)}")
        
        # 3. Test specific domain lookup if provided
        if args.domain:
            print(f"\n=== TESTING DOMAIN LOOKUP FOR '{args.domain}' ===")
            
            # Try the built-in function first
            print(f"Using built-in getDomainIDByName function:")
            domain_id = vsz.getDomainIDByName(args.host, args.domain, token)
            
            if domain_id:
                print(f"  Success! Domain ID: {domain_id}")
            else:
                print(f"  Failed to find domain using built-in function")
            
            # Try a direct API call with detailed logging
            print("\nUsing direct API call:")
            try:
                url = f"{host_url}/wsg/api/public/{vsz.api_version}/domains/byName/{args.domain}?serviceTicket={token}"
                print(f"API URL: {url}")
                
                response = requests.get(url, verify=False)
                print(f"Status code: {response.status_code}")
                
                if response.status_code == 200:
                    domain_data = response.json()
                    if args.verbose:
                        print("Full API response:")
                        print(json.dumps(domain_data, indent=2))
                    
                    if 'id' in domain_data:
                        print(f"  Success! Domain ID: {domain_data['id']}")
                    else:
                        print(f"  Domain found but no ID in response")
                else:
                    print(f"  Error response: {response.text}")
            except Exception as e:
                print(f"  Error in direct API call: {str(e)}")
            
            # 4. Try fuzzy search to find similar domain names
            print("\n=== SEARCHING FOR SIMILAR DOMAIN NAMES ===")
            search_term = args.domain.lower()
            
            if domains:
                found_similar = False
                print("Domains with similar names:")
                for domain in domains:
                    name = domain.get('name', '').lower()
                    # Look for partial matches or similar names
                    if search_term in name or name in search_term or (
                            len(search_term) > 3 and 
                            sum(c1 == c2 for c1, c2 in zip(name, search_term)) > len(search_term) / 2
                       ):
                        found_similar = True
                        print(f"  Similar: '{domain.get('name')}', ID: {domain.get('id')}")
                
                if not found_similar:
                    print("  No similar domain names found")
            
            # 5. Try different API versions
            print("\n=== TRYING DIFFERENT API VERSIONS ===")
            for version in ['v9_0', 'v10_0', 'v11_0', 'v12_0', 'v13_0', 'v14_0']:
                if version == vsz.api_version:
                    continue  # Skip the one we already tried
                
                try:
                    url = f"{host_url}/wsg/api/public/{version}/domains/byName/{args.domain}?serviceTicket={token}"
                    print(f"Trying API version {version}...")
                    
                    response = requests.get(url, verify=False)
                    
                    if response.status_code == 200:
                        domain_data = response.json()
                        print(f"  Success with API version {version}! Domain ID: {domain_data.get('id', 'N/A')}")
                    elif response.status_code == 404:
                        print(f"  Not found with API version {version}")
                    else:
                        print(f"  Error with API version {version}: {response.status_code}")
                except Exception as e:
                    print(f"  Error with API version {version}: {str(e)}")
        
    except Exception as e:
        print(f"Error during test: {str(e)}")
        import traceback
        traceback.print_exc()
    
    finally:
        # Release token
        print("\nReleasing authentication token...")
        vsz.deleteToken(args.host, token)
        print("Done")


if __name__ == "__main__":
    main()
