#!/usr/bin/env python3
"""
CSV Utilities for SmartZone L3 ACL Rules
This module provides functionality to convert between CSV and JSON formats for ACL rules.
"""

import csv
import json
import sys
import os

# Define the CSV header fields
CSV_FIELDS = [
    "description", "protocol", "action", "direction",
    "sourceIp", "sourceIpMask", "enableSourceIpSubnet",
    "destinationIp", "destinationIpMask", "enableDestinationIpSubnet",
    "sourceMinPort", "sourceMaxPort", "enableSourcePortRange",
    "destinationMinPort", "destinationMaxPort", "enableDestinationPortRange",
    "customProtocol"
]

# Fields that should be converted to boolean
BOOLEAN_FIELDS = [
    "enableSourceIpSubnet", "enableDestinationIpSubnet", 
    "enableSourcePortRange", "enableDestinationPortRange"
]

# Fields that should be converted to integer
INTEGER_FIELDS = [
    "sourceMinPort", "sourceMaxPort", 
    "destinationMinPort", "destinationMaxPort",
    "customProtocol"
]

def csv_to_json(csv_file, json_file=None):
    """
    Convert a CSV file of ACL rules to JSON format.
    
    Args:
        csv_file (str): Path to the CSV file
        json_file (str, optional): Path to save the JSON output. If None, returns the JSON as a string.
        
    Returns:
        str or None: If json_file is None, returns the JSON as a string, otherwise returns None.
    """
    rules = []
    
    try:
        with open(csv_file, 'r', newline='') as file:
            reader = csv.DictReader(file)
            
            # Verify CSV has required fields
            if not reader.fieldnames:
                raise ValueError("CSV file is empty or has no headers")
                
            missing_fields = set(["description", "protocol", "action", "direction"]) - set(reader.fieldnames)
            if missing_fields:
                raise ValueError(f"CSV is missing required fields: {', '.join(missing_fields)}")
            
            for row in reader:
                rule = {}
                for field in reader.fieldnames:
                    # Skip empty fields
                    if field not in row or not row[field].strip():
                        continue
                        
                    value = row[field].strip()
                    
                    # Convert boolean fields
                    if field in BOOLEAN_FIELDS:
                        # Convert various boolean representations
                        value = value.lower()
                        if value in ('true', 'yes', 'y', '1', 'enable', 'enabled'):
                            rule[field] = True
                        elif value in ('false', 'no', 'n', '0', 'disable', 'disabled'):
                            rule[field] = False
                        else:
                            print(f"Warning: Invalid boolean value '{value}' for field '{field}'. Using default False.")
                            rule[field] = False
                    
                    # Convert integer fields
                    elif field in INTEGER_FIELDS:
                        try:
                            rule[field] = int(value)
                        except ValueError:
                            print(f"Warning: Invalid integer value '{value}' for field '{field}'. Skipping.")
                    
                    # Handle string fields
                    else:
                        rule[field] = value
                
                # Set default values for boolean fields if not specified
                for field in BOOLEAN_FIELDS:
                    if field not in rule:
                        rule[field] = False
                
                rules.append(rule)
        
        # Convert to JSON
        json_data = json.dumps(rules, indent=2)
        
        # Save to file if specified
        if json_file:
            with open(json_file, 'w') as f:
                f.write(json_data)
            return None
        else:
            return json_data
            
    except Exception as e:
        print(f"Error converting CSV to JSON: {str(e)}")
        return None

def json_to_csv(json_file, csv_file=None):
    """
    Convert a JSON file of ACL rules to CSV format.
    
    Args:
        json_file (str): Path to the JSON file
        csv_file (str, optional): Path to save the CSV output. If None, returns the CSV as a string.
        
    Returns:
        str or None: If csv_file is None, returns the CSV as a string, otherwise returns None.
    """
    try:
        # Load JSON data
        with open(json_file, 'r') as f:
            data = json.load(f)
        
        # Handle different JSON formats
        if isinstance(data, dict) and 'l3AclRuleList' in data:
            rules = data['l3AclRuleList']
        elif isinstance(data, list):
            rules = data
        else:
            raise ValueError("Invalid JSON format. Expected an array of rules or an object with 'l3AclRuleList'")
        
        # Determine output
        if csv_file:
            output_file = open(csv_file, 'w', newline='')
            writer = csv.DictWriter(output_file, fieldnames=CSV_FIELDS)
            writer.writeheader()
        else:
            import io
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=CSV_FIELDS)
            writer.writeheader()
        
        # Write rules to CSV
        for rule in rules:
            # Create a new row with only the fields we care about
            row = {}
            for field in CSV_FIELDS:
                if field in rule:
                    row[field] = rule[field]
            writer.writerow(row)
        
        # Clean up and return
        if csv_file:
            output_file.close()
            return None
        else:
            csv_data = output.getvalue()
            output.close()
            return csv_data
            
    except Exception as e:
        print(f"Error converting JSON to CSV: {str(e)}")
        return None

def create_csv_template(output_file=None):
    """
    Create a CSV template file with sample rules.
    
    Args:
        output_file (str, optional): Path to save the CSV template. If None, returns the CSV as a string.
        
    Returns:
        str or None: If output_file is None, returns the CSV as a string, otherwise returns None.
    """
    # Sample rules
    sample_rules = [
        {
            "description": "Allow specific TCP subnet traffic",
            "protocol": "TCP",
            "action": "ALLOW",
            "direction": "DUAL",
            "sourceIp": "172.17.26.55",
            "sourceIpMask": "255.255.255.0",
            "enableSourceIpSubnet": True,
            "destinationIp": "172.17.26.60",
            "destinationIpMask": "255.255.0.0",
            "enableDestinationIpSubnet": False,
            "sourceMinPort": 80,
            "sourceMaxPort": 80,
            "enableSourcePortRange": False,
            "destinationMinPort": 0,
            "destinationMaxPort": 0,
            "enableDestinationPortRange": False
        },
        {
            "description": "Block specific UDP subnet traffic",
            "protocol": "UDP",
            "action": "BLOCK",
            "direction": "INBOUND",
            "sourceIp": "192.168.1.0",
            "sourceIpMask": "255.255.255.0",
            "enableSourceIpSubnet": True,
            "destinationIp": "10.0.0.0",
            "destinationIpMask": "255.0.0.0",
            "enableDestinationIpSubnet": False
        },
        {
            "description": "Allow HTTPS traffic to web servers",
            "protocol": "TCP",
            "action": "ALLOW",
            "direction": "INBOUND",
            "destinationIp": "192.168.10.0",
            "destinationIpMask": "255.255.255.0",
            "enableDestinationIpSubnet": True,
            "destinationMinPort": 443,
            "destinationMaxPort": 443,
            "enableDestinationPortRange": True
        }
    ]
    
    # Determine output
    if output_file:
        output_file = open(output_file, 'w', newline='')
        writer = csv.DictWriter(output_file, fieldnames=CSV_FIELDS)
        writer.writeheader()
    else:
        import io
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=CSV_FIELDS)
        writer.writeheader()
    
    # Write rules to CSV
    for rule in sample_rules:
        # Create a new row with only the fields we care about
        row = {}
        for field in CSV_FIELDS:
            if field in rule:
                row[field] = rule[field]
        writer.writerow(row)
    
    # Clean up and return
    if output_file:
        output_file.close()
        return None
    else:
        csv_data = output.getvalue()
        output.close()
        return csv_data

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Convert between CSV and JSON formats for SmartZone L3 ACL rules')
    parser.add_argument('--csv-to-json', help='Convert CSV file to JSON')
    parser.add_argument('--json-to-csv', help='Convert JSON file to CSV')
    parser.add_argument('--output', help='Output file path')
    parser.add_argument('--create-template', action='store_true', help='Create a CSV template file')
    
    args = parser.parse_args()
    
    if args.csv_to_json:
        output = args.output or args.csv_to_json.replace('.csv', '.json')
        if args.csv_to_json == output:
            output += '.json'
        print(f"Converting {args.csv_to_json} to {output}...")
        csv_to_json(args.csv_to_json, output)
        print(f"Conversion complete. JSON saved to {output}")
        
    elif args.json_to_csv:
        output = args.output or args.json_to_csv.replace('.json', '.csv')
        if args.json_to_csv == output:
            output += '.csv'
        print(f"Converting {args.json_to_csv} to {output}...")
        json_to_csv(args.json_to_csv, output)
        print(f"Conversion complete. CSV saved to {output}")
        
    elif args.create_template:
        output = args.output or "acl_rules_template.csv"
        print(f"Creating CSV template file {output}...")
        create_csv_template(output)
        print(f"Template created and saved to {output}")
        
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
