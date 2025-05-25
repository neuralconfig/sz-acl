#!/usr/bin/env python3
"""
SmartZone Firewall Profile Web Application
A Flask web app for creating firewall profiles via SmartZone API
"""

import os
import json
import tempfile
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_file, flash, redirect, url_for
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge
import csv
import io
import copy
import secrets

# Import our existing modules
from create_firewall_profile import vSZ_calls
from csv_utils import csv_to_json

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# Configuration
UPLOAD_FOLDER = tempfile.gettempdir()
ALLOWED_EXTENSIONS = {'csv', 'json'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Security headers middleware
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline';"
    return response

# Error handlers
@app.errorhandler(413)
@app.errorhandler(RequestEntityTooLarge)
def handle_file_too_large(e):
    return jsonify({'error': 'File too large. Maximum size is 16MB'}), 413

@app.errorhandler(500)
def handle_server_error(e):
    return jsonify({'error': 'Internal server error'}), 500

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/templates/rules')
def download_rules_template():
    """Download CSV template for ACL rules"""
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header with all required columns
    writer.writerow([
        'description', 'protocol', 'action', 'direction',
        'sourceIp', 'sourceIpMask', 'enableSourceIpSubnet',
        'destinationIp', 'destinationIpMask', 'enableDestinationIpSubnet',
        'sourceMinPort', 'sourceMaxPort', 'enableSourcePortRange',
        'destinationMinPort', 'destinationMaxPort', 'enableDestinationPortRange',
        'customProtocol'
    ])
    
    # Write example rules
    writer.writerow([
        'Allow DNS', 'UDP', 'ALLOW', 'DUAL',
        '192.168.X.0', '255.255.255.0', 'true',
        '8.8.8.8', '255.255.255.255', 'true',
        '', '', 'false',
        '53', '53', 'false',
        ''
    ])
    writer.writerow([
        'Allow HTTPS', 'TCP', 'ALLOW', 'DUAL',
        '192.168.X.0', '255.255.255.0', 'true',
        '', '', 'false',
        '', '', 'false',
        '443', '443', 'false',
        ''
    ])
    writer.writerow([
        'Allow HTTP', 'TCP', 'ALLOW', 'DUAL',
        '192.168.X.0', '255.255.255.0', 'true',
        '', '', 'false',
        '', '', 'false',
        '80', '80', 'false',
        ''
    ])
    writer.writerow([
        'Block all other traffic', '', 'BLOCK', 'DUAL',
        '', '', 'false',
        '', '', 'false',
        '', '', 'false',
        '', '', 'false',
        ''
    ])
    
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode()),
        mimetype='text/csv',
        as_attachment=True,
        download_name='acl_rules_template.csv'
    )

@app.route('/templates/wildcard')
def download_wildcard_template():
    """Download CSV template for wildcard sites"""
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow(['name', 'octet'])
    
    # Write example entries
    writer.writerow(['Site_A', '10'])
    writer.writerow(['Site_B', '20'])
    writer.writerow(['Site_C', '30'])
    
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode()),
        mimetype='text/csv',
        as_attachment=True,
        download_name='wildcard_sites_template.csv'
    )

@app.route('/api/create-profile', methods=['POST'])
def create_profile():
    """Create firewall profile(s) via API"""
    try:
        # Get form data and sanitize inputs
        hostname = request.form.get('hostname', '').strip()
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        domain = request.form.get('domain', '').strip()
        profile_name = request.form.get('profile_name', '').strip()
        description = request.form.get('description', '').strip()
        default_action = request.form.get('default_action', 'ALLOW')
        uplink_rate = request.form.get('uplink_rate', '').strip()
        downlink_rate = request.form.get('downlink_rate', '').strip()
        
        # Input validation
        if default_action not in ['ALLOW', 'BLOCK']:
            return jsonify({'error': 'Invalid default action'}), 400
        
        # Validate required fields
        if not all([hostname, username, password]):
            return jsonify({'error': 'Missing required credentials'}), 400
        
        # Handle file uploads
        rules_file = request.files.get('rules_file')
        wildcard_file = request.files.get('wildcard_file')
        
        if not rules_file:
            return jsonify({'error': 'Rules file is required'}), 400
        
        # Save uploaded files temporarily
        rules_path = None
        wildcard_path = None
        
        if rules_file and allowed_file(rules_file.filename):
            rules_filename = secure_filename(rules_file.filename)
            rules_path = os.path.join(app.config['UPLOAD_FOLDER'], rules_filename)
            rules_file.save(rules_path)
        else:
            return jsonify({'error': 'Invalid rules file'}), 400
        
        if wildcard_file and allowed_file(wildcard_file.filename):
            wildcard_filename = secure_filename(wildcard_file.filename)
            wildcard_path = os.path.join(app.config['UPLOAD_FOLDER'], wildcard_filename)
            wildcard_file.save(wildcard_path)
        
        # Initialize API handler
        vsz = vSZ_calls()
        
        # Authenticate
        token = vsz.getToken(hostname, username, password)
        
        results = []
        
        try:
            # Get domain ID if specified
            domain_id = None
            if domain:
                domain_id = vsz.getDomainIDByName(hostname, domain, token)
                if not domain_id:
                    return jsonify({'error': f'Domain {domain} not found'}), 404
            
            # Load rules
            rules_data = []
            if rules_path.lower().endswith('.csv'):
                json_data = csv_to_json(rules_path)
                rules_data = json.loads(json_data)
            else:
                with open(rules_path, 'r') as f:
                    data = json.load(f)
                    if isinstance(data, dict) and 'l3AclRuleList' in data:
                        rules_data = data['l3AclRuleList']
                    elif isinstance(data, list):
                        rules_data = data
            
            # Process rate limits
            uplink_mbps = float(uplink_rate) if uplink_rate else None
            downlink_mbps = float(downlink_rate) if downlink_rate else None
            
            # If wildcard file provided, create multiple profiles
            if wildcard_path:
                wildcard_entries = []
                with open(wildcard_path, 'r', newline='') as f:
                    reader = csv.DictReader(f)
                    wildcard_entries = list(reader)
                
                for entry in wildcard_entries:
                    site_name = entry['name'].strip('"')
                    octet_value = int(entry['octet'])
                    
                    # Create payload for this site
                    site_rules = copy.deepcopy(rules_data)
                    
                    # Apply wildcard replacement
                    for rule in site_rules:
                        if "sourceIp" in rule and rule["sourceIp"]:
                            rule["sourceIp"] = rule["sourceIp"].replace("X", str(octet_value)).replace("x", str(octet_value))
                        if "destinationIp" in rule and rule["destinationIp"]:
                            rule["destinationIp"] = rule["destinationIp"].replace("X", str(octet_value)).replace("x", str(octet_value))
                    
                    # Create L3 ACL payload
                    l3_acl_payload = {
                        "name": site_name,
                        "defaultAction": default_action,
                        "l3AclRuleList": site_rules
                    }
                    
                    if domain_id:
                        l3_acl_payload["domainId"] = domain_id
                    if description:
                        l3_acl_payload["description"] = description
                    
                    # Create L3 ACL Policy
                    l3_response = vsz.createL3ACLPolicy(hostname, token, l3_acl_payload)
                    
                    if l3_response.status_code in [200, 201]:
                        l3_policy_id = l3_response.json().get('id')
                        
                        # Create Firewall Profile
                        firewall_payload = {
                            "name": site_name,
                            "l3AccessControlPolicyId": l3_policy_id
                        }
                        
                        if domain_id:
                            firewall_payload["domainId"] = domain_id
                        if description:
                            firewall_payload["description"] = description
                        if uplink_mbps:
                            firewall_payload["uplinkRateLimitingMbps"] = uplink_mbps
                        if downlink_mbps:
                            firewall_payload["downlinkRateLimitingMbps"] = downlink_mbps
                        
                        firewall_response = vsz.createFirewallProfile(hostname, token, firewall_payload)
                        
                        if firewall_response and firewall_response.status_code in [200, 201]:
                            firewall_id = firewall_response.json().get('id')
                            results.append({
                                'site': site_name,
                                'status': 'success',
                                'firewall_id': firewall_id,
                                'l3_acl_id': l3_policy_id
                            })
                        else:
                            # Clean up L3 ACL
                            vsz.deleteL3ACLPolicy(hostname, token, l3_policy_id)
                            error_msg = 'Failed to create firewall profile'
                            if firewall_response:
                                try:
                                    error_data = firewall_response.json()
                                    if 'message' in error_data:
                                        error_msg = f"Firewall Profile Error: {error_data['message']}"
                                except:
                                    pass
                            results.append({
                                'site': site_name,
                                'status': 'failed',
                                'error': error_msg
                            })
                    else:
                        error_msg = 'Failed to create L3 ACL policy'
                        try:
                            error_data = l3_response.json()
                            if 'message' in error_data:
                                error_msg = f"L3 ACL Error: {error_data['message']}"
                        except:
                            error_msg = f"L3 ACL Error: HTTP {l3_response.status_code}"
                        results.append({
                            'site': site_name,
                            'status': 'failed',
                            'error': error_msg
                        })
            
            # Single profile creation
            else:
                if not profile_name:
                    return jsonify({'error': 'Profile name is required when not using wildcard file'}), 400
                
                # Create L3 ACL payload
                l3_acl_payload = {
                    "name": profile_name,
                    "defaultAction": default_action,
                    "l3AclRuleList": rules_data
                }
                
                if domain_id:
                    l3_acl_payload["domainId"] = domain_id
                if description:
                    l3_acl_payload["description"] = description
                
                # Create L3 ACL Policy
                l3_response = vsz.createL3ACLPolicy(hostname, token, l3_acl_payload)
                
                if l3_response.status_code in [200, 201]:
                    l3_policy_id = l3_response.json().get('id')
                    
                    # Create Firewall Profile
                    firewall_payload = {
                        "name": profile_name,
                        "l3AccessControlPolicyId": l3_policy_id
                    }
                    
                    if domain_id:
                        firewall_payload["domainId"] = domain_id
                    if description:
                        firewall_payload["description"] = description
                    if uplink_mbps:
                        firewall_payload["uplinkRateLimitingMbps"] = uplink_mbps
                    if downlink_mbps:
                        firewall_payload["downlinkRateLimitingMbps"] = downlink_mbps
                    
                    firewall_response = vsz.createFirewallProfile(hostname, token, firewall_payload)
                    
                    if firewall_response and firewall_response.status_code in [200, 201]:
                        firewall_id = firewall_response.json().get('id')
                        results.append({
                            'site': profile_name,
                            'status': 'success',
                            'firewall_id': firewall_id,
                            'l3_acl_id': l3_policy_id
                        })
                    else:
                        # Clean up L3 ACL
                        vsz.deleteL3ACLPolicy(hostname, token, l3_policy_id)
                        error_msg = 'Failed to create firewall profile'
                        if firewall_response:
                            try:
                                error_data = firewall_response.json()
                                if 'message' in error_data:
                                    error_msg = f"Firewall Profile Error: {error_data['message']}"
                            except:
                                pass
                        return jsonify({'error': error_msg}), 500
                else:
                    error_msg = 'Failed to create L3 ACL policy'
                    try:
                        error_data = l3_response.json()
                        if 'message' in error_data:
                            error_msg = f"L3 ACL Error: {error_data['message']}"
                    except:
                        error_msg = f"L3 ACL Error: HTTP {l3_response.status_code}"
                    return jsonify({'error': error_msg}), 500
        
        finally:
            # Clean up
            vsz.deleteToken(hostname, token)
            if rules_path and os.path.exists(rules_path):
                os.remove(rules_path)
            if wildcard_path and os.path.exists(wildcard_path):
                os.remove(wildcard_path)
        
        return jsonify({
            'success': True,
            'results': results
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/list-domains', methods=['POST'])
def list_domains():
    """List available domains"""
    try:
        hostname = request.json.get('hostname')
        username = request.json.get('username')
        password = request.json.get('password')
        
        if not all([hostname, username, password]):
            return jsonify({'error': 'Missing required credentials'}), 400
        
        vsz = vSZ_calls()
        token = vsz.getToken(hostname, username, password)
        
        try:
            domains = vsz.listDomains(hostname, token)
            domain_list = [{'name': d['name'], 'id': d['id']} for d in domains] if domains else []
            return jsonify({'domains': domain_list})
        finally:
            vsz.deleteToken(hostname, token)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/list-firewall-profiles', methods=['POST'])
def list_firewall_profiles():
    """List firewall profiles with optional pattern matching"""
    try:
        data = request.json
        hostname = data.get('hostname')
        username = data.get('username')
        password = data.get('password')
        domain = data.get('domain')
        pattern = data.get('pattern', '')
        
        if not all([hostname, username, password]):
            return jsonify({'error': 'Missing required credentials'}), 400
        
        vsz = vSZ_calls()
        token = vsz.getToken(hostname, username, password)
        
        try:
            # Get domain ID if specified
            domain_id = None
            if domain:
                domain_id = vsz.getDomainIDByName(hostname, domain, token)
            
            # List profiles
            profiles_response = vsz.listFirewallProfiles(hostname, token, domain_id)
            
            if not profiles_response or 'list' not in profiles_response:
                return jsonify({'profiles': []})
            
            profiles = profiles_response['list']
            
            # Filter by pattern if provided
            if pattern:
                import re
                regex = re.compile(pattern)
                profiles = [p for p in profiles if regex.search(p['name'])]
            
            # Get additional details for each profile
            profile_list = []
            for profile in profiles:
                # Get full profile details to get L3 ACL ID
                full_profile = vsz.getFirewallProfile(hostname, token, profile['id'])
                if full_profile:
                    profile_list.append({
                        'id': profile['id'],
                        'name': profile['name'],
                        'l3AclId': full_profile.get('l3AccessControlPolicyId', ''),
                        'description': profile.get('description', '')
                    })
            
            return jsonify({'profiles': profile_list})
        finally:
            vsz.deleteToken(hostname, token)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/delete-firewall-profiles', methods=['POST'])
def delete_firewall_profiles():
    """Delete selected firewall profiles and optionally their L3 ACLs"""
    try:
        data = request.json
        hostname = data.get('hostname')
        username = data.get('username')
        password = data.get('password')
        profiles_to_delete = data.get('profiles', [])
        delete_l3_acls = data.get('deleteL3Acls', True)
        
        if not all([hostname, username, password]):
            return jsonify({'error': 'Missing required credentials'}), 400
        
        if not profiles_to_delete:
            return jsonify({'error': 'No profiles selected for deletion'}), 400
        
        vsz = vSZ_calls()
        token = vsz.getToken(hostname, username, password)
        
        results = []
        
        try:
            for profile in profiles_to_delete:
                profile_id = profile['id']
                profile_name = profile['name']
                l3_acl_id = profile.get('l3AclId')
                
                # Delete firewall profile
                success = vsz.deleteFirewallProfile(hostname, token, profile_id)
                
                if success:
                    result = {
                        'profile': profile_name,
                        'status': 'success',
                        'message': 'Firewall profile deleted'
                    }
                    
                    # Delete L3 ACL if requested
                    if delete_l3_acls and l3_acl_id:
                        l3_success = vsz.deleteL3ACLPolicy(hostname, token, l3_acl_id)
                        if l3_success:
                            result['l3AclStatus'] = 'deleted'
                        else:
                            result['l3AclStatus'] = 'failed'
                    
                    results.append(result)
                else:
                    results.append({
                        'profile': profile_name,
                        'status': 'failed',
                        'message': 'Failed to delete firewall profile'
                    })
            
            return jsonify({'success': True, 'results': results})
        
        finally:
            vsz.deleteToken(hostname, token)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=8080)