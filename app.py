from flask import Flask, render_template, request, jsonify, session
import re
import os
import json
from datetime import datetime
import threading
import subprocess
import sys
from scanners.scanner_manager import ScannerManager
from google_sheets_logger import GoogleSheetsLogger
from email_verifier import verify_gmail
from report_generator import generate_professional_report
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# Initialize components
scanner_manager = ScannerManager()
sheets_logger = GoogleSheetsLogger()

# Store scan results temporarily
scan_results = {}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/verify_email', methods=['POST'])
def verify_email():
    data = request.json
    email = data.get('email')
    
    if not email or not re.match(r'^[a-zA-Z0-9._%+-]+@gmail\.com$', email):
        return jsonify({'valid': False, 'message': 'Invalid Gmail ID format'})
    
    # Verify Gmail exists (using Google's API or verification service)
    is_valid = verify_gmail(email)
    
    if is_valid:
        session['gmail'] = email
        return jsonify({'valid': True, 'message': 'Email verified successfully'})
    else:
        return jsonify({'valid': False, 'message': 'Gmail ID does not exist or cannot be verified'})

@app.route('/check_scanner', methods=['POST'])
def check_scanner():
    data = request.json
    scanner_type = data.get('scanner_type')
    
    # Check if scanner is installed
    is_installed = scanner_manager.check_scanner_installed(scanner_type)
    
    return jsonify({
        'installed': is_installed,
        'scanner': scanner_type
    })

@app.route('/scan', methods=['POST'])
def scan():
    if 'gmail' not in session:
        return jsonify({'error': 'Please verify your Gmail first'}), 401
    
    data = request.json
    scan_type = data.get('scan_type')
    target = data.get('target')
    gmail = session['gmail']
    
    # Validate target
    if not target:
        return jsonify({'error': 'Target URL/IP is required'}), 400
    
    # Start scan in background thread
    scan_id = secrets.token_hex(8)
    thread = threading.Thread(
        target=run_scan,
        args=(scan_id, scan_type, target, gmail)
    )
    thread.daemon = True
    thread.start()
    
    return jsonify({
        'scan_id': scan_id,
        'message': 'Scan started successfully'
    })

def run_scan(scan_id, scan_type, target, gmail):
    """Run the actual scan"""
    try:
        # Initialize results
        results = {
            'scan_id': scan_id,
            'timestamp': datetime.now().isoformat(),
            'target': target,
            'scan_type': scan_type,
            'gmail': gmail,
            'status': 'running',
            'results': {},
            'vulnerabilities': []
        }
        
        scan_results[scan_id] = results
        
        # Check and install required scanners
        scanner_manager.ensure_scanners(scan_type)
        
        # Run the scan based on type
        if scan_type == 'all' or scan_type == 1:
            results['results']['nmap'] = scanner_manager.run_nmap(target)
            results['results']['nikto'] = scanner_manager.run_nikto(target)
            results['results']['whatweb'] = scanner_manager.run_whatweb(target)
            results['results']['curl'] = scanner_manager.run_curl(target)
        else:
            scanner_map = {
                2: 'nmap',
                3: 'nikto',
                4: 'curl',
                5: 'whatweb'
            }
            scanner_name = scanner_map.get(scan_type)
            if scanner_name:
                method = getattr(scanner_manager, f'run_{scanner_name}')
                results['results'][scanner_name] = method(target)
        
        # Analyze vulnerabilities
        results['vulnerabilities'] = analyze_vulnerabilities(results['results'])
        
        # Determine overall vulnerability stage
        results['vuln_stage'] = determine_vuln_stage(results['vulnerabilities'])
        
        # Generate professional report
        report_path = generate_professional_report(results)
        results['report_path'] = report_path
        
        # Log to Google Sheets
        sheets_logger.log_scan({
            'timestamp': results['timestamp'],
            'gmail': gmail,
            'scan_type': scan_type,
            'target': target,
            'vuln_stage': results['vuln_stage']
        })
        
        results['status'] = 'completed'
        scan_results[scan_id] = results
        
    except Exception as e:
        results['status'] = 'failed'
        results['error'] = str(e)
        scan_results[scan_id] = results

@app.route('/scan_status/<scan_id>')
def scan_status(scan_id):
    if scan_id in scan_results:
        return jsonify(scan_results[scan_id])
    return jsonify({'error': 'Scan not found'}), 404

@app.route('/download_report/<scan_id>')
def download_report(scan_id):
    if scan_id in scan_results:
        report_path = scan_results[scan_id].get('report_path')
        if report_path and os.path.exists(report_path):
            return send_file(report_path, as_attachment=True)
    return jsonify({'error': 'Report not found'}), 404

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
