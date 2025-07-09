from flask import Flask, render_template, request, jsonify, send_file
from scanner import VulnerabilityScanner
import json
import os
from datetime import datetime
import threading
import re

app = Flask(__name__)

# Create results directory if it doesn't exist
if not os.path.exists('results'):
    os.makedirs('results')

# Store active scans and completed scan results
active_scans = {}
completed_scans = {}
scan_threads = {}  # Store scan threads

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/start_scan', methods=['POST'])
def start_scan():
    data = request.json
    target = data.get('target')
    username = data.get('username')
    password = data.get('password')
    
    if not target:
        return jsonify({'error': 'Target is required'}), 400
    
    # Create a unique scan ID
    scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    # Initialize scanner
    scanner = VulnerabilityScanner(target, username, password)
    scanner.stop_scan = False  # Add stop flag
    
    # Store scanner instance
    active_scans[scan_id] = scanner
    
    # Start scan in background thread
    thread = threading.Thread(target=run_scan, args=(scan_id, scanner))
    thread.daemon = True
    scan_threads[scan_id] = thread  # Store thread reference
    thread.start()
    
    return jsonify({'scan_id': scan_id})

def run_scan(scan_id, scanner):
    try:
        # Initialize scan status
        scanner.scan_results["scan_details"]["scan_status"] = "Running"
        
        # Attempt authentication if credentials are provided
        if scanner.username and scanner.password and not scanner.stop_scan:
            if scanner.authenticate():
                scanner.scan_results["scan_details"]["authentication_status"] = "Successfully authenticated"
            else:
                scanner.scan_results["scan_details"]["authentication_status"] = "Authentication failed"
        
        # Run the scan if not stopped
        if not scanner.stop_scan:
            scanner.scan()
            # Don't update status here as it's already updated in scanner.scan()
        
        # Generate and save report
        report_path = save_scan_results(scan_id, scanner)
        completed_scans[scan_id] = report_path
        
    except Exception as e:
        print(f"Error during scan {scan_id}: {str(e)}")
        scanner.scan_results["scan_details"]["scan_status"] = "Error"
        scanner.scan_results["scan_details"]["error_message"] = str(e)
        # Save results even if there's an error
        try:
            report_path = save_scan_results(scan_id, scanner)
            completed_scans[scan_id] = report_path
        except:
            pass
    finally:
        # Clean up active scan
        if scan_id in active_scans:
            del active_scans[scan_id]
        if scan_id in scan_threads:
            del scan_threads[scan_id]

def save_scan_results(scan_id, scanner):
    """Save scan results to a file and return the file path"""
    try:
        # Create a safe filename
        safe_target = re.sub(r'[^\w\-_.]', '_', scanner.target)
        filename = f"results/scan_{safe_target}_{scan_id}.json"
        
        # Save results to file
        with open(filename, 'w') as f:
            json.dump(scanner.scan_results, f, indent=2)
        
        return filename
    except Exception as e:
        print(f"Error saving results: {str(e)}")
        return None

@app.route('/scan_status/<scan_id>')
def scan_status(scan_id):
    try:
        # Check if scan is completed
        if scan_id in completed_scans:
            filename = completed_scans[scan_id]
            try:
                with open(filename, 'r') as f:
                    scan_data = json.load(f)
                    return jsonify({
                        'status': 'completed',
                        'details': scan_data['scan_details'],
                        'vulnerabilities': scan_data['vulnerabilities'],
                        'summary': scan_data['summary']
                    })
            except Exception as e:
                print(f"Error reading completed scan data: {str(e)}")
                return jsonify({'error': 'Error reading scan data'}), 500
        
        # Check if scan is still running
        if scan_id in active_scans:
            scanner = active_scans[scan_id]
            return jsonify({
                'status': scanner.scan_results['scan_details']['scan_status'],
                'details': scanner.scan_results['scan_details'],
                'vulnerabilities': scanner.scan_results['vulnerabilities'],
                'summary': scanner.scan_results['summary']
            })
        
        return jsonify({'error': 'Scan not found'}), 404
    except Exception as e:
        print(f"Error getting scan status: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/download_report/<scan_id>')
def download_report(scan_id):
    try:
        # Check completed scans first
        if scan_id in completed_scans:
            filename = completed_scans[scan_id]
            if not os.path.exists(filename):
                return jsonify({'error': 'Report file not found'}), 404
                
            return send_file(
                filename,
                as_attachment=True,
                download_name=f"vulnerability_report_{scan_id}.json",
                mimetype='application/json'
            )
        
        # Check active scans
        if scan_id in active_scans:
            scanner = active_scans[scan_id]
            if scanner.scan_results['scan_details']['scan_status'].lower() != 'completed':
                return jsonify({'error': 'Scan is not completed yet'}), 400
                
            safe_target = re.sub(r'[^\w\-_.]', '_', scanner.target)
            filename = f"results/scan_{safe_target}_{scan_id}.json"
            
            if not os.path.exists(filename):
                return jsonify({'error': 'Report file not found'}), 404
                
            return send_file(
                filename,
                as_attachment=True,
                download_name=f"vulnerability_report_{scan_id}.json",
                mimetype='application/json'
            )
        
        return jsonify({'error': 'Scan not found'}), 404
    except Exception as e:
        print(f"Error downloading report: {str(e)}")
        return jsonify({'error': 'Failed to download report'}), 500

@app.route('/stop_scan/<scan_id>')
def stop_scan(scan_id):
    try:
        if scan_id in active_scans:
            scanner = active_scans[scan_id]
            scanner.stop_scan = True  # Signal the scanner to stop
            
            # Wait for the thread to finish
            if scan_id in scan_threads:
                scan_threads[scan_id].join(timeout=5)  # Wait up to 5 seconds
            
            # Save partial results
            report_path = save_scan_results(scan_id, scanner)
            completed_scans[scan_id] = report_path
            
            # Cleanup
            if scan_id in active_scans:
                del active_scans[scan_id]
            if scan_id in scan_threads:
                del scan_threads[scan_id]
            
            return jsonify({'status': 'success', 'message': 'Scan stopped successfully'})
        else:
            return jsonify({'error': 'Scan not found'}), 404
    except Exception as e:
        print(f"Error stopping scan: {str(e)}")
        return jsonify({'error': 'Failed to stop scan'}), 500

if __name__ == '__main__':
    app.run(debug=True)