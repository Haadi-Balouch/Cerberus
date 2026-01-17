"""
Cerberus Backend API - Production Ready
Fixed Version with proper separation of concerns and error handling
"""
import eventlet
eventlet.monkey_patch()

from flask import Flask, jsonify, request, send_file
from flask_cors import CORS
from flask_socketio import SocketIO, emit
import threading
import json
import os
import sys
from datetime import datetime
import traceback
import time

# Import Cerberus modules
from module.recon.host_discovery import ping_host
from module.recon.dns_resolver import resolve_dns
from module.recon.tcp_check import tcp_ping
from module.ports.port_scanner import scan_multiple_ports, grab_banner_enhanced
from module.ports.service_fingerprint import fingerprint_service
from module.cve.cve_auto_fetcher import auto_cve_lookup
from module.web.xss_scanner import check_xss
from module.web.sql_scanner import check_sqli
from module.web.headers import check_headers
from module.web.admin_finder import find_admin_panels
from module.web.dir_enum import brute_force_dirs, load_wordlist
try:
    from reporting.pdf_report import generate_pdf
except ImportError:
    print("Warning: PDF generation module not available (missing reportlab). PDF reports will be disabled.")
    def generate_pdf(results):
        print("Error: PDF generation is disabled due to missing dependencies.")
        return None
from utils.logger import log_message
import sys
sys.stdout.reconfigure(encoding='utf-8')
sys.stderr.reconfigure(encoding='utf-8')


app = Flask(__name__)
CORS(app)
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode="eventlet",
    logger=False,
    engineio_logger=False
)


import tempfile

# ============================================
# GLOBAL STATE (Thread-safe)
# ============================================
OUTPUT_DIR = os.path.join(tempfile.gettempdir(), "cerberus_outputs")
scan_lock = threading.Lock()
current_scan = {
    'running': False,
    'progress': 0,
    'phase': '',
    'results': None,
    'error': None,
    'logs': []
}
last_scan_results = None  # Persist results across connections

# ============================================
# CORE UTILITIES
# ============================================

def emit_log(message, log_type='info'):
    """Thread-safe log emission with connection validation"""
    try:
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        log_data = {
            'timestamp': timestamp,
            'message': str(message),
            'type': log_type
        }
        
        # Store in history
        with scan_lock:
            if current_scan['running']:
                 current_scan['logs'].append(log_data)

        # Emit only to connected clients
        socketio.emit('scan_log', log_data)
        
        # Console output
        print(f"[{timestamp}] [{log_type.upper()}] {message}")
        
        # File logging
        log_message(f"[{log_type.upper()}] {message}")
        
    except Exception as e:
        print(f"Error in emit_log: {str(e)}")

def emit_progress(progress, phase=''):
    """Thread-safe progress emission with rate limiting"""
    try:
        with scan_lock:
            # Rate limit: only emit if changed by 1% or phase changed
            if (abs(progress - current_scan['progress']) < 1.0 and 
                phase == current_scan['phase']):
                return
                
            current_scan['progress'] = progress
            current_scan['phase'] = phase
        
        socketio.emit('scan_progress', {
            'progress': progress,
            'phase': phase
        })
    except Exception as e:
        print(f"Error emitting progress: {e}")

def safe_dict_access(d, key, default=None):
    """Safely access dictionary keys"""
    try:
        return d.get(key, default) if isinstance(d, dict) else default
    except:
        return default

# ============================================
# TARGET DETECTION
# ============================================

def detect_target_type(target):
    """
    Detect if target is IP, domain, or URL
    Returns: (type, normalized_target)
    """
    target = target.strip()
    
    if target.startswith(('http://', 'https://')):
        return 'url', target
    
    # Simple IP check
    parts = target.replace(':', '').split('.')
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return 'ip', target
    
    return 'domain', target

def extract_hostname(target, target_type):
    """Extract hostname from target"""
    if target_type == 'url':
        from urllib.parse import urlparse
        parsed = urlparse(target)
        return parsed.netloc or parsed.path
    return target

def filter_modules_by_target(modules, target_type):
    """Filter modules based on target type"""
    web_modules = ['headers', 'admin', 'xss', 'sqli', 'dir']
    
    if target_type == 'ip':
        # Remove web modules for IP targets
        return [m for m in modules if m not in web_modules]
    
    return modules

# ============================================
# SCANNING LOGIC (SEPARATED FROM API)
# ============================================

class ScanExecutor:
    """
    Separated scan execution logic
    This ensures CLI and GUI use the SAME code
    """
    
    def __init__(self, config, emit_callback=None):
        self.config = config
        self.emit = emit_callback or emit_log
        self.results = {
            'target': config['target'],
            'timestamp': datetime.now().isoformat(),
            'modules': config['modules'],
            'recon': {},
            'ports': [],
            'web': {}
        }
    
    def run_recon(self, hostname):
        """Execute reconnaissance phase"""
        self.emit(' Running reconnaissance...', 'info')
        emit_progress(15, 'Reconnaissance')
        
        try:
            reachable = ping_host(hostname)
            dns_info = resolve_dns(hostname)
            tcp_80 = tcp_ping(hostname, 80)
            
            self.results['recon'] = {
                'reachable': reachable,
                'dns': dns_info,
                'tcp_port_80': tcp_80
            }
            
            self.emit(f'    Host reachable: {reachable}', 'success' if reachable else 'warning')
            self.emit(f'    DNS resolved: {dns_info.get("ip", "N/A")}', 'info')
            
            return True
        except Exception as e:
            self.emit(f'   Recon error: {str(e)}', 'warning')
            self.results['recon'] = {'error': str(e)}
            return False
    
    def run_port_scan(self, hostname):
        """Execute port scanning phase"""
        self.emit(' Scanning ports...', 'info')
        emit_progress(25, 'Port Scanning')
        
        try:
            port_list = [21, 22, 23, 25, 53, 80, 110, 143, 139, 443, 445, 3306, 3389, 5432, 8080, 8443]
            open_ports = scan_multiple_ports(hostname, port_list)
            
            self.emit(f'    Found {len(open_ports)} open ports', 'success')
            
            if not open_ports:
                return True
            
            emit_progress(35, 'Service Detection')
            
            total_ports = len(open_ports)
            for idx, port in enumerate(open_ports):
                try:
                    # Banner grabbing
                    banner = grab_banner_enhanced(hostname, port)
                    fingerprint = fingerprint_service(banner)
                    
                    # CVE lookup (CRITICAL FIX: This was missing proper data flow)
                    cves = []
                    if 'cve' in self.config['modules']:
                        if fingerprint['service'] != 'unknown' and fingerprint['version'] != 'unknown':
                            try:
                                # This is the REAL CVE lookup that GUI was missing
                                cve_results = auto_cve_lookup(fingerprint['service'], fingerprint['version'])
                                
                                # Handle both list and dict responses
                                if isinstance(cve_results, list):
                                    cves = cve_results
                                elif isinstance(cve_results, dict) and 'error' not in cve_results:
                                    cves = [cve_results]
                                
                                self.emit(f'  • Port {port}: {fingerprint["service"]} {fingerprint["version"]} ({len(cves)} CVEs)', 'info')
                            except Exception as cve_err:
                                self.emit(f'   CVE lookup failed for port {port}: {str(cve_err)}', 'warning')
                    
                    # Store complete port information
                    self.results['ports'].append({
                        'port': port,
                        'banner': banner,
                        'service': fingerprint['service'],
                        'version': fingerprint['version'],
                        'cves': cves  # This now contains REAL CVE data
                    })
                    
                    # Progress update
                    progress = 35 + (20 * (idx + 1) / total_ports)
                    emit_progress(progress, f'Analyzing port {port}')
                    
                except Exception as port_err:
                    self.emit(f'   Error analyzing port {port}: {str(port_err)}', 'warning')
                    # Still add port with error info
                    self.results['ports'].append({
                        'port': port,
                        'banner': 'Error',
                        'service': 'unknown',
                        'version': 'unknown',
                        'cves': [],
                        'error': str(port_err)
                    })
            
            return True
            
        except Exception as e:
            self.emit(f'   Port scan error: {str(e)}', 'warning')
            self.results['ports'] = []
            return False
    
    def run_web_scan(self, url):
        """Execute web vulnerability scanning"""
        web_modules = [m for m in self.config['modules'] if m in ['headers', 'admin', 'xss', 'sqli', 'dir']]
        
        if not web_modules:
            return True
        
        self.emit(' Starting web security scan...', 'info')
        
        # Security Headers
        if 'headers' in web_modules:
            emit_progress(55, 'Checking Security Headers')
            self.emit(' Analyzing security headers...', 'info')
            try:
                headers_result = check_headers(url)
                self.results['web']['headers'] = headers_result
                
                if headers_result.get('secure'):
                    self.emit('    All security headers present', 'success')
                else:
                    missing = len(headers_result.get('missing_headers', []))
                    self.emit(f'   {missing} security headers missing', 'warning')
            except Exception as e:
                self.emit(f'   Headers check failed: {str(e)}', 'warning')
                self.results['web']['headers'] = {'error': str(e)}
        
        # Admin Panel Discovery
        if 'admin' in web_modules:
            emit_progress(65, 'Admin Panel Discovery')
            self.emit(' Searching for admin panels...', 'info')
            try:
                admin_results = find_admin_panels(url)
                self.results['web']['admin_panels'] = admin_results
                self.emit(f'    Found {len(admin_results)} potential admin paths', 'info')
            except Exception as e:
                self.emit(f'   Admin scan failed: {str(e)}', 'warning')
                self.results['web']['admin_panels'] = []
        
        # XSS Detection
        if 'xss' in web_modules:
            emit_progress(75, 'XSS Detection')
            self.emit(' Testing for XSS vulnerabilities...', 'info')
            try:
                xss_result = check_xss(url)
                self.results['web']['xss'] = xss_result
                
                if xss_result.get('xss'):
                    findings = len(xss_result.get('findings', []))
                    self.emit(f'   XSS vulnerability detected ({findings} findings)', 'warning')
                else:
                    self.emit('    No XSS vulnerabilities found', 'success')
            except Exception as e:
                self.emit(f'   XSS scan failed: {str(e)}', 'warning')
                self.results['web']['xss'] = {'error': str(e)}
        
        # SQL Injection
        if 'sqli' in web_modules:
            emit_progress(85, 'SQL Injection Testing')
            self.emit(' Testing for SQL injection...', 'info')
            try:
                sqli_result = check_sqli(url)
                self.results['web']['sqli'] = sqli_result
                
                if sqli_result.get('sqli'):
                    findings = len(sqli_result.get('details', []))
                    self.emit(f'   SQL injection detected ({findings} findings)', 'warning')
                else:
                    self.emit('    No SQL injection found', 'success')
            except Exception as e:
                self.emit(f'   SQLi scan failed: {str(e)}', 'warning')
                self.results['web']['sqli'] = {'error': str(e)}
        
        # Directory Enumeration
        if 'dir' in web_modules:
            emit_progress(90, 'Directory Enumeration')
            self.emit(' Enumerating directories...', 'info')
            try:
                wordlist_path = self.config.get('wordlist')
                wordlist = None
                
                if wordlist_path and os.path.exists(wordlist_path):
                    wordlist = load_wordlist(wordlist_path, limit=200)
                
                workers = self.config.get('workers', 15)
                rate = self.config.get('rate', 0)
                
                dir_results = brute_force_dirs(url, wordlist, workers, 3.5, rate)
                self.results['web']['directories'] = dir_results
                self.emit(f'    Found {len(dir_results)} accessible paths', 'info')
            except Exception as e:
                self.emit(f'   Directory scan failed: {str(e)}', 'warning')
                self.results['web']['directories'] = []
        
        return True
    
    def generate_reports(self):
        """Generate JSON and PDF reports with proper error handling"""
        self.emit(' Generating reports...', 'info')
        emit_progress(95, 'Generating Reports')
        
        json_file = None
        pdf_file = None
        
        # Ensure outputs directory exists
        try:
            os.makedirs(OUTPUT_DIR, exist_ok=True)
        except Exception as e:
            self.emit(f'   Cannot create outputs directory: {str(e)}', 'error')
            return None, None
        
        # Generate JSON (should never fail)
        try:
            json_filename = f'cerberus_output_{datetime.now().strftime("%Y-%m-%d_%H-%M-%S")}.json'
            json_file = os.path.join(OUTPUT_DIR, json_filename)
            with open(json_file, 'w') as f:
                json.dump(self.results, f, indent=4)
            self.emit(f'    JSON saved: {json_file}', 'success')
        except Exception as e:
            self.emit(f'   JSON save failed: {str(e)}', 'error')
            json_file = None
        
        # Generate PDF (with defensive handling)
        try:
            # CRITICAL FIX: Add URL field even for IP targets
            if 'url' not in self.results or not self.results['url']:
                target_type = detect_target_type(self.results['target'])[0]
                if target_type == 'url':
                    self.results['url'] = self.results['target']
                elif target_type == 'domain':
                    self.results['url'] = f"http://{self.results['target']}"
                else:
                    self.results['url'] = None  # IP target - no web scan
            
            pdf_file = generate_pdf(self.results)
            self.emit(f'    PDF saved: {pdf_file}', 'success')
        except Exception as e:
            self.emit(f'  PDF generation failed: {str(e)}', 'error')
            # Log full traceback for debugging
            log_message(f"PDF Error Traceback: {traceback.format_exc()}")
            pdf_file = None
        
        return json_file, pdf_file
    
    def execute(self):
        """Main execution flow"""
        try:
            target = self.config['target']
            modules = self.config['modules']
            
            self.emit(' Cerberus Security Scanner v2.0 initialized', 'success')
            self.emit(f'Target: {target}', 'info')
            
            # Detect target type
            target_type, normalized_target = detect_target_type(target)
            self.emit(f' Target type detected: {target_type.upper()}', 'info')
            
            # Update results with detected info
            self.results['target'] = normalized_target
            self.results['target_type'] = target_type
            
            hostname = extract_hostname(normalized_target, target_type)
            
            # Filter modules by target type
            filtered_modules = filter_modules_by_target(modules, target_type)
            self.results['modules'] = filtered_modules
            self.emit(f' Enabled modules: {", ".join(filtered_modules)}', 'info')
            
            emit_progress(10, 'Initialization')
            
            # Execute scan phases
            if 'recon' in filtered_modules:
                self.run_recon(hostname)
            
            if 'ports' in filtered_modules:
                self.run_port_scan(hostname)
            
            # Web scan only for URL/domain targets
            web_modules = [m for m in filtered_modules if m in ['headers', 'admin', 'xss', 'sqli', 'dir']]
            if web_modules and target_type != 'ip':
                url = normalized_target if target_type == 'url' else f'http://{normalized_target}'
                self.results['url'] = url
                self.run_web_scan(url)
            
            # Generate reports
            json_file, pdf_file = self.generate_reports()
            
            if json_file:
                self.results['json_file'] = json_file
            if pdf_file:
                self.results['pdf_file'] = pdf_file
            
            emit_progress(100, 'Scan Complete')
            self.emit(' Scan completed successfully!', 'success')
            
            return self.results
            
        except Exception as e:
            self.emit(f' Fatal error: {str(e)}', 'error')
            log_message(f"Scan Error: {traceback.format_exc()}")
            raise

# ============================================
# SCAN THREAD EXECUTION
# ============================================

def run_scan_thread(config):
    """
    Main scan execution in separate thread
    CRITICAL FIX: This now uses ScanExecutor for consistency with CLI
    """
    global last_scan_results
    try:
        with scan_lock:
            current_scan['running'] = True
            current_scan['progress'] = 0
            current_scan['error'] = None
            current_scan['results'] = None
            current_scan['logs'] = [] # Clear logs for new scan
        
        # Create executor and run scan
        executor = ScanExecutor(config, emit_callback=emit_log)
        results = executor.execute()
        
        # Store results
        with scan_lock:
            current_scan['results'] = results
            current_scan['running'] = False
            last_scan_results = results  # Persist for retrieval
        
        # Emit completion
        socketio.emit('scan_complete', results)
        
    except Exception as e:
        error_msg = f'Fatal error: {str(e)}'
        emit_log(error_msg, 'error')
        emit_log(traceback.format_exc(), 'error')
        
        with scan_lock:
            current_scan['running'] = False
            current_scan['error'] = str(e)
        
        socketio.emit('scan_error', {'error': str(e)})

# ============================================
# API ENDPOINTS
# ============================================

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'ok',
        'version': '2.0',
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/scan/start', methods=['POST'])
def start_scan():
    """Start a new scan"""
    with scan_lock:
        if current_scan['running']:
            return jsonify({'error': 'Scan already in progress'}), 400
    
    try:
        config = request.json
        
        # Validate required fields
        if not config.get('target'):
            return jsonify({'error': 'Target is required'}), 400
        
        if not config.get('modules'):
            return jsonify({'error': 'At least one module must be selected'}), 400
        
        # Start scan in background task
        socketio.start_background_task(run_scan_thread, config)
        
        return jsonify({
            'status': 'started',
            'message': 'Scan initiated successfully'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/status', methods=['GET'])
def scan_status():
    """Get current scan status"""
    with scan_lock:
        return jsonify({
            'running': current_scan['running'],
            'progress': current_scan['progress'],
            'phase': current_scan['phase'],
            'error': current_scan['error']
        })

@app.route('/api/scan/results', methods=['GET'])
def get_results():
    """Get scan results"""
    global last_scan_results
    with scan_lock:
        if current_scan['results']:
            return jsonify(current_scan['results'])
        elif last_scan_results:
            return jsonify(last_scan_results)
        else:
            return jsonify({'error': 'No results available'}), 404

@app.route('/api/scan/download/<file_type>', methods=['GET'])
def download_report(file_type):
    """
    Download report file
    CRITICAL FIX: Added proper error handling and file validation
    """
    with scan_lock:
        if not current_scan['results']:
            return jsonify({'error': 'No scan results available'}), 404
        
        results = current_scan['results']
    
    # Determine file path
    if file_type == 'json':
        file_path = results.get('json_file')
    elif file_type == 'pdf':
        file_path = results.get('pdf_file')
    else:
        return jsonify({'error': 'Invalid file type. Use "json" or "pdf"'}), 400
    
    # Validate file exists
    if not file_path:
        return jsonify({'error': f'{file_type.upper()} report not generated'}), 404
    
    if not os.path.exists(file_path):
        return jsonify({'error': f'{file_type.upper()} file not found at {file_path}'}), 404
    
    # Serve file
    try:
        return send_file(
            file_path,
            as_attachment=True,
            download_name=os.path.basename(file_path),
            mimetype='application/pdf' if file_type == 'pdf' else 'application/json'
        )
    except Exception as e:
        return jsonify({'error': f'Failed to send file: {str(e)}'}), 500

@app.route('/api/profiles', methods=['GET'])
def get_profiles():
    """Get available scan profiles"""
    profiles = {
        'quick': {
            'name': 'Quick Scan',
            'description': 'Fast, non-intrusive reconnaissance',
            'modules': ['headers', 'admin', 'recon', 'ports'],
            'risk': 'SAFE'
        },
        'standard': {
            'name': 'Standard Scan',
            'description': 'Balanced security assessment',
            'modules': ['headers', 'admin', 'xss', 'recon', 'ports', 'cve'],
            'risk': 'MODERATE'
        },
        'aggressive': {
            'name': 'Aggressive Scan',
            'description': 'Comprehensive vulnerability testing',
            'modules': ['headers', 'admin', 'xss', 'sqli', 'dir', 'recon', 'ports', 'cve'],
            'risk': 'AGGRESSIVE'
        },
        'web-only': {
            'name': 'Web Application Scan',
            'description': 'Focus on web vulnerabilities',
            'modules': ['headers', 'admin', 'xss', 'sqli', 'dir'],
            'risk': 'MODERATE'
        },
        'network-only': {
            'name': 'Network Infrastructure Scan',
            'description': 'Focus on network vulnerabilities',
            'modules': ['recon', 'ports', 'cve'],
            'risk': 'SAFE'
        }
    }
    return jsonify(profiles)

# ============================================
# SOCKETIO EVENTS
# ============================================
connected_clients = set()
client_lock = threading.Lock()

@socketio.on('connect')
def handle_connect():
    """Handle client connection with deduplication"""
    client_id = request.sid
    
    with client_lock:
        # Check if too many connections from same source
        if len(connected_clients) > 5:
            print(f'⚠ Warning: Too many connections ({len(connected_clients)}), rejecting new connection')
            return False  # Reject connection
        
        connected_clients.add(client_id)
        print(f'✓ Client connected: {client_id} (Total: {len(connected_clients)})')
    
    emit('connected', {
        'status': 'ok',
        'timestamp': datetime.now().isoformat(),
        'client_id': client_id
    })

    # Send current scan state if running
    with scan_lock:
        if current_scan['running']:
            emit('scan_progress', {
                'progress': current_scan['progress'],
                'phase': current_scan['phase']
            })
            # Send log history
            if current_scan['logs']:
                emit('log_history', current_scan['logs'])

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    client_id = request.sid
    
    with client_lock:
        connected_clients.discard(client_id)
        print(f'✗ Client disconnected: {client_id} (Remaining: {len(connected_clients)})')

@socketio.on('ping')
def handle_ping():
    """Handle ping for connection testing"""
    emit('pong', {'timestamp': datetime.now().isoformat()})

# ============================================
# MAIN
# ============================================

if __name__ == '__main__':
    print(' Cerberus Backend API Server')
    print('=' * 50)
    print(f'Outputs directory: {OUTPUT_DIR}')
    print('Server running on: http://localhost:5000')
    print('WebSocket available for real-time updates')
    print('Press Ctrl+C to stop')
    print('=' * 50)
    
    # Create outputs directory
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)