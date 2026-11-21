#!/usr/bin/env python3
"""
Hoover Web GUI - Web-based interface for Hoover WiFi tools
Dark-themed local web interface for easy tool management
"""

from flask import Flask, render_template, jsonify, request, send_file, session, redirect, url_for
from flask_socketio import SocketIO, emit
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import subprocess
import os
import re
import json
import signal
import threading
import time
from datetime import datetime
from pathlib import Path
from collections import deque
import psutil
import secrets

app = Flask(__name__)
# Generate a secure random secret key
app.config['SECRET_KEY'] = secrets.token_hex(32)
# Restrict CORS to localhost only for security
socketio = SocketIO(app, cors_allowed_origins=["http://127.0.0.1:5000", "http://localhost:5000"])

# --- Authentication ---
# Password hash stored in memory; generated on first run
_auth_password_hash = None

def _generate_auth_password():
    """Generate a random password on first run and display it in the terminal."""
    global _auth_password_hash
    password = secrets.token_urlsafe(16)
    _auth_password_hash = generate_password_hash(password)
    return password

def login_required(f):
    """Decorator that checks for a valid session cookie before allowing access."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('authenticated'):
            # For API endpoints return 401 JSON; for pages redirect to login
            if request.path.startswith('/api/'):
                return jsonify({'success': False, 'error': 'Authentication required'}), 401
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated_function

# --- CSRF Protection ---

def _get_csrf_token():
    """Return the CSRF token for the current session, creating one if needed."""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']

def csrf_protect(f):
    """Decorator that validates the X-CSRF-Token header on POST requests."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == 'POST':
            token = request.headers.get('X-CSRF-Token', '')
            if not token or token != session.get('csrf_token'):
                return jsonify({'success': False, 'error': 'Invalid CSRF token'}), 403
        return f(*args, **kwargs)
    return decorated_function

# --- Input Validation Helpers ---

_RE_INTERFACE = re.compile(r'^[a-zA-Z0-9_-]+$')
_RE_MAC = re.compile(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$')
_RE_FILENAME = re.compile(r'^[a-zA-Z0-9_.-]+$')

SSID_FILES_DIR = Path('ssid_files')

def validate_interface(name):
    """Return (ok, error_msg) for an interface name."""
    if not name or not _RE_INTERFACE.match(name):
        return False, 'Invalid interface name'
    return True, None

def validate_mac(mac):
    """Return (ok, error_msg) for a MAC address string."""
    if not mac or not _RE_MAC.match(mac):
        return False, 'Invalid MAC address format (expected XX:XX:XX:XX:XX:XX)'
    return True, None

def validate_ssid_filename(name):
    """Return (ok, error_msg) for an SSID file name. It must be a plain .txt
    filename with no path separators and must exist inside SSID_FILES_DIR."""
    if not name:
        return False, 'SSID filename required'
    if '/' in name or '\\' in name or '..' in name:
        return False, 'Invalid filename (path separators not allowed)'
    if not name.endswith('.txt'):
        return False, 'Only .txt files are allowed'
    if not _RE_FILENAME.match(name):
        return False, 'Invalid characters in filename'
    filepath = (SSID_FILES_DIR / name).resolve()
    if not str(filepath).startswith(str(SSID_FILES_DIR.resolve())):
        return False, 'Access denied'
    if not filepath.is_file():
        return False, f'SSID file not found: {name}'
    return True, None

def validate_channel(ch):
    """Return (ok, error_msg) for a channel number."""
    try:
        ch = int(ch)
    except (TypeError, ValueError):
        return False, 'Channel must be an integer'
    if ch < 1 or ch > 14:
        return False, 'Channel must be between 1 and 14'
    return True, None

def validate_positive_number(value, label, allow_float=False):
    """Return (ok, error_msg) for a positive numeric parameter."""
    try:
        value = float(value) if allow_float else int(value)
    except (TypeError, ValueError):
        return False, f'{label} must be a number'
    if value <= 0:
        return False, f'{label} must be greater than 0'
    return True, None

def validate_encryption(enc):
    """Return (ok, error_msg) for an encryption choice."""
    if enc is None or enc == '':
        return True, None  # empty is allowed (open network)
    if enc not in ('wpa2', 'wep'):
        return False, "Encryption must be 'wpa2', 'wep', or empty"
    return True, None


# --- Thread Safety ---
_state_lock = threading.Lock()

# Global state
active_processes = {}
tool_status = {
    'monitor': {'running': False, 'pid': None, 'interface': None},
    'generator': {'running': False, 'pid': None, 'interface': None},
    'capturer': {'running': False, 'pid': None, 'interface': None},
    'deauth': {'running': False, 'pid': None, 'interface': None},
    'ap_scanner': {'running': False, 'pid': None, 'interface': None},
    'handshake': {'running': False, 'pid': None, 'interface': None},
    'portal': {'running': False, 'pid': None, 'interface': None},
    'karma': {'running': False, 'pid': None, 'interface': None},
    'wids': {'running': False, 'pid': None, 'interface': None},
    'packet_replay': {'running': False, 'pid': None, 'interface': None},
    'wps_attack': {'running': False, 'pid': None, 'interface': None},
    'network_mapper': {'running': False, 'pid': None, 'interface': None},
    'ble_scanner': {'running': False, 'pid': None, 'interface': None},
    'pentest_workflow': {'running': False, 'pid': None, 'interface': None},
}

# --- Probe Request Buffer ---
_probe_buffer = deque(maxlen=100)
_probe_lock = threading.Lock()


class ProcessMonitor:
    """Monitor and manage tool processes"""

    def __init__(self, tool_name, process, log_callback):
        self.tool_name = tool_name
        self.process = process
        self.log_callback = log_callback
        self.running = True

    def start_monitoring(self):
        """Monitor process output"""
        thread = threading.Thread(target=self._monitor_output)
        thread.daemon = True
        thread.start()

    def _monitor_output(self):
        """Read and emit process output"""
        while self.running and self.process.poll() is None:
            try:
                if self.process.stdout:
                    line = self.process.stdout.readline()
                    if line:
                        decoded = line.decode('utf-8', errors='ignore').strip()
                        self.log_callback(self.tool_name, decoded)

                        # If this is the probe monitor, try to parse probe data
                        if self.tool_name == 'monitor' and decoded:
                            _parse_and_emit_probe(decoded)
            except Exception as e:
                self.log_callback(self.tool_name, f"Error reading output: {e}")
            time.sleep(0.1)

        # Process ended
        if self.process.poll() is not None:
            self.log_callback(self.tool_name, f"Process exited with code {self.process.returncode}")
            with _state_lock:
                tool_status[self.tool_name]['running'] = False
                tool_status[self.tool_name]['pid'] = None

    def stop(self):
        """Stop monitoring"""
        self.running = False


def _parse_and_emit_probe(line):
    """Try to extract probe request data from monitor output and emit via SocketIO.

    Expected format from hoover.py output lines such as:
        MAC: AA:BB:CC:DD:EE:FF  SSID: MyNetwork  Signal: -45dBm
    or similar structured output.  We attempt a best-effort parse; lines
    that do not match are silently ignored.
    """
    probe = {}
    # Attempt to extract MAC
    mac_match = re.search(r'(?:MAC|SRC|Source)[:\s]+([0-9A-Fa-f:]{17})', line, re.IGNORECASE)
    if mac_match:
        probe['mac'] = mac_match.group(1).upper()
    else:
        # Fallback: look for any MAC address in the line
        mac_any = re.search(r'([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})', line)
        if mac_any:
            probe['mac'] = mac_any.group(1).upper()
        else:
            return  # No MAC found, nothing to emit

    # SSID
    ssid_match = re.search(r'SSID[:\s]+(.+?)(?:\s{2,}|Signal|$)', line, re.IGNORECASE)
    probe['ssid'] = ssid_match.group(1).strip() if ssid_match else ''

    # Signal strength
    signal_match = re.search(r'Signal[:\s]+([-\d]+)', line, re.IGNORECASE)
    probe['signal'] = int(signal_match.group(1)) if signal_match else None

    probe['timestamp'] = datetime.now().strftime('%H:%M:%S')

    with _probe_lock:
        _probe_buffer.append(probe)

    socketio.emit('probe', probe)


def emit_log(tool, message):
    """Emit log message to web clients"""
    timestamp = datetime.now().strftime("%H:%M:%S")
    socketio.emit('log', {
        'tool': tool,
        'timestamp': timestamp,
        'message': message
    })

def get_network_interfaces():
    """Get list of wireless interfaces"""
    interfaces = []
    try:
        # Try using iwconfig first
        result = subprocess.run(['iwconfig'], stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, text=True, timeout=5)
        lines = result.stdout.split('\n')

        for line in lines:
            # Skip empty lines, indented lines, and lines with "no wireless extensions"
            if not line or line.startswith(' ') or line.startswith('\t'):
                continue

            if 'no wireless extensions' in line.lower():
                continue

            parts = line.split()
            if not parts:
                continue

            iface = parts[0]

            # Skip loopback
            if iface == 'lo':
                continue

            # Determine mode (might be on this line or subsequent lines)
            mode = 'Managed'
            if 'Mode:Monitor' in line or 'monitor' in line.lower():
                mode = 'Monitor'

            interfaces.append({'name': iface, 'mode': mode})

    except FileNotFoundError:
        # iwconfig not found, try fallback method
        return get_network_interfaces_fallback()
    except Exception as e:
        print(f"[!] Error getting interfaces with iwconfig: {e}")
        return get_network_interfaces_fallback()

    # If no interfaces found with iwconfig, try fallback
    if not interfaces:
        return get_network_interfaces_fallback()

    return interfaces

def get_network_interfaces_fallback():
    """Fallback method to get network interfaces using /sys/class/net"""
    interfaces = []
    try:
        net_dir = Path('/sys/class/net')
        if not net_dir.exists():
            print("[!] /sys/class/net not found")
            return []

        for iface_dir in net_dir.iterdir():
            iface_name = iface_dir.name

            # Skip loopback
            if iface_name == 'lo':
                continue

            # Check if it's a wireless interface
            wireless_dir = iface_dir / 'wireless'
            phy80211_dir = iface_dir / 'phy80211'

            if wireless_dir.exists() or phy80211_dir.exists():
                # Determine mode by checking with iw command
                mode = 'Managed'
                try:
                    result = subprocess.run(['iw', 'dev', iface_name, 'info'],
                                          capture_output=True, text=True, timeout=2)
                    if 'type monitor' in result.stdout.lower():
                        mode = 'Monitor'
                except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError, Exception):
                    # If iw fails, default to Managed mode
                    pass

                interfaces.append({'name': iface_name, 'mode': mode})

    except Exception as e:
        print(f"[!] Error in fallback interface discovery: {e}")

    return interfaces

def get_ssid_files():
    """Get list of SSID files from the dedicated ssid_files/ directory"""
    files = []
    if not SSID_FILES_DIR.exists():
        return files
    for f in SSID_FILES_DIR.glob('*.txt'):
        if f.is_file():
            try:
                with open(f, 'r') as file:
                    lines = [l.strip() for l in file if l.strip() and not l.startswith('#')]
                    files.append({
                        'name': f.name,
                        'count': len(lines)
                    })
            except Exception:
                pass
    return files

def get_capture_files():
    """Get list of capture files"""
    captures = []
    capture_dir = Path('./captures')

    if capture_dir.exists():
        for f in capture_dir.glob('*.pcap'):
            stat = f.stat()
            captures.append({
                'name': f.name,
                'size': stat.st_size,
                'modified': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
            })

    return sorted(captures, key=lambda x: x['modified'], reverse=True)


def _migrate_ssid_files():
    """On startup, move any existing .txt SSID files from project root to ssid_files/."""
    SSID_FILES_DIR.mkdir(exist_ok=True)
    for f in Path('.').glob('*.txt'):
        if f.is_file() and f.name != 'requirements.txt':
            dest = SSID_FILES_DIR / f.name
            if not dest.exists():
                try:
                    f.rename(dest)
                    print(f"[*] Migrated SSID file {f.name} -> ssid_files/{f.name}")
                except Exception as e:
                    print(f"[!] Failed to migrate {f.name}: {e}")


# --- Routes ---

@app.route('/login', methods=['GET'])
def login_page():
    """Show login page"""
    if session.get('authenticated'):
        return redirect(url_for('index'))
    return render_template('login.html')

@app.route('/api/login', methods=['POST'])
def api_login():
    """Authenticate the user with a password"""
    data = request.json or {}
    password = data.get('password', '')
    if _auth_password_hash and check_password_hash(_auth_password_hash, password):
        session['authenticated'] = True
        # Generate CSRF token for the new session
        _get_csrf_token()
        return jsonify({'success': True})
    return jsonify({'success': False, 'error': 'Invalid password'}), 401

@app.route('/api/logout', methods=['POST'])
def api_logout():
    """Log the user out"""
    session.clear()
    return jsonify({'success': True})

@app.route('/')
@login_required
def index():
    """Serve main page"""
    return render_template('index.html', csrf_token=_get_csrf_token())

@app.route('/api/status')
@login_required
def api_status():
    """Get current status"""
    with _state_lock:
        status_copy = {k: dict(v) for k, v in tool_status.items()}
    return jsonify({
        'status': status_copy,
        'interfaces': get_network_interfaces(),
        'ssid_files': get_ssid_files(),
        'captures': get_capture_files(),
        'system': {
            'cpu': psutil.cpu_percent(),
            'memory': psutil.virtual_memory().percent
        }
    })

@app.route('/api/interfaces')
@login_required
def api_interfaces():
    """Get network interfaces"""
    return jsonify(get_network_interfaces())

@app.route('/api/probes')
@login_required
def api_probes():
    """Return the current probe request buffer as JSON"""
    with _probe_lock:
        probes = list(_probe_buffer)
    return jsonify({'success': True, 'probes': probes})

@app.route('/api/monitor/start', methods=['POST'])
@login_required
@csrf_protect
def api_monitor_start():
    """Start probe request monitor"""
    with _state_lock:
        if tool_status['monitor']['running']:
            return jsonify({'success': False, 'error': 'Monitor already running'})

    data = request.json
    interface = data.get('interface')
    verbose = data.get('verbose', False)

    # Input validation
    ok, err = validate_interface(interface)
    if not ok:
        return jsonify({'success': False, 'error': err}), 400

    try:
        cmd = ['python3', 'hoover.py', '-i', interface]
        if verbose:
            cmd.append('-v')

        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        with _state_lock:
            tool_status['monitor']['running'] = True
            tool_status['monitor']['pid'] = process.pid
            tool_status['monitor']['interface'] = interface
            active_processes['monitor'] = process

        # Start monitoring output
        monitor = ProcessMonitor('monitor', process, emit_log)
        monitor.start_monitoring()

        emit_log('monitor', f'Probe request monitor started on {interface}')

        return jsonify({'success': True, 'pid': process.pid})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/monitor/stop', methods=['POST'])
@login_required
@csrf_protect
def api_monitor_stop():
    """Stop probe request monitor"""
    with _state_lock:
        if not tool_status['monitor']['running']:
            return jsonify({'success': False, 'error': 'Monitor not running'})

    try:
        with _state_lock:
            process = active_processes.get('monitor')
        if process:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)

        with _state_lock:
            tool_status['monitor']['running'] = False
            tool_status['monitor']['pid'] = None
            tool_status['monitor']['interface'] = None

        emit_log('monitor', 'Probe request monitor stopped')

        return jsonify({'success': True})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/generator/start', methods=['POST'])
@login_required
@csrf_protect
def api_generator_start():
    """Start SSID generator"""
    with _state_lock:
        if tool_status['generator']['running']:
            return jsonify({'success': False, 'error': 'Generator already running'})

    data = request.json
    interface = data.get('interface')
    ssid_file = data.get('ssid_file')
    continuous = data.get('continuous', False)
    interval = data.get('interval', 0.1)
    channel = data.get('channel', 6)

    # Input validation
    ok, err = validate_interface(interface)
    if not ok:
        return jsonify({'success': False, 'error': err}), 400

    ok, err = validate_ssid_filename(ssid_file)
    if not ok:
        return jsonify({'success': False, 'error': err}), 400

    ok, err = validate_positive_number(interval, 'Interval', allow_float=True)
    if not ok:
        return jsonify({'success': False, 'error': err}), 400

    ok, err = validate_channel(channel)
    if not ok:
        return jsonify({'success': False, 'error': err}), 400

    try:
        ssid_file_path = str(SSID_FILES_DIR / ssid_file)
        cmd = ['python3', 'ssid_generator.py', '-i', interface, '-f', ssid_file_path,
               '-t', str(interval), '-ch', str(channel)]

        if continuous:
            cmd.append('-c')

        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        with _state_lock:
            tool_status['generator']['running'] = True
            tool_status['generator']['pid'] = process.pid
            tool_status['generator']['interface'] = interface
            active_processes['generator'] = process

        # Start monitoring output
        monitor = ProcessMonitor('generator', process, emit_log)
        monitor.start_monitoring()

        emit_log('generator', f'SSID generator started on {interface}')

        return jsonify({'success': True, 'pid': process.pid})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/generator/stop', methods=['POST'])
@login_required
@csrf_protect
def api_generator_stop():
    """Stop SSID generator"""
    with _state_lock:
        if not tool_status['generator']['running']:
            return jsonify({'success': False, 'error': 'Generator not running'})

    try:
        with _state_lock:
            process = active_processes.get('generator')
        if process:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)

        with _state_lock:
            tool_status['generator']['running'] = False
            tool_status['generator']['pid'] = None
            tool_status['generator']['interface'] = None

        emit_log('generator', 'SSID generator stopped')

        return jsonify({'success': True})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/capturer/start', methods=['POST'])
@login_required
@csrf_protect
def api_capturer_start():
    """Start SSID capturer"""
    with _state_lock:
        if tool_status['capturer']['running']:
            return jsonify({'success': False, 'error': 'Capturer already running'})

    data = request.json
    interface = data.get('interface')
    ssid_file = data.get('ssid_file')
    ssid = data.get('ssid')
    rotate = data.get('rotate', False)
    duration = data.get('duration', 300)
    channel = data.get('channel', 6)
    encryption = data.get('encryption')
    password = data.get('password')
    internet = data.get('internet', False)
    upstream = data.get('upstream')

    # Input validation
    ok, err = validate_interface(interface)
    if not ok:
        return jsonify({'success': False, 'error': err}), 400

    ok, err = validate_ssid_filename(ssid_file)
    if not ok:
        return jsonify({'success': False, 'error': err}), 400

    if not rotate and not ssid:
        return jsonify({'success': False, 'error': 'SSID required when not rotating'}), 400

    ok, err = validate_positive_number(duration, 'Duration')
    if not ok:
        return jsonify({'success': False, 'error': err}), 400

    ok, err = validate_channel(channel)
    if not ok:
        return jsonify({'success': False, 'error': err}), 400

    ok, err = validate_encryption(encryption)
    if not ok:
        return jsonify({'success': False, 'error': err}), 400

    if internet and upstream:
        ok, err = validate_interface(upstream)
        if not ok:
            return jsonify({'success': False, 'error': f'Upstream: {err}'}), 400

    try:
        ssid_file_path = str(SSID_FILES_DIR / ssid_file)
        cmd = ['python3', 'ssid_capturer.py', '-i', interface, '-f', ssid_file_path,
               '-d', str(duration), '-ch', str(channel)]

        if rotate:
            cmd.append('-r')
        else:
            cmd.extend(['-s', ssid])

        if encryption:
            cmd.extend(['-e', encryption])
            if password:
                cmd.extend(['-p', password])

        if internet and upstream:
            cmd.extend(['--internet', '-u', upstream])

        # TODO: The CLI tools should accept a --no-confirm or --web-mode flag so the
        # web GUI does not need to pipe 'yes' into stdin.  Currently the CLI prompts
        # for an interactive authorization confirmation.  The web GUI's own confirmation
        # dialog (shown before the API call) serves as the authorization check, so
        # auto-confirming here is intentional.  When the CLI tools are updated to
        # support --web-mode, replace the stdin pipe with that flag.
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                  stdin=subprocess.PIPE)

        # Auto-confirm: the user already confirmed via the web GUI's dialog.
        process.stdin.write(b'yes\n')
        process.stdin.flush()

        with _state_lock:
            tool_status['capturer']['running'] = True
            tool_status['capturer']['pid'] = process.pid
            tool_status['capturer']['interface'] = interface
            active_processes['capturer'] = process

        # Start monitoring output
        monitor = ProcessMonitor('capturer', process, emit_log)
        monitor.start_monitoring()

        emit_log('capturer', f'SSID capturer started on {interface}')

        return jsonify({'success': True, 'pid': process.pid})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/capturer/stop', methods=['POST'])
@login_required
@csrf_protect
def api_capturer_stop():
    """Stop SSID capturer"""
    with _state_lock:
        if not tool_status['capturer']['running']:
            return jsonify({'success': False, 'error': 'Capturer not running'})

    try:
        with _state_lock:
            process = active_processes.get('capturer')
        if process:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)

        # Cleanup
        subprocess.run(['killall', 'hostapd'], capture_output=True)
        subprocess.run(['killall', 'dnsmasq'], capture_output=True)

        with _state_lock:
            tool_status['capturer']['running'] = False
            tool_status['capturer']['pid'] = None
            tool_status['capturer']['interface'] = None

        emit_log('capturer', 'SSID capturer stopped')

        return jsonify({'success': True})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/deauth/start', methods=['POST'])
@login_required
@csrf_protect
def api_deauth_start():
    """Start deauthentication attack"""
    with _state_lock:
        if tool_status['deauth']['running']:
            return jsonify({'success': False, 'error': 'Deauth attack already running'})

    data = request.json
    interface = data.get('interface')
    bssid = data.get('bssid')
    client = data.get('client', 'ff:ff:ff:ff:ff:ff')
    count = data.get('count', 10)
    delay = data.get('delay', 0.1)
    channel = data.get('channel')
    continuous = data.get('continuous', False)

    # Input validation
    ok, err = validate_interface(interface)
    if not ok:
        return jsonify({'success': False, 'error': err}), 400

    ok, err = validate_mac(bssid)
    if not ok:
        return jsonify({'success': False, 'error': f'BSSID: {err}'}), 400

    ok, err = validate_mac(client)
    if not ok:
        return jsonify({'success': False, 'error': f'Client MAC: {err}'}), 400

    if not continuous:
        ok, err = validate_positive_number(count, 'Count')
        if not ok:
            return jsonify({'success': False, 'error': err}), 400

    ok, err = validate_positive_number(delay, 'Delay', allow_float=True)
    if not ok:
        return jsonify({'success': False, 'error': err}), 400

    if channel is not None and channel != '':
        ok, err = validate_channel(channel)
        if not ok:
            return jsonify({'success': False, 'error': err}), 400

    try:
        cmd = ['python3', 'deauth.py', '-i', interface, '-b', bssid]

        if client and client.lower() != 'ff:ff:ff:ff:ff:ff':
            cmd.extend(['-c', client])

        if continuous:
            cmd.append('--continuous')
        else:
            cmd.extend(['-n', str(count)])

        cmd.extend(['-d', str(delay)])

        if channel:
            cmd.extend(['-ch', str(channel)])

        # TODO: The CLI tools should accept a --no-confirm or --web-mode flag so the
        # web GUI does not need to pipe 'yes' into stdin.  Currently the CLI prompts
        # for an interactive authorization confirmation.  The web GUI's own confirmation
        # dialog (shown before the API call) serves as the authorization check, so
        # auto-confirming here is intentional.  When the CLI tools are updated to
        # support --web-mode, replace the stdin pipe with that flag.
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                  stdin=subprocess.PIPE)

        # Auto-confirm: the user already confirmed via the web GUI's dialog.
        process.stdin.write(b'yes\n')
        process.stdin.flush()

        with _state_lock:
            tool_status['deauth']['running'] = True
            tool_status['deauth']['pid'] = process.pid
            tool_status['deauth']['interface'] = interface
            active_processes['deauth'] = process

        # Start monitoring output
        monitor = ProcessMonitor('deauth', process, emit_log)
        monitor.start_monitoring()

        emit_log('deauth', f'Deauth attack started on {interface} targeting {bssid}')

        return jsonify({'success': True, 'pid': process.pid})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/deauth/stop', methods=['POST'])
@login_required
@csrf_protect
def api_deauth_stop():
    """Stop deauthentication attack"""
    with _state_lock:
        if not tool_status['deauth']['running']:
            return jsonify({'success': False, 'error': 'Deauth attack not running'})

    try:
        with _state_lock:
            process = active_processes.get('deauth')
        if process:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)

        with _state_lock:
            tool_status['deauth']['running'] = False
            tool_status['deauth']['pid'] = None
            tool_status['deauth']['interface'] = None

        emit_log('deauth', 'Deauth attack stopped')

        return jsonify({'success': True})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

# --- AP Scanner ---

@app.route('/api/ap-scanner/start', methods=['POST'])
@login_required
@csrf_protect
def api_ap_scanner_start():
    """Start AP scanner"""
    with _state_lock:
        if tool_status['ap_scanner']['running']:
            return jsonify({'success': False, 'error': 'AP Scanner already running'})

    data = request.json
    interface = data.get('interface')
    timeout = data.get('timeout', 30)
    channel = data.get('channel')

    ok, err = validate_interface(interface)
    if not ok:
        return jsonify({'success': False, 'error': err}), 400

    ok, err = validate_positive_number(timeout, 'Timeout')
    if not ok:
        return jsonify({'success': False, 'error': err}), 400

    if channel:
        ok, err = validate_channel(channel)
        if not ok:
            return jsonify({'success': False, 'error': err}), 400

    try:
        cmd = ['python3', 'ap_scanner.py', '-i', interface, '-t', str(timeout)]
        if channel:
            cmd.extend(['-ch', str(channel), '--no-hop'])

        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        with _state_lock:
            tool_status['ap_scanner']['running'] = True
            tool_status['ap_scanner']['pid'] = process.pid
            tool_status['ap_scanner']['interface'] = interface
            active_processes['ap_scanner'] = process

        monitor = ProcessMonitor('ap_scanner', process, emit_log)
        monitor.start_monitoring()

        emit_log('ap_scanner', f'AP Scanner started on {interface}')
        return jsonify({'success': True, 'pid': process.pid})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/ap-scanner/stop', methods=['POST'])
@login_required
@csrf_protect
def api_ap_scanner_stop():
    """Stop AP scanner"""
    with _state_lock:
        if not tool_status['ap_scanner']['running']:
            return jsonify({'success': False, 'error': 'AP Scanner not running'})

    try:
        with _state_lock:
            process = active_processes.get('ap_scanner')
        if process:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)

        with _state_lock:
            tool_status['ap_scanner']['running'] = False
            tool_status['ap_scanner']['pid'] = None
            tool_status['ap_scanner']['interface'] = None

        emit_log('ap_scanner', 'AP Scanner stopped')
        return jsonify({'success': True})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


# --- Handshake Capture ---

@app.route('/api/handshake/start', methods=['POST'])
@login_required
@csrf_protect
def api_handshake_start():
    """Start WPA handshake capture"""
    with _state_lock:
        if tool_status['handshake']['running']:
            return jsonify({'success': False, 'error': 'Handshake capture already running'})

    data = request.json
    interface = data.get('interface')
    bssid = data.get('bssid')
    client = data.get('client')
    channel = data.get('channel')
    timeout = data.get('timeout', 120)
    no_deauth = data.get('no_deauth', False)

    ok, err = validate_interface(interface)
    if not ok:
        return jsonify({'success': False, 'error': err}), 400

    ok, err = validate_mac(bssid)
    if not ok:
        return jsonify({'success': False, 'error': f'BSSID: {err}'}), 400

    if client:
        ok, err = validate_mac(client)
        if not ok:
            return jsonify({'success': False, 'error': f'Client MAC: {err}'}), 400

    ok, err = validate_positive_number(timeout, 'Timeout')
    if not ok:
        return jsonify({'success': False, 'error': err}), 400

    if channel:
        ok, err = validate_channel(channel)
        if not ok:
            return jsonify({'success': False, 'error': err}), 400

    try:
        cmd = ['python3', 'handshake_capture.py', '-i', interface, '-b', bssid,
               '-t', str(timeout)]
        if client:
            cmd.extend(['-c', client])
        if channel:
            cmd.extend(['-ch', str(channel)])
        if no_deauth:
            cmd.append('--no-deauth')

        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        with _state_lock:
            tool_status['handshake']['running'] = True
            tool_status['handshake']['pid'] = process.pid
            tool_status['handshake']['interface'] = interface
            active_processes['handshake'] = process

        monitor = ProcessMonitor('handshake', process, emit_log)
        monitor.start_monitoring()

        emit_log('handshake', f'Handshake capture started on {interface} targeting {bssid}')
        return jsonify({'success': True, 'pid': process.pid})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/handshake/stop', methods=['POST'])
@login_required
@csrf_protect
def api_handshake_stop():
    """Stop handshake capture"""
    with _state_lock:
        if not tool_status['handshake']['running']:
            return jsonify({'success': False, 'error': 'Handshake capture not running'})

    try:
        with _state_lock:
            process = active_processes.get('handshake')
        if process:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)

        with _state_lock:
            tool_status['handshake']['running'] = False
            tool_status['handshake']['pid'] = None
            tool_status['handshake']['interface'] = None

        emit_log('handshake', 'Handshake capture stopped')
        return jsonify({'success': True})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


# --- Captive Portal ---

@app.route('/api/portal/start', methods=['POST'])
@login_required
@csrf_protect
def api_portal_start():
    """Start captive portal"""
    with _state_lock:
        if tool_status['portal']['running']:
            return jsonify({'success': False, 'error': 'Captive portal already running'})

    data = request.json
    interface = data.get('interface')
    ssid = data.get('ssid', 'Free-WiFi')
    channel = data.get('channel', 6)
    template = data.get('template', 'default')

    ok, err = validate_interface(interface)
    if not ok:
        return jsonify({'success': False, 'error': err}), 400

    ok, err = validate_channel(channel)
    if not ok:
        return jsonify({'success': False, 'error': err}), 400

    if template not in ('default', 'hotel', 'coffee'):
        return jsonify({'success': False, 'error': 'Invalid template'}), 400

    if not ssid or len(ssid) > 32 or any(ord(c) < 32 for c in ssid):
        return jsonify({'success': False, 'error': 'Invalid SSID (max 32 chars, no control characters)'}), 400

    try:
        cmd = ['python3', 'captive_portal.py', '-i', interface, '-s', ssid,
               '-ch', str(channel), '-t', template]

        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        with _state_lock:
            tool_status['portal']['running'] = True
            tool_status['portal']['pid'] = process.pid
            tool_status['portal']['interface'] = interface
            active_processes['portal'] = process

        monitor = ProcessMonitor('portal', process, emit_log)
        monitor.start_monitoring()

        emit_log('portal', f'Captive portal started on {interface} (SSID: {ssid})')
        return jsonify({'success': True, 'pid': process.pid})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/portal/stop', methods=['POST'])
@login_required
@csrf_protect
def api_portal_stop():
    """Stop captive portal"""
    with _state_lock:
        if not tool_status['portal']['running']:
            return jsonify({'success': False, 'error': 'Captive portal not running'})

    try:
        with _state_lock:
            process = active_processes.get('portal')
        if process:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)

        subprocess.run(['killall', 'hostapd'], capture_output=True)
        subprocess.run(['killall', 'dnsmasq'], capture_output=True)

        with _state_lock:
            tool_status['portal']['running'] = False
            tool_status['portal']['pid'] = None
            tool_status['portal']['interface'] = None

        emit_log('portal', 'Captive portal stopped')
        return jsonify({'success': True})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


# --- Karma Attack ---

@app.route('/api/karma/start', methods=['POST'])
@login_required
@csrf_protect
def api_karma_start():
    """Start karma attack"""
    with _state_lock:
        if tool_status['karma']['running']:
            return jsonify({'success': False, 'error': 'Karma attack already running'})

    data = request.json
    interface = data.get('interface')
    channel = data.get('channel', 6)

    ok, err = validate_interface(interface)
    if not ok:
        return jsonify({'success': False, 'error': err}), 400

    ok, err = validate_channel(channel)
    if not ok:
        return jsonify({'success': False, 'error': err}), 400

    try:
        cmd = ['python3', 'karma_attack.py', '-i', interface, '-ch', str(channel)]

        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        with _state_lock:
            tool_status['karma']['running'] = True
            tool_status['karma']['pid'] = process.pid
            tool_status['karma']['interface'] = interface
            active_processes['karma'] = process

        monitor = ProcessMonitor('karma', process, emit_log)
        monitor.start_monitoring()

        emit_log('karma', f'Karma attack started on {interface}')
        return jsonify({'success': True, 'pid': process.pid})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/karma/stop', methods=['POST'])
@login_required
@csrf_protect
def api_karma_stop():
    """Stop karma attack"""
    with _state_lock:
        if not tool_status['karma']['running']:
            return jsonify({'success': False, 'error': 'Karma attack not running'})

    try:
        with _state_lock:
            process = active_processes.get('karma')
        if process:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)

        with _state_lock:
            tool_status['karma']['running'] = False
            tool_status['karma']['pid'] = None
            tool_status['karma']['interface'] = None

        emit_log('karma', 'Karma attack stopped')
        return jsonify({'success': True})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


# --- WIDS ---

@app.route('/api/wids/start', methods=['POST'])
@login_required
@csrf_protect
def api_wids_start():
    """Start wireless intrusion detection"""
    with _state_lock:
        if tool_status['wids']['running']:
            return jsonify({'success': False, 'error': 'WIDS already running'})

    data = request.json
    interface = data.get('interface')
    deauth_threshold = data.get('deauth_threshold', 10)

    ok, err = validate_interface(interface)
    if not ok:
        return jsonify({'success': False, 'error': err}), 400

    ok, err = validate_positive_number(deauth_threshold, 'Deauth threshold')
    if not ok:
        return jsonify({'success': False, 'error': err}), 400

    try:
        cmd = ['python3', 'wids.py', '-i', interface,
               '--deauth-threshold', str(deauth_threshold)]

        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        with _state_lock:
            tool_status['wids']['running'] = True
            tool_status['wids']['pid'] = process.pid
            tool_status['wids']['interface'] = interface
            active_processes['wids'] = process

        monitor = ProcessMonitor('wids', process, emit_log)
        monitor.start_monitoring()

        emit_log('wids', f'WIDS started on {interface}')
        return jsonify({'success': True, 'pid': process.pid})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/wids/stop', methods=['POST'])
@login_required
@csrf_protect
def api_wids_stop():
    """Stop wireless intrusion detection"""
    with _state_lock:
        if not tool_status['wids']['running']:
            return jsonify({'success': False, 'error': 'WIDS not running'})

    try:
        with _state_lock:
            process = active_processes.get('wids')
        if process:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)

        with _state_lock:
            tool_status['wids']['running'] = False
            tool_status['wids']['pid'] = None
            tool_status['wids']['interface'] = None

        emit_log('wids', 'WIDS stopped')
        return jsonify({'success': True})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/packet-replay/start', methods=['POST'])
@login_required
@csrf_protect
def api_packet_replay_start():
    """Start packet replay tool"""
    with _state_lock:
        if tool_status['packet_replay']['running']:
            return jsonify({'success': False, 'error': 'Packet replay already running'})

    data = request.json
    interface = data.get('interface')
    pcap_file = data.get('pcap_file')
    replay_count = data.get('replay_count', 1)
    delay = data.get('delay', 0.1)
    filter_type = data.get('filter_type')
    timeout = data.get('timeout', 30)

    ok, err = validate_interface(interface)
    if not ok:
        return jsonify({'success': False, 'error': err}), 400

    try:
        cmd = ['python3', 'packet_replay.py', '-i', interface, '-c', str(replay_count),
               '-d', str(delay), '-t', str(timeout)]
        if pcap_file:
            cmd.extend(['-r', pcap_file])
        if filter_type:
            cmd.extend(['--filter', filter_type])

        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        with _state_lock:
            tool_status['packet_replay']['running'] = True
            tool_status['packet_replay']['pid'] = process.pid
            tool_status['packet_replay']['interface'] = interface
            active_processes['packet_replay'] = process

        monitor = ProcessMonitor('packet_replay', process, emit_log)
        monitor.start_monitoring()

        emit_log('packet_replay', f'Packet replay started on {interface}')
        return jsonify({'success': True, 'pid': process.pid})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/packet-replay/stop', methods=['POST'])
@login_required
@csrf_protect
def api_packet_replay_stop():
    """Stop packet replay tool"""
    with _state_lock:
        if not tool_status['packet_replay']['running']:
            return jsonify({'success': False, 'error': 'Packet replay not running'})

    try:
        with _state_lock:
            process = active_processes.get('packet_replay')
        if process:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)

        with _state_lock:
            tool_status['packet_replay']['running'] = False
            tool_status['packet_replay']['pid'] = None
            tool_status['packet_replay']['interface'] = None

        emit_log('packet_replay', 'Packet replay stopped')
        return jsonify({'success': True})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/wps-attack/start', methods=['POST'])
@login_required
@csrf_protect
def api_wps_attack_start():
    """Start WPS attack"""
    with _state_lock:
        if tool_status['wps_attack']['running']:
            return jsonify({'success': False, 'error': 'WPS attack already running'})

    data = request.json
    interface = data.get('interface')
    bssid = data.get('bssid')
    method = data.get('method', 'reaver')
    timeout = data.get('timeout', 300)

    ok, err = validate_interface(interface)
    if not ok:
        return jsonify({'success': False, 'error': err}), 400

    ok, err = validate_mac(bssid)
    if not ok:
        return jsonify({'success': False, 'error': err}), 400

    try:
        cmd = ['python3', 'wps_attack.py', '-i', interface, '-b', bssid,
               '-m', method, '-t', str(timeout)]

        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        with _state_lock:
            tool_status['wps_attack']['running'] = True
            tool_status['wps_attack']['pid'] = process.pid
            tool_status['wps_attack']['interface'] = interface
            active_processes['wps_attack'] = process

        monitor = ProcessMonitor('wps_attack', process, emit_log)
        monitor.start_monitoring()

        emit_log('wps_attack', f'WPS attack started on {interface} targeting {bssid}')
        return jsonify({'success': True, 'pid': process.pid})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/wps-attack/stop', methods=['POST'])
@login_required
@csrf_protect
def api_wps_attack_stop():
    """Stop WPS attack"""
    with _state_lock:
        if not tool_status['wps_attack']['running']:
            return jsonify({'success': False, 'error': 'WPS attack not running'})

    try:
        with _state_lock:
            process = active_processes.get('wps_attack')
        if process:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)

        with _state_lock:
            tool_status['wps_attack']['running'] = False
            tool_status['wps_attack']['pid'] = None
            tool_status['wps_attack']['interface'] = None

        emit_log('wps_attack', 'WPS attack stopped')
        return jsonify({'success': True})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/network-mapper/start', methods=['POST'])
@login_required
@csrf_protect
def api_network_mapper_start():
    """Start network mapper"""
    with _state_lock:
        if tool_status['network_mapper']['running']:
            return jsonify({'success': False, 'error': 'Network mapper already running'})

    data = request.json
    interface = data.get('interface')
    target_range = data.get('target_range', '192.168.1.0/24')
    port_scan = data.get('port_scan', True)

    ok, err = validate_interface(interface)
    if not ok:
        return jsonify({'success': False, 'error': err}), 400

    try:
        cmd = ['python3', 'network_mapper.py', '-i', interface, '-r', target_range]
        if not port_scan:
            cmd.append('--no-port-scan')

        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        with _state_lock:
            tool_status['network_mapper']['running'] = True
            tool_status['network_mapper']['pid'] = process.pid
            tool_status['network_mapper']['interface'] = interface
            active_processes['network_mapper'] = process

        monitor = ProcessMonitor('network_mapper', process, emit_log)
        monitor.start_monitoring()

        emit_log('network_mapper', f'Network mapper started on {interface} ({target_range})')
        return jsonify({'success': True, 'pid': process.pid})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/network-mapper/stop', methods=['POST'])
@login_required
@csrf_protect
def api_network_mapper_stop():
    """Stop network mapper"""
    with _state_lock:
        if not tool_status['network_mapper']['running']:
            return jsonify({'success': False, 'error': 'Network mapper not running'})

    try:
        with _state_lock:
            process = active_processes.get('network_mapper')
        if process:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)

        with _state_lock:
            tool_status['network_mapper']['running'] = False
            tool_status['network_mapper']['pid'] = None
            tool_status['network_mapper']['interface'] = None

        emit_log('network_mapper', 'Network mapper stopped')
        return jsonify({'success': True})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/ble-scanner/start', methods=['POST'])
@login_required
@csrf_protect
def api_ble_scanner_start():
    """Start BLE scanner"""
    with _state_lock:
        if tool_status['ble_scanner']['running']:
            return jsonify({'success': False, 'error': 'BLE scanner already running'})

    data = request.json
    scan_time = data.get('scan_time', 10)
    service_scan = data.get('service_scan', False)
    filter_name = data.get('filter_name')

    try:
        cmd = ['python3', 'ble_scanner.py', '-t', str(scan_time)]
        if service_scan:
            cmd.append('--services')
        if filter_name:
            cmd.extend(['--filter-name', filter_name])

        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        with _state_lock:
            tool_status['ble_scanner']['running'] = True
            tool_status['ble_scanner']['pid'] = process.pid
            tool_status['ble_scanner']['interface'] = 'bluetooth'
            active_processes['ble_scanner'] = process

        monitor = ProcessMonitor('ble_scanner', process, emit_log)
        monitor.start_monitoring()

        emit_log('ble_scanner', 'BLE scanner started')
        return jsonify({'success': True, 'pid': process.pid})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/ble-scanner/stop', methods=['POST'])
@login_required
@csrf_protect
def api_ble_scanner_stop():
    """Stop BLE scanner"""
    with _state_lock:
        if not tool_status['ble_scanner']['running']:
            return jsonify({'success': False, 'error': 'BLE scanner not running'})

    try:
        with _state_lock:
            process = active_processes.get('ble_scanner')
        if process:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)

        with _state_lock:
            tool_status['ble_scanner']['running'] = False
            tool_status['ble_scanner']['pid'] = None
            tool_status['ble_scanner']['interface'] = None

        emit_log('ble_scanner', 'BLE scanner stopped')
        return jsonify({'success': True})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/pentest-workflow/start', methods=['POST'])
@login_required
@csrf_protect
def api_pentest_workflow_start():
    """Start automated pentest workflow"""
    with _state_lock:
        if tool_status['pentest_workflow']['running']:
            return jsonify({'success': False, 'error': 'Pentest workflow already running'})

    data = request.json
    interface = data.get('interface')
    bssid = data.get('bssid')
    no_deauth = data.get('no_deauth', False)
    skip_wps = data.get('skip_wps', False)
    timeout = data.get('timeout', 300)

    ok, err = validate_interface(interface)
    if not ok:
        return jsonify({'success': False, 'error': err}), 400

    try:
        cmd = ['python3', 'pentest_workflow.py', '-i', interface, '-t', str(timeout)]
        if bssid:
            ok, err = validate_mac(bssid)
            if not ok:
                return jsonify({'success': False, 'error': err}), 400
            cmd.extend(['-b', bssid])
        if no_deauth:
            cmd.append('--no-deauth')
        if skip_wps:
            cmd.append('--skip-wps')

        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        with _state_lock:
            tool_status['pentest_workflow']['running'] = True
            tool_status['pentest_workflow']['pid'] = process.pid
            tool_status['pentest_workflow']['interface'] = interface
            active_processes['pentest_workflow'] = process

        monitor = ProcessMonitor('pentest_workflow', process, emit_log)
        monitor.start_monitoring()

        emit_log('pentest_workflow', f'Pentest workflow started on {interface}')
        return jsonify({'success': True, 'pid': process.pid})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/pentest-workflow/stop', methods=['POST'])
@login_required
@csrf_protect
def api_pentest_workflow_stop():
    """Stop pentest workflow"""
    with _state_lock:
        if not tool_status['pentest_workflow']['running']:
            return jsonify({'success': False, 'error': 'Pentest workflow not running'})

    try:
        with _state_lock:
            process = active_processes.get('pentest_workflow')
        if process:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)

        with _state_lock:
            tool_status['pentest_workflow']['running'] = False
            tool_status['pentest_workflow']['pid'] = None
            tool_status['pentest_workflow']['interface'] = None

        emit_log('pentest_workflow', 'Pentest workflow stopped')
        return jsonify({'success': True})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/ssid-file/<filename>')
@login_required
def api_ssid_file(filename):
    """Get SSID file contents (from ssid_files/ directory only)"""
    try:
        # Validate filename to prevent path traversal
        if not filename or '/' in filename or '\\' in filename or '..' in filename:
            return jsonify({'success': False, 'error': 'Invalid filename'}), 400

        # Only allow .txt files
        if not filename.endswith('.txt'):
            return jsonify({'success': False, 'error': 'Only .txt files are allowed'}), 400

        if not _RE_FILENAME.match(filename):
            return jsonify({'success': False, 'error': 'Invalid characters in filename'}), 400

        # Only serve files from the dedicated ssid_files/ directory
        filepath = (SSID_FILES_DIR / filename).resolve()
        if not str(filepath).startswith(str(SSID_FILES_DIR.resolve())):
            return jsonify({'success': False, 'error': 'Access denied'}), 403

        with open(filepath, 'r') as f:
            content = f.read()
        return jsonify({'success': True, 'content': content})
    except FileNotFoundError:
        return jsonify({'success': False, 'error': 'File not found'}), 404
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/ssid-file/<filename>', methods=['POST'])
@login_required
@csrf_protect
def api_ssid_file_save(filename):
    """Save SSID file (into ssid_files/ directory only)"""
    try:
        # Validate filename to prevent path traversal
        if not filename or '/' in filename or '\\' in filename or '..' in filename:
            return jsonify({'success': False, 'error': 'Invalid filename'}), 400

        # Only allow .txt files
        if not filename.endswith('.txt'):
            return jsonify({'success': False, 'error': 'Only .txt files are allowed'}), 400

        if not _RE_FILENAME.match(filename):
            return jsonify({'success': False, 'error': 'Invalid characters in filename'}), 400

        # Ensure the ssid_files directory exists
        SSID_FILES_DIR.mkdir(exist_ok=True)

        # Only write files into the dedicated ssid_files/ directory
        filepath = (SSID_FILES_DIR / filename).resolve()
        if not str(filepath).startswith(str(SSID_FILES_DIR.resolve())):
            return jsonify({'success': False, 'error': 'Access denied'}), 403

        data = request.json
        content = data.get('content', '')

        with open(filepath, 'w') as f:
            f.write(content)

        emit_log('system', f'SSID file {filename} saved')
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/capture/<filename>')
@login_required
def api_capture_download(filename):
    """Download capture file"""
    try:
        # Validate filename to prevent path traversal
        if not filename or '/' in filename or '\\' in filename or '..' in filename:
            return jsonify({'success': False, 'error': 'Invalid filename'}), 400

        # Only allow .pcap files
        if not filename.endswith('.pcap'):
            return jsonify({'success': False, 'error': 'Only .pcap files are allowed'}), 400

        filepath = Path('./captures') / filename
        # Ensure the resolved path is in the captures directory
        if not filepath.resolve().parent == Path('./captures').resolve():
            return jsonify({'success': False, 'error': 'Access denied'}), 403

        if filepath.exists():
            return send_file(filepath, as_attachment=True)
        else:
            return jsonify({'success': False, 'error': 'File not found'}), 404
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    emit_log('system', 'Web client connected')

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    pass

def check_root():
    """Check if running as root"""
    if os.geteuid() != 0:
        print("[!] Warning: Some features require root privileges")
        print("[!] Run with: sudo python3 hoover_web.py")
        return False
    return True

def main():
    """Start web server"""
    print("="*70)
    print("Hoover Web GUI")
    print("="*70)
    print("\nWeb-based interface for Hoover WiFi security tools")
    print("\nIMPORTANT: For authorized security testing only!")
    print("Only use on networks you own or have written authorization to test.")
    print("="*70)

    check_root()

    # Migrate existing SSID files into ssid_files/ on first run
    _migrate_ssid_files()

    # Generate and display the login password
    password = _generate_auth_password()
    print(f"\n{'='*70}")
    print(f"  LOGIN PASSWORD: {password}")
    print(f"  (This password is generated fresh each time the server starts)")
    print(f"{'='*70}")

    host = '127.0.0.1'
    port = 5000

    print(f"\n[+] Starting web server on http://{host}:{port}")
    print(f"[+] Open this URL in your browser to access the interface")
    print(f"[*] Press Ctrl+C to stop\n")

    try:
        socketio.run(app, host=host, port=port, debug=False)
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")

        # Stop all running processes
        with _state_lock:
            procs = dict(active_processes)
        for tool, process in procs.items():
            try:
                process.terminate()
                process.wait(timeout=3)
            except (subprocess.TimeoutExpired, ProcessLookupError, Exception):
                try:
                    process.kill()
                    process.wait(timeout=3)
                except Exception:
                    pass

        print("[+] Goodbye!")

if __name__ == '__main__':
    main()
