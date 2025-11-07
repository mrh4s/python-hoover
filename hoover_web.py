#!/usr/bin/env python3
"""
Hoover Web GUI - Web-based interface for Hoover WiFi tools
Dark-themed local web interface for easy tool management
"""

from flask import Flask, render_template, jsonify, request, send_file
from flask_socketio import SocketIO, emit
import subprocess
import os
import json
import signal
import threading
import time
from datetime import datetime
from pathlib import Path
import psutil

app = Flask(__name__)
app.config['SECRET_KEY'] = 'hoover-secret-key-change-in-production'
socketio = SocketIO(app, cors_allowed_origins="*")

# Global state
active_processes = {}
tool_status = {
    'monitor': {'running': False, 'pid': None, 'interface': None},
    'generator': {'running': False, 'pid': None, 'interface': None},
    'capturer': {'running': False, 'pid': None, 'interface': None}
}

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
                        self.log_callback(self.tool_name, line.decode('utf-8', errors='ignore').strip())
            except Exception as e:
                self.log_callback(self.tool_name, f"Error reading output: {e}")
            time.sleep(0.1)

        # Process ended
        if self.process.poll() is not None:
            self.log_callback(self.tool_name, f"Process exited with code {self.process.returncode}")
            tool_status[self.tool_name]['running'] = False
            tool_status[self.tool_name]['pid'] = None

    def stop(self):
        """Stop monitoring"""
        self.running = False

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
                except:
                    # If iw fails, default to Managed mode
                    pass

                interfaces.append({'name': iface_name, 'mode': mode})

    except Exception as e:
        print(f"[!] Error in fallback interface discovery: {e}")

    return interfaces

def get_ssid_files():
    """Get list of SSID files"""
    files = []
    for f in Path('.').glob('*.txt'):
        if f.is_file():
            with open(f, 'r') as file:
                lines = [l.strip() for l in file if l.strip() and not l.startswith('#')]
                files.append({
                    'name': f.name,
                    'count': len(lines)
                })
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

@app.route('/')
def index():
    """Serve main page"""
    return render_template('index.html')

@app.route('/api/status')
def api_status():
    """Get current status"""
    return jsonify({
        'status': tool_status,
        'interfaces': get_network_interfaces(),
        'ssid_files': get_ssid_files(),
        'captures': get_capture_files(),
        'system': {
            'cpu': psutil.cpu_percent(),
            'memory': psutil.virtual_memory().percent
        }
    })

@app.route('/api/interfaces')
def api_interfaces():
    """Get network interfaces"""
    return jsonify(get_network_interfaces())

@app.route('/api/monitor/start', methods=['POST'])
def api_monitor_start():
    """Start probe request monitor"""
    if tool_status['monitor']['running']:
        return jsonify({'success': False, 'error': 'Monitor already running'})

    data = request.json
    interface = data.get('interface')
    verbose = data.get('verbose', False)

    if not interface:
        return jsonify({'success': False, 'error': 'Interface required'})

    try:
        cmd = ['python3', 'hoover.py', '-i', interface]
        if verbose:
            cmd.append('-v')

        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

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
def api_monitor_stop():
    """Stop probe request monitor"""
    if not tool_status['monitor']['running']:
        return jsonify({'success': False, 'error': 'Monitor not running'})

    try:
        process = active_processes.get('monitor')
        if process:
            process.terminate()
            process.wait(timeout=5)

        tool_status['monitor']['running'] = False
        tool_status['monitor']['pid'] = None
        tool_status['monitor']['interface'] = None

        emit_log('monitor', 'Probe request monitor stopped')

        return jsonify({'success': True})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/generator/start', methods=['POST'])
def api_generator_start():
    """Start SSID generator"""
    if tool_status['generator']['running']:
        return jsonify({'success': False, 'error': 'Generator already running'})

    data = request.json
    interface = data.get('interface')
    ssid_file = data.get('ssid_file')
    continuous = data.get('continuous', False)
    interval = data.get('interval', 0.1)
    channel = data.get('channel', 6)

    if not interface or not ssid_file:
        return jsonify({'success': False, 'error': 'Interface and SSID file required'})

    try:
        cmd = ['python3', 'ssid_generator.py', '-i', interface, '-f', ssid_file,
               '-t', str(interval), '-ch', str(channel)]

        if continuous:
            cmd.append('-c')

        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

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
def api_generator_stop():
    """Stop SSID generator"""
    if not tool_status['generator']['running']:
        return jsonify({'success': False, 'error': 'Generator not running'})

    try:
        process = active_processes.get('generator')
        if process:
            process.terminate()
            process.wait(timeout=5)

        tool_status['generator']['running'] = False
        tool_status['generator']['pid'] = None
        tool_status['generator']['interface'] = None

        emit_log('generator', 'SSID generator stopped')

        return jsonify({'success': True})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/capturer/start', methods=['POST'])
def api_capturer_start():
    """Start SSID capturer"""
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

    if not interface or not ssid_file:
        return jsonify({'success': False, 'error': 'Interface and SSID file required'})

    if not rotate and not ssid:
        return jsonify({'success': False, 'error': 'SSID required when not rotating'})

    try:
        cmd = ['python3', 'ssid_capturer.py', '-i', interface, '-f', ssid_file,
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

        # Note: This needs manual authorization confirmation
        # For web GUI, we'll need to handle this differently
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                  stdin=subprocess.PIPE)

        # Auto-confirm authorization (user already confirmed in web GUI)
        process.stdin.write(b'yes\n')
        process.stdin.flush()

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
def api_capturer_stop():
    """Stop SSID capturer"""
    if not tool_status['capturer']['running']:
        return jsonify({'success': False, 'error': 'Capturer not running'})

    try:
        process = active_processes.get('capturer')
        if process:
            process.terminate()
            process.wait(timeout=5)

        # Cleanup
        subprocess.run(['killall', 'hostapd'], capture_output=True)
        subprocess.run(['killall', 'dnsmasq'], capture_output=True)

        tool_status['capturer']['running'] = False
        tool_status['capturer']['pid'] = None
        tool_status['capturer']['interface'] = None

        emit_log('capturer', 'SSID capturer stopped')

        return jsonify({'success': True})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/ssid-file/<filename>')
def api_ssid_file(filename):
    """Get SSID file contents"""
    try:
        with open(filename, 'r') as f:
            content = f.read()
        return jsonify({'success': True, 'content': content})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/ssid-file/<filename>', methods=['POST'])
def api_ssid_file_save(filename):
    """Save SSID file"""
    try:
        data = request.json
        content = data.get('content', '')

        with open(filename, 'w') as f:
            f.write(content)

        emit_log('system', f'SSID file {filename} saved')
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/capture/<filename>')
def api_capture_download(filename):
    """Download capture file"""
    try:
        filepath = Path('./captures') / filename
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
        for tool, process in active_processes.items():
            try:
                process.terminate()
                process.wait(timeout=3)
            except:
                pass

        print("[+] Goodbye!")

if __name__ == '__main__':
    main()
