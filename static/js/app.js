// Hoover Web GUI - Frontend JavaScript

// Initialize Socket.IO
const socket = io();

// State
let currentStatus = null;

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    initializeEventListeners();
    loadStatus();
    startStatusPolling();
    setupSocketListeners();
});

// Event Listeners
function initializeEventListeners() {
    // Monitor controls
    document.getElementById('monitor-start').addEventListener('click', startMonitor);
    document.getElementById('monitor-stop').addEventListener('click', stopMonitor);

    // Generator controls
    document.getElementById('generator-start').addEventListener('click', startGenerator);
    document.getElementById('generator-stop').addEventListener('click', stopGenerator);

    // Capturer controls
    document.getElementById('capturer-start').addEventListener('click', startCapturer);
    document.getElementById('capturer-stop').addEventListener('click', stopCapturer);

    // Deauth controls
    document.getElementById('deauth-start').addEventListener('click', startDeauth);
    document.getElementById('deauth-stop').addEventListener('click', stopDeauth);

    // Capturer rotation checkbox
    document.getElementById('capturer-rotate').addEventListener('change', (e) => {
        document.getElementById('capturer-ssid-group').style.display =
            e.target.checked ? 'none' : 'block';
    });

    // Capturer encryption select
    document.getElementById('capturer-encryption').addEventListener('change', (e) => {
        document.getElementById('capturer-password-group').style.display =
            e.target.value ? 'block' : 'none';
    });

    // Capturer internet checkbox
    document.getElementById('capturer-internet').addEventListener('change', (e) => {
        document.getElementById('capturer-upstream-group').style.display =
            e.target.checked ? 'block' : 'none';
    });

    // Logs controls
    document.getElementById('clear-logs').addEventListener('click', clearLogs);

    // Captures controls
    document.getElementById('refresh-captures').addEventListener('click', loadStatus);
}

// Socket.IO listeners
function setupSocketListeners() {
    socket.on('connect', () => {
        addLog('system', 'Connected to server');
    });

    socket.on('disconnect', () => {
        addLog('system', 'Disconnected from server');
    });

    socket.on('log', (data) => {
        addLog(data.tool, data.message, data.timestamp);
    });
}

// API Calls
async function apiCall(endpoint, method = 'GET', data = null) {
    try {
        const options = {
            method: method,
            headers: {
                'Content-Type': 'application/json'
            }
        };

        if (data) {
            options.body = JSON.stringify(data);
        }

        const response = await fetch(endpoint, options);
        return await response.json();
    } catch (error) {
        console.error('API call failed:', error);
        return { success: false, error: error.message };
    }
}

// Load system status
async function loadStatus() {
    const result = await apiCall('/api/status');

    if (result) {
        currentStatus = result;
        updateUI(result);
    }
}

// Start status polling
function startStatusPolling() {
    setInterval(loadStatus, 2000); // Poll every 2 seconds
}

// Update UI with status data
function updateUI(data) {
    // Update system resources
    document.getElementById('cpu-usage').textContent = `${data.system.cpu.toFixed(1)}%`;
    document.getElementById('memory-usage').textContent = `${data.system.memory.toFixed(1)}%`;

    // Update interfaces
    updateInterfacesList(data.interfaces);
    populateInterfaceSelects(data.interfaces);

    // Update SSID files
    updateSSIDFilesList(data.ssid_files);
    populateSSIDFileSelects(data.ssid_files);

    // Update tool statuses
    updateToolStatus('monitor', data.status.monitor);
    updateToolStatus('generator', data.status.generator);
    updateToolStatus('capturer', data.status.capturer);
    updateToolStatus('deauth', data.status.deauth);

    // Update captures
    updateCapturesList(data.captures);
}

// Update interfaces list
function updateInterfacesList(interfaces) {
    const container = document.getElementById('interfaces-list');

    if (interfaces.length === 0) {
        container.innerHTML = '<p class="empty-message">No interfaces found</p>';
        return;
    }

    container.innerHTML = interfaces.map(iface => `
        <div class="stat">
            <span>${iface.name}</span>
            <span style="color: ${iface.mode === 'Monitor' ? 'var(--accent-green)' : 'var(--text-secondary)'}">
                ${iface.mode}
            </span>
        </div>
    `).join('');
}

// Populate interface select dropdowns
function populateInterfaceSelects(interfaces) {
    const selects = ['monitor-interface', 'generator-interface', 'capturer-interface', 'deauth-interface'];

    selects.forEach(selectId => {
        const select = document.getElementById(selectId);
        const currentValue = select.value;

        select.innerHTML = '<option value="">Select interface...</option>' +
            interfaces.map(iface =>
                `<option value="${iface.name}">${iface.name} (${iface.mode})</option>`
            ).join('');

        // Restore previous selection if still available
        if (currentValue) {
            select.value = currentValue;
        }
    });
}

// Update SSID files list
function updateSSIDFilesList(files) {
    const container = document.getElementById('ssid-files-list');

    if (files.length === 0) {
        container.innerHTML = '<p class="empty-message">No SSID files found</p>';
        return;
    }

    container.innerHTML = files.map(file => `
        <div class="stat">
            <span>${file.name}</span>
            <span>${file.count} SSIDs</span>
        </div>
    `).join('');
}

// Populate SSID file select dropdowns
function populateSSIDFileSelects(files) {
    const selects = ['generator-file', 'capturer-file'];

    selects.forEach(selectId => {
        const select = document.getElementById(selectId);
        const currentValue = select.value;

        select.innerHTML = '<option value="">Select file...</option>' +
            files.map(file =>
                `<option value="${file.name}">${file.name} (${file.count} SSIDs)</option>`
            ).join('');

        // Restore previous selection if still available
        if (currentValue) {
            select.value = currentValue;
        }
    });
}

// Update tool status
function updateToolStatus(tool, status) {
    const badge = document.getElementById(`${tool}-status`);
    const startBtn = document.getElementById(`${tool}-start`);
    const stopBtn = document.getElementById(`${tool}-stop`);

    if (status.running) {
        badge.textContent = 'Running';
        badge.classList.add('running');
        startBtn.disabled = true;
        stopBtn.disabled = false;
    } else {
        badge.textContent = 'Stopped';
        badge.classList.remove('running');
        startBtn.disabled = false;
        stopBtn.disabled = true;
    }
}

// Update captures list
function updateCapturesList(captures) {
    const container = document.getElementById('captures-list');

    if (captures.length === 0) {
        container.innerHTML = '<p class="empty-message">No captures yet. Start the SSID Capturer to record traffic.</p>';
        return;
    }

    container.innerHTML = captures.map(capture => `
        <div class="capture-item">
            <div class="capture-info">
                <div class="capture-name">${capture.name}</div>
                <div class="capture-meta">
                    ${formatBytes(capture.size)} • ${capture.modified}
                </div>
            </div>
            <a href="/api/capture/${capture.name}" class="capture-download">Download</a>
        </div>
    `).join('');
}

// Tool control functions
async function startMonitor() {
    const interface_name = document.getElementById('monitor-interface').value;
    const verbose = document.getElementById('monitor-verbose').checked;

    if (!interface_name) {
        alert('Please select an interface');
        return;
    }

    const result = await apiCall('/api/monitor/start', 'POST', {
        interface: interface_name,
        verbose: verbose
    });

    if (result.success) {
        addLog('monitor', `Started on ${interface_name}`);
    } else {
        alert(`Failed to start monitor: ${result.error}`);
    }
}

async function stopMonitor() {
    const result = await apiCall('/api/monitor/stop', 'POST');

    if (!result.success) {
        alert(`Failed to stop monitor: ${result.error}`);
    }
}

async function startGenerator() {
    const interface_name = document.getElementById('generator-interface').value;
    const ssid_file = document.getElementById('generator-file').value;
    const continuous = document.getElementById('generator-continuous').checked;
    const interval = parseFloat(document.getElementById('generator-interval').value);
    const channel = parseInt(document.getElementById('generator-channel').value);

    if (!interface_name || !ssid_file) {
        alert('Please select interface and SSID file');
        return;
    }

    const result = await apiCall('/api/generator/start', 'POST', {
        interface: interface_name,
        ssid_file: ssid_file,
        continuous: continuous,
        interval: interval,
        channel: channel
    });

    if (result.success) {
        addLog('generator', `Started on ${interface_name}`);
    } else {
        alert(`Failed to start generator: ${result.error}`);
    }
}

async function stopGenerator() {
    const result = await apiCall('/api/generator/stop', 'POST');

    if (!result.success) {
        alert(`Failed to stop generator: ${result.error}`);
    }
}

async function startCapturer() {
    const interface_name = document.getElementById('capturer-interface').value;
    const ssid_file = document.getElementById('capturer-file').value;
    const rotate = document.getElementById('capturer-rotate').checked;
    const ssid = document.getElementById('capturer-ssid').value;
    const duration = parseInt(document.getElementById('capturer-duration').value);
    const channel = parseInt(document.getElementById('capturer-channel').value);
    const encryption = document.getElementById('capturer-encryption').value;
    const password = document.getElementById('capturer-password').value;
    const internet = document.getElementById('capturer-internet').checked;
    const upstream = document.getElementById('capturer-upstream').value;

    if (!interface_name || !ssid_file) {
        alert('Please select interface and SSID file');
        return;
    }

    if (!rotate && !ssid) {
        alert('Please enter an SSID or enable rotation');
        return;
    }

    if (encryption && !password) {
        alert('Password required for encrypted networks');
        return;
    }

    if (internet && !upstream) {
        alert('Upstream interface required for internet sharing');
        return;
    }

    // Confirmation dialog
    if (!confirm('⚠️ AUTHORIZATION REQUIRED\n\nThis tool creates a rogue access point and captures network traffic.\n\nOnly proceed if you have written authorization to test this network.\n\nUnauthorized use may be illegal.\n\nDo you confirm you have authorization?')) {
        return;
    }

    const result = await apiCall('/api/capturer/start', 'POST', {
        interface: interface_name,
        ssid_file: ssid_file,
        rotate: rotate,
        ssid: ssid,
        duration: duration,
        channel: channel,
        encryption: encryption || null,
        password: password || null,
        internet: internet,
        upstream: upstream || null
    });

    if (result.success) {
        addLog('capturer', `Started on ${interface_name}`);
    } else {
        alert(`Failed to start capturer: ${result.error}`);
    }
}

async function stopCapturer() {
    const result = await apiCall('/api/capturer/stop', 'POST');

    if (!result.success) {
        alert(`Failed to stop capturer: ${result.error}`);
    }
}

async function startDeauth() {
    const interface_name = document.getElementById('deauth-interface').value;
    const bssid = document.getElementById('deauth-bssid').value.trim();
    const client = document.getElementById('deauth-client').value.trim() || 'ff:ff:ff:ff:ff:ff';
    const count = parseInt(document.getElementById('deauth-count').value);
    const channel = parseInt(document.getElementById('deauth-channel').value);
    const delay = parseFloat(document.getElementById('deauth-delay').value);
    const continuous = document.getElementById('deauth-continuous').checked;

    // Validate inputs
    if (!interface_name) {
        alert('Please select an interface');
        return;
    }

    if (!bssid) {
        alert('Please enter target BSSID (AP MAC address)');
        return;
    }

    // Validate MAC address format
    const macRegex = /^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/;
    if (!macRegex.test(bssid)) {
        alert('Invalid BSSID format. Use format: 00:11:22:33:44:55');
        return;
    }

    if (client && !macRegex.test(client)) {
        alert('Invalid client MAC format. Use format: 00:11:22:33:44:55');
        return;
    }

    // Confirmation dialog
    if (!confirm('⚠️ AUTHORIZATION REQUIRED\n\nThis tool sends WiFi deauthentication frames that will disconnect clients from wireless networks.\n\nThis is a DISRUPTIVE action!\n\nOnly proceed if you have written authorization to test this network.\n\nUnauthorized use may violate:\n- Computer Fraud and Abuse Act (CFAA)\n- Federal Wiretap Act\n- Local computer crime laws\n\nDo you confirm you have authorization?')) {
        return;
    }

    const result = await apiCall('/api/deauth/start', 'POST', {
        interface: interface_name,
        bssid: bssid,
        client: client,
        count: count,
        channel: channel,
        delay: delay,
        continuous: continuous
    });

    if (result.success) {
        addLog('deauth', `Started deauth attack on ${interface_name} targeting ${bssid}`);
    } else {
        alert(`Failed to start deauth attack: ${result.error}`);
    }
}

async function stopDeauth() {
    const result = await apiCall('/api/deauth/stop', 'POST');

    if (!result.success) {
        alert(`Failed to stop deauth attack: ${result.error}`);
    }
}

// Logging functions
function addLog(tool, message, timestamp = null) {
    const container = document.getElementById('logs-container');

    if (!timestamp) {
        const now = new Date();
        timestamp = now.toTimeString().split(' ')[0];
    }

    const logEntry = document.createElement('div');
    logEntry.className = 'log-entry';

    const toolClass = tool.toLowerCase();
    const toolLabel = tool.toUpperCase();

    logEntry.innerHTML = `
        <span class="log-time">${timestamp}</span>
        <span class="log-tool ${toolClass}">[${toolLabel}]</span>
        <span class="log-message">${escapeHtml(message)}</span>
    `;

    container.appendChild(logEntry);

    // Auto-scroll to bottom
    container.scrollTop = container.scrollHeight;

    // Limit log entries to 200
    while (container.children.length > 200) {
        container.removeChild(container.firstChild);
    }
}

function clearLogs() {
    const container = document.getElementById('logs-container');
    container.innerHTML = '<div class="log-entry system"><span class="log-time">--:--:--</span><span class="log-tool">[SYSTEM]</span><span class="log-message">Logs cleared</span></div>';
}

// Utility functions
function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}
