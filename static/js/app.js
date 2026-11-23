// Hoover Web GUI - Frontend JavaScript

// Initialize Socket.IO
const socket = io();

// State
let currentStatus = null;
let probeData = [];
let probeSortKey = 'timestamp';
let probeSortAsc = false; // newest first by default
let probeFilterText = '';

// CSRF token from meta tag
function getCsrfToken() {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute('content') : '';
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    initializeEventListeners();
    loadStatus();
    loadProbeBuffer();
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

    // AP Scanner controls
    document.getElementById('ap-scanner-start').addEventListener('click', startAPScanner);
    document.getElementById('ap-scanner-stop').addEventListener('click', stopAPScanner);

    // Handshake Capture controls
    document.getElementById('handshake-start').addEventListener('click', startHandshake);
    document.getElementById('handshake-stop').addEventListener('click', stopHandshake);

    // Captive Portal controls
    document.getElementById('portal-start').addEventListener('click', startPortal);
    document.getElementById('portal-stop').addEventListener('click', stopPortal);

    // Karma Attack controls
    document.getElementById('karma-start').addEventListener('click', startKarma);
    document.getElementById('karma-stop').addEventListener('click', stopKarma);

    // WIDS controls
    document.getElementById('wids-start').addEventListener('click', startWIDS);
    document.getElementById('wids-stop').addEventListener('click', stopWIDS);

    // Packet Replay controls
    document.getElementById('packet-replay-start').addEventListener('click', startPacketReplay);
    document.getElementById('packet-replay-stop').addEventListener('click', stopPacketReplay);

    // WPS Attack controls
    document.getElementById('wps-attack-start').addEventListener('click', startWPSAttack);
    document.getElementById('wps-attack-stop').addEventListener('click', stopWPSAttack);

    // Network Mapper controls
    document.getElementById('network-mapper-start').addEventListener('click', startNetworkMapper);
    document.getElementById('network-mapper-stop').addEventListener('click', stopNetworkMapper);

    // BLE Scanner controls
    document.getElementById('ble-scanner-start').addEventListener('click', startBLEScanner);
    document.getElementById('ble-scanner-stop').addEventListener('click', stopBLEScanner);

    // Pentest Workflow controls
    document.getElementById('pentest-workflow-start').addEventListener('click', startPentestWorkflow);
    document.getElementById('pentest-workflow-stop').addEventListener('click', stopPentestWorkflow);

    // EAP Attack controls
    document.getElementById('eap-attack-start').addEventListener('click', startEAPAttack);
    document.getElementById('eap-attack-stop').addEventListener('click', stopEAPAttack);

    // PMKID Capture controls
    document.getElementById('pmkid-capture-start').addEventListener('click', startPMKIDCapture);
    document.getElementById('pmkid-capture-stop').addEventListener('click', stopPMKIDCapture);

    // MitM Attack controls
    document.getElementById('mitm-attack-start').addEventListener('click', startMitMAttack);
    document.getElementById('mitm-attack-stop').addEventListener('click', stopMitMAttack);

    // BLE Attack controls
    document.getElementById('ble-attack-start').addEventListener('click', startBLEAttack);
    document.getElementById('ble-attack-stop').addEventListener('click', stopBLEAttack);

    // Dragonblood controls
    document.getElementById('dragonblood-start').addEventListener('click', startDragonblood);
    document.getElementById('dragonblood-stop').addEventListener('click', stopDragonblood);

    // KRACK Detect controls
    document.getElementById('krack-start').addEventListener('click', startKRACK);
    document.getElementById('krack-stop').addEventListener('click', stopKRACK);

    // FragAttacks controls
    document.getElementById('fragattacks-start').addEventListener('click', startFragAttacks);
    document.getElementById('fragattacks-stop').addEventListener('click', stopFragAttacks);

    // Wardriving controls
    document.getElementById('wardriving-start').addEventListener('click', startWardriving);
    document.getElementById('wardriving-stop').addEventListener('click', stopWardriving);

    // Cloud C2 controls
    document.getElementById('cloud-c2-start').addEventListener('click', startCloudC2);
    document.getElementById('cloud-c2-stop').addEventListener('click', stopCloudC2);

    // WEP Attack controls
    document.getElementById('wep-attack-start').addEventListener('click', startWEPAttack);
    document.getElementById('wep-attack-stop').addEventListener('click', stopWEPAttack);

    // FT Attack controls
    document.getElementById('ft-attack-start').addEventListener('click', startFTAttack);
    document.getElementById('ft-attack-stop').addEventListener('click', stopFTAttack);

    // Password Crack controls
    document.getElementById('password-crack-start').addEventListener('click', startPasswordCrack);
    document.getElementById('password-crack-stop').addEventListener('click', stopPasswordCrack);

    // Channel MitM controls
    document.getElementById('channel-mitm-start').addEventListener('click', startChannelMitM);
    document.getElementById('channel-mitm-stop').addEventListener('click', stopChannelMitM);

    // WiFi Direct controls
    document.getElementById('wifi-direct-start').addEventListener('click', startWiFiDirect);
    document.getElementById('wifi-direct-stop').addEventListener('click', stopWiFiDirect);

    // Jamming Detect controls
    document.getElementById('jamming-detect-start').addEventListener('click', startJammingDetect);
    document.getElementById('jamming-detect-stop').addEventListener('click', stopJammingDetect);

    // DHCP/DNS Attack controls
    document.getElementById('dhcp-dns-attack-start').addEventListener('click', startDHCPDNSAttack);
    document.getElementById('dhcp-dns-attack-stop').addEventListener('click', stopDHCPDNSAttack);

    // Portal Bypass controls
    document.getElementById('portal-bypass-start').addEventListener('click', startPortalBypass);
    document.getElementById('portal-bypass-stop').addEventListener('click', stopPortalBypass);

    // Multi-Adapter controls
    document.getElementById('multi-adapter-discover').addEventListener('click', discoverMultiAdapter);

    // Report Generator controls
    document.getElementById('report-generate').addEventListener('click', generateReport);

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

    // Logout button
    document.getElementById('logout-btn').addEventListener('click', doLogout);

    // Probe filter input
    document.getElementById('probe-filter').addEventListener('input', (e) => {
        probeFilterText = e.target.value.toLowerCase();
        renderProbeTable();
    });

    // Probe table sortable headers
    document.querySelectorAll('.probe-table th.sortable').forEach(th => {
        th.addEventListener('click', () => {
            const key = th.getAttribute('data-sort');
            if (probeSortKey === key) {
                probeSortAsc = !probeSortAsc;
            } else {
                probeSortKey = key;
                probeSortAsc = true;
            }
            // Update sort indicators
            document.querySelectorAll('.probe-table th.sortable').forEach(h => {
                h.classList.remove('sort-asc', 'sort-desc');
            });
            th.classList.add(probeSortAsc ? 'sort-asc' : 'sort-desc');
            renderProbeTable();
        });
    });
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

    socket.on('probe', (data) => {
        probeData.push(data);
        // Keep only the last 100 probes client-side
        if (probeData.length > 100) {
            probeData = probeData.slice(-100);
        }
        renderProbeTable();
    });
}

// API Calls with CSRF token
async function apiCall(endpoint, method = 'GET', data = null) {
    try {
        const options = {
            method: method,
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': getCsrfToken()
            }
        };

        if (data) {
            options.body = JSON.stringify(data);
        }

        const response = await fetch(endpoint, options);

        // If 401, redirect to login
        if (response.status === 401) {
            window.location.href = '/login';
            return { success: false, error: 'Session expired' };
        }

        return await response.json();
    } catch (error) {
        console.error('API call failed:', error);
        return { success: false, error: error.message };
    }
}

// Logout
async function doLogout() {
    await fetch('/api/logout', { method: 'POST' });
    window.location.href = '/login';
}

// Load probe buffer from server
async function loadProbeBuffer() {
    const result = await apiCall('/api/probes');
    if (result && result.success && result.probes) {
        probeData = result.probes;
        renderProbeTable();
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
    updateToolStatus('ap-scanner', data.status.ap_scanner);
    updateToolStatus('handshake', data.status.handshake);
    updateToolStatus('portal', data.status.portal);
    updateToolStatus('karma', data.status.karma);
    updateToolStatus('wids', data.status.wids);
    updateToolStatus('packet-replay', data.status.packet_replay);
    updateToolStatus('wps-attack', data.status.wps_attack);
    updateToolStatus('network-mapper', data.status.network_mapper);
    updateToolStatus('ble-scanner', data.status.ble_scanner);
    updateToolStatus('pentest-workflow', data.status.pentest_workflow);
    updateToolStatus('eap-attack', data.status.eap_attack);
    updateToolStatus('pmkid-capture', data.status.pmkid_capture);
    updateToolStatus('mitm-attack', data.status.mitm_attack);
    updateToolStatus('ble-attack', data.status.ble_attack);
    updateToolStatus('dragonblood', data.status.dragonblood);
    updateToolStatus('krack', data.status.krack);
    updateToolStatus('fragattacks', data.status.fragattacks);
    updateToolStatus('wardriving', data.status.wardriving);
    updateToolStatus('cloud-c2', data.status.cloud_c2);
    updateToolStatus('wep-attack', data.status.wep_attack);
    updateToolStatus('ft-attack', data.status.ft_attack);
    updateToolStatus('password-crack', data.status.password_crack);
    updateToolStatus('channel-mitm', data.status.channel_mitm);
    updateToolStatus('wifi-direct', data.status.wifi_direct);
    updateToolStatus('jamming-detect', data.status.jamming_detect);
    updateToolStatus('dhcp-dns-attack', data.status.dhcp_dns_attack);
    updateToolStatus('portal-bypass', data.status.portal_bypass);

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
            <span>${escapeHtml(iface.name)}</span>
            <span style="color: ${iface.mode === 'Monitor' ? 'var(--accent-green)' : 'var(--text-secondary)'}">
                ${escapeHtml(iface.mode)}
            </span>
        </div>
    `).join('');
}

// Populate interface select dropdowns
function populateInterfaceSelects(interfaces) {
    const selects = ['monitor-interface', 'generator-interface', 'capturer-interface', 'deauth-interface',
                     'ap-scanner-interface', 'handshake-interface', 'portal-interface', 'karma-interface', 'wids-interface',
                     'packet-replay-interface', 'wps-attack-interface', 'network-mapper-interface', 'pentest-workflow-interface',
                     'eap-attack-interface', 'pmkid-capture-interface', 'mitm-attack-interface',
                     'ble-attack-interface', 'dragonblood-interface', 'krack-interface', 'fragattacks-interface',
                     'wardriving-interface', 'wep-attack-interface', 'ft-attack-interface', 'channel-mitm-monitor-interface',
                     'channel-mitm-inject-interface', 'wifi-direct-interface', 'jamming-detect-interface',
                     'dhcp-dns-attack-interface', 'portal-bypass-interface'];

    selects.forEach(selectId => {
        const select = document.getElementById(selectId);
        const currentValue = select.value;

        select.innerHTML = '<option value="">Select interface...</option>' +
            interfaces.map(iface =>
                `<option value="${escapeHtml(iface.name)}">${escapeHtml(iface.name)} (${escapeHtml(iface.mode)})</option>`
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
        container.innerHTML = '<p class="empty-message">No SSID files found in ssid_files/</p>';
        return;
    }

    container.innerHTML = files.map(file => `
        <div class="stat">
            <span>${escapeHtml(file.name)}</span>
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
                `<option value="${escapeHtml(file.name)}">${escapeHtml(file.name)} (${file.count} SSIDs)</option>`
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
                <div class="capture-name">${escapeHtml(capture.name)}</div>
                <div class="capture-meta">
                    ${formatBytes(capture.size)} - ${escapeHtml(capture.modified)}
                </div>
            </div>
            <a href="/api/capture/${encodeURIComponent(capture.name)}" class="capture-download">Download</a>
        </div>
    `).join('');
}

// --- Probe Table ---

function renderProbeTable() {
    const tbody = document.getElementById('probe-table-body');
    const countBadge = document.getElementById('probe-count');

    // Filter
    let filtered = probeData;
    if (probeFilterText) {
        filtered = probeData.filter(p => {
            const haystack = [p.mac || '', p.ssid || '', p.vendor || '', p.timestamp || ''].join(' ').toLowerCase();
            return haystack.includes(probeFilterText);
        });
    }

    // Sort
    filtered = [...filtered].sort((a, b) => {
        let va = a[probeSortKey] || '';
        let vb = b[probeSortKey] || '';
        if (probeSortKey === 'signal') {
            va = a.signal != null ? a.signal : -999;
            vb = b.signal != null ? b.signal : -999;
            return probeSortAsc ? va - vb : vb - va;
        }
        va = String(va).toLowerCase();
        vb = String(vb).toLowerCase();
        if (va < vb) return probeSortAsc ? -1 : 1;
        if (va > vb) return probeSortAsc ? 1 : -1;
        return 0;
    });

    countBadge.textContent = probeData.length;

    if (filtered.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" class="empty-message">No probe requests captured yet. Start the monitor above.</td></tr>';
        return;
    }

    tbody.innerHTML = filtered.map(p => `
        <tr>
            <td>${escapeHtml(p.timestamp || '')}</td>
            <td class="mono">${escapeHtml(p.mac || '')}</td>
            <td>${escapeHtml(p.vendor || '')}</td>
            <td>${escapeHtml(p.ssid || '(hidden)')}</td>
            <td>${p.signal != null ? p.signal + ' dBm' : '--'}</td>
        </tr>
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
    if (!confirm('AUTHORIZATION REQUIRED\n\nThis tool creates a rogue access point and captures network traffic.\n\nOnly proceed if you have written authorization to test this network.\n\nUnauthorized use may be illegal.\n\nDo you confirm you have authorization?')) {
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
    if (!confirm('AUTHORIZATION REQUIRED\n\nThis tool sends WiFi deauthentication frames that will disconnect clients from wireless networks.\n\nThis is a DISRUPTIVE action!\n\nOnly proceed if you have written authorization to test this network.\n\nDo you confirm you have authorization?')) {
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

// --- AP Scanner ---

async function startAPScanner() {
    const interface_name = document.getElementById('ap-scanner-interface').value;
    const timeout = parseInt(document.getElementById('ap-scanner-timeout').value);
    const channelEl = document.getElementById('ap-scanner-channel');
    const channel = channelEl.value ? parseInt(channelEl.value) : null;

    if (!interface_name) { alert('Please select an interface'); return; }

    const result = await apiCall('/api/ap-scanner/start', 'POST', {
        interface: interface_name, timeout: timeout, channel: channel
    });

    if (result.success) { addLog('ap_scanner', `Scan started on ${interface_name}`); }
    else { alert(`Failed to start AP Scanner: ${result.error}`); }
}

async function stopAPScanner() {
    const result = await apiCall('/api/ap-scanner/stop', 'POST');
    if (!result.success) { alert(`Failed to stop AP Scanner: ${result.error}`); }
}

// --- Handshake Capture ---

async function startHandshake() {
    const interface_name = document.getElementById('handshake-interface').value;
    const bssid = document.getElementById('handshake-bssid').value.trim();
    const client = document.getElementById('handshake-client').value.trim() || null;
    const timeout = parseInt(document.getElementById('handshake-timeout').value);
    const channelEl = document.getElementById('handshake-channel');
    const channel = channelEl.value ? parseInt(channelEl.value) : null;
    const no_deauth = document.getElementById('handshake-no-deauth').checked;

    if (!interface_name) { alert('Please select an interface'); return; }
    if (!bssid) { alert('Please enter target BSSID'); return; }

    const macRegex = /^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/;
    if (!macRegex.test(bssid)) { alert('Invalid BSSID format'); return; }
    if (client && !macRegex.test(client)) { alert('Invalid client MAC format'); return; }

    const result = await apiCall('/api/handshake/start', 'POST', {
        interface: interface_name, bssid: bssid, client: client,
        timeout: timeout, channel: channel, no_deauth: no_deauth
    });

    if (result.success) { addLog('handshake', `Capture started targeting ${bssid}`); }
    else { alert(`Failed to start handshake capture: ${result.error}`); }
}

async function stopHandshake() {
    const result = await apiCall('/api/handshake/stop', 'POST');
    if (!result.success) { alert(`Failed to stop handshake capture: ${result.error}`); }
}

// --- Captive Portal ---

async function startPortal() {
    const interface_name = document.getElementById('portal-interface').value;
    const ssid = document.getElementById('portal-ssid').value.trim() || 'Free-WiFi';
    const channel = parseInt(document.getElementById('portal-channel').value);
    const template = document.getElementById('portal-template').value;

    if (!interface_name) { alert('Please select an interface'); return; }

    if (!confirm('AUTHORIZATION REQUIRED\n\nThis tool creates a captive portal to capture credentials.\n\nOnly proceed with written authorization.\n\nDo you confirm?')) {
        return;
    }

    const result = await apiCall('/api/portal/start', 'POST', {
        interface: interface_name, ssid: ssid, channel: channel, template: template
    });

    if (result.success) { addLog('portal', `Captive portal started (SSID: ${ssid})`); }
    else { alert(`Failed to start captive portal: ${result.error}`); }
}

async function stopPortal() {
    const result = await apiCall('/api/portal/stop', 'POST');
    if (!result.success) { alert(`Failed to stop captive portal: ${result.error}`); }
}

// --- Karma Attack ---

async function startKarma() {
    const interface_name = document.getElementById('karma-interface').value;
    const channel = parseInt(document.getElementById('karma-channel').value);

    if (!interface_name) { alert('Please select an interface'); return; }

    if (!confirm('AUTHORIZATION REQUIRED\n\nThis tool responds to all probe requests with matching beacons.\n\nOnly proceed with written authorization.\n\nDo you confirm?')) {
        return;
    }

    const result = await apiCall('/api/karma/start', 'POST', {
        interface: interface_name, channel: channel
    });

    if (result.success) { addLog('karma', `Karma attack started on ${interface_name}`); }
    else { alert(`Failed to start karma attack: ${result.error}`); }
}

async function stopKarma() {
    const result = await apiCall('/api/karma/stop', 'POST');
    if (!result.success) { alert(`Failed to stop karma attack: ${result.error}`); }
}

// --- WIDS ---

async function startWIDS() {
    const interface_name = document.getElementById('wids-interface').value;
    const deauth_threshold = parseInt(document.getElementById('wids-deauth-threshold').value);

    if (!interface_name) { alert('Please select an interface'); return; }

    const result = await apiCall('/api/wids/start', 'POST', {
        interface: interface_name, deauth_threshold: deauth_threshold
    });

    if (result.success) { addLog('wids', `WIDS started on ${interface_name}`); }
    else { alert(`Failed to start WIDS: ${result.error}`); }
}

async function stopWIDS() {
    const result = await apiCall('/api/wids/stop', 'POST');
    if (!result.success) { alert(`Failed to stop WIDS: ${result.error}`); }
}

// --- Packet Replay ---

async function startPacketReplay() {
    const interface_name = document.getElementById('packet-replay-interface').value;
    const filter_type = document.getElementById('packet-replay-filter').value || null;
    const timeout = parseInt(document.getElementById('packet-replay-timeout').value);
    const replay_count = parseInt(document.getElementById('packet-replay-count').value);
    const delay = parseFloat(document.getElementById('packet-replay-delay').value);

    if (!interface_name) { alert('Please select an interface'); return; }

    const result = await apiCall('/api/packet-replay/start', 'POST', {
        interface: interface_name, filter_type: filter_type,
        timeout: timeout, replay_count: replay_count, delay: delay
    });

    if (result.success) { addLog('packet_replay', `Packet replay started on ${interface_name}`); }
    else { alert(`Failed to start packet replay: ${result.error}`); }
}

async function stopPacketReplay() {
    const result = await apiCall('/api/packet-replay/stop', 'POST');
    if (!result.success) { alert(`Failed to stop packet replay: ${result.error}`); }
}

// --- WPS Attack ---

async function startWPSAttack() {
    const interface_name = document.getElementById('wps-attack-interface').value;
    const bssid = document.getElementById('wps-attack-bssid').value.trim();
    const method = document.getElementById('wps-attack-method').value;
    const timeout = parseInt(document.getElementById('wps-attack-timeout').value);

    if (!interface_name) { alert('Please select an interface'); return; }
    if (!bssid) { alert('Please enter target BSSID'); return; }

    const macRegex = /^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/;
    if (!macRegex.test(bssid)) { alert('Invalid BSSID format'); return; }

    if (!confirm('AUTHORIZATION REQUIRED\n\nThis tool performs WPS PIN brute force attacks.\n\nOnly proceed with written authorization.\n\nDo you confirm?')) {
        return;
    }

    const result = await apiCall('/api/wps-attack/start', 'POST', {
        interface: interface_name, bssid: bssid, method: method, timeout: timeout
    });

    if (result.success) { addLog('wps_attack', `WPS attack started targeting ${bssid} (${method})`); }
    else { alert(`Failed to start WPS attack: ${result.error}`); }
}

async function stopWPSAttack() {
    const result = await apiCall('/api/wps-attack/stop', 'POST');
    if (!result.success) { alert(`Failed to stop WPS attack: ${result.error}`); }
}

// --- Network Mapper ---

async function startNetworkMapper() {
    const interface_name = document.getElementById('network-mapper-interface').value;
    const target_range = document.getElementById('network-mapper-range').value.trim();
    const port_scan = document.getElementById('network-mapper-port-scan').checked;

    if (!interface_name) { alert('Please select an interface'); return; }
    if (!target_range) { alert('Please enter target range'); return; }

    const result = await apiCall('/api/network-mapper/start', 'POST', {
        interface: interface_name, target_range: target_range, port_scan: port_scan
    });

    if (result.success) { addLog('network_mapper', `Network scan started on ${interface_name} (${target_range})`); }
    else { alert(`Failed to start network mapper: ${result.error}`); }
}

async function stopNetworkMapper() {
    const result = await apiCall('/api/network-mapper/stop', 'POST');
    if (!result.success) { alert(`Failed to stop network mapper: ${result.error}`); }
}

// --- BLE Scanner ---

async function startBLEScanner() {
    const scan_time = parseInt(document.getElementById('ble-scanner-time').value);
    const service_scan = document.getElementById('ble-scanner-services').checked;
    const filter_name = document.getElementById('ble-scanner-filter-name').value.trim() || null;

    const result = await apiCall('/api/ble-scanner/start', 'POST', {
        scan_time: scan_time, service_scan: service_scan, filter_name: filter_name
    });

    if (result.success) { addLog('ble_scanner', 'BLE scan started'); }
    else { alert(`Failed to start BLE scanner: ${result.error}`); }
}

async function stopBLEScanner() {
    const result = await apiCall('/api/ble-scanner/stop', 'POST');
    if (!result.success) { alert(`Failed to stop BLE scanner: ${result.error}`); }
}

// --- Pentest Workflow ---

async function startPentestWorkflow() {
    const interface_name = document.getElementById('pentest-workflow-interface').value;
    const bssid = document.getElementById('pentest-workflow-bssid').value.trim() || null;
    const timeout = parseInt(document.getElementById('pentest-workflow-timeout').value);
    const no_deauth = document.getElementById('pentest-workflow-no-deauth').checked;
    const skip_wps = document.getElementById('pentest-workflow-skip-wps').checked;

    if (!interface_name) { alert('Please select an interface'); return; }

    if (bssid) {
        const macRegex = /^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/;
        if (!macRegex.test(bssid)) { alert('Invalid BSSID format'); return; }
    }

    if (!confirm('AUTHORIZATION REQUIRED\n\nThis runs an automated pentest workflow including scanning, deauthentication, and handshake capture.\n\nOnly proceed with written authorization.\n\nDo you confirm?')) {
        return;
    }

    const result = await apiCall('/api/pentest-workflow/start', 'POST', {
        interface: interface_name, bssid: bssid, timeout: timeout,
        no_deauth: no_deauth, skip_wps: skip_wps
    });

    if (result.success) { addLog('pentest_workflow', `Pentest workflow started on ${interface_name}`); }
    else { alert(`Failed to start pentest workflow: ${result.error}`); }
}

async function stopPentestWorkflow() {
    const result = await apiCall('/api/pentest-workflow/stop', 'POST');
    if (!result.success) { alert(`Failed to stop pentest workflow: ${result.error}`); }
}

// --- EAP Attack ---

async function startEAPAttack() {
    const interface_name = document.getElementById('eap-attack-interface').value;
    const ssid = document.getElementById('eap-attack-ssid').value.trim();
    const channel = parseInt(document.getElementById('eap-attack-channel').value);
    const method = document.getElementById('eap-attack-method').value;
    const timeout = parseInt(document.getElementById('eap-attack-timeout').value);

    if (!interface_name) { alert('Please select an interface'); return; }
    if (!ssid) { alert('Please enter an SSID'); return; }

    if (!confirm('AUTHORIZATION REQUIRED\n\nThis tool creates a rogue WPA-Enterprise AP to capture EAP credentials.\n\nOnly proceed with written authorization.\n\nDo you confirm?')) {
        return;
    }

    const result = await apiCall('/api/eap-attack/start', 'POST', {
        interface: interface_name, ssid: ssid, channel: channel,
        method: method, timeout: timeout
    });

    if (result.success) { addLog('eap_attack', `EAP attack started (SSID: ${ssid}, method: ${method})`); }
    else { alert(`Failed to start EAP attack: ${result.error}`); }
}

async function stopEAPAttack() {
    const result = await apiCall('/api/eap-attack/stop', 'POST');
    if (!result.success) { alert(`Failed to stop EAP attack: ${result.error}`); }
}

// --- PMKID Capture ---

async function startPMKIDCapture() {
    const interface_name = document.getElementById('pmkid-capture-interface').value;
    const bssid = document.getElementById('pmkid-capture-bssid').value.trim();
    const timeout = parseInt(document.getElementById('pmkid-capture-timeout').value);
    const channelEl = document.getElementById('pmkid-capture-channel');
    const channel = channelEl.value ? parseInt(channelEl.value) : null;
    const client_mac = document.getElementById('pmkid-capture-client-mac').value.trim() || null;

    if (!interface_name) { alert('Please select an interface'); return; }
    if (!bssid) { alert('Please enter target BSSID'); return; }

    const macRegex = /^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/;
    if (!macRegex.test(bssid)) { alert('Invalid BSSID format'); return; }
    if (client_mac && !macRegex.test(client_mac)) { alert('Invalid client MAC format'); return; }

    const result = await apiCall('/api/pmkid-capture/start', 'POST', {
        interface: interface_name, bssid: bssid, timeout: timeout,
        channel: channel, client_mac: client_mac
    });

    if (result.success) { addLog('pmkid_capture', `PMKID capture started targeting ${bssid}`); }
    else { alert(`Failed to start PMKID capture: ${result.error}`); }
}

async function stopPMKIDCapture() {
    const result = await apiCall('/api/pmkid-capture/stop', 'POST');
    if (!result.success) { alert(`Failed to stop PMKID capture: ${result.error}`); }
}

// --- MitM Attack ---

async function startMitMAttack() {
    const interface_name = document.getElementById('mitm-attack-interface').value;
    const target = document.getElementById('mitm-attack-target').value.trim();
    const gateway = document.getElementById('mitm-attack-gateway').value.trim();
    const timeout = parseInt(document.getElementById('mitm-attack-timeout').value);
    const ports = document.getElementById('mitm-attack-ports').value.trim() || null;
    const no_forward = document.getElementById('mitm-attack-no-forward').checked;

    if (!interface_name) { alert('Please select an interface'); return; }
    if (!target) { alert('Please enter target IP'); return; }
    if (!gateway) { alert('Please enter gateway IP'); return; }

    const ipRegex = /^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
    if (!ipRegex.test(target)) { alert('Invalid target IP format'); return; }
    if (!ipRegex.test(gateway)) { alert('Invalid gateway IP format'); return; }

    if (!confirm('AUTHORIZATION REQUIRED\n\nThis tool performs ARP spoofing to intercept network traffic.\n\nOnly proceed with written authorization.\n\nDo you confirm?')) {
        return;
    }

    const result = await apiCall('/api/mitm-attack/start', 'POST', {
        interface: interface_name, target: target, gateway: gateway,
        timeout: timeout, ports: ports, no_forward: no_forward
    });

    if (result.success) { addLog('mitm_attack', `MitM attack started (${target} <-> ${gateway})`); }
    else { alert(`Failed to start MitM attack: ${result.error}`); }
}

async function stopMitMAttack() {
    const result = await apiCall('/api/mitm-attack/stop', 'POST');
    if (!result.success) { alert(`Failed to stop MitM attack: ${result.error}`); }
}

// --- BLE Attack ---

async function startBLEAttack() {
    const target = document.getElementById('ble-attack-target').value.trim() || null;
    const mode = document.getElementById('ble-attack-mode').value;
    const scan_time = parseInt(document.getElementById('ble-attack-scan-time').value);
    const uuid = document.getElementById('ble-attack-uuid').value.trim() || null;
    const write_data = document.getElementById('ble-attack-write-data').value.trim() || null;
    const replay_count = parseInt(document.getElementById('ble-attack-replay-count').value);
    const replay_interval = parseFloat(document.getElementById('ble-attack-replay-interval').value);
    const spoof_name = document.getElementById('ble-attack-spoof-name').value.trim() || null;
    const timeout = parseInt(document.getElementById('ble-attack-timeout').value);

    if (target) {
        const macRegex = /^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/;
        if (!macRegex.test(target)) { alert('Invalid target MAC format'); return; }
    }
    if ((mode === 'enumerate' || mode === 'replay' || mode === 'fuzz') && !target) {
        alert(`Target MAC is required for ${mode} mode`); return;
    }
    if ((mode === 'replay' || mode === 'fuzz') && !uuid) {
        alert(`UUID is required for ${mode} mode`); return;
    }

    if (!confirm('AUTHORIZATION REQUIRED\n\nThis tool performs BLE attacks on Bluetooth devices.\n\nOnly proceed with written authorization.\n\nDo you confirm?')) {
        return;
    }

    const result = await apiCall('/api/ble-attack/start', 'POST', {
        target: target, mode: mode, scan_time: scan_time, uuid: uuid,
        write_data: write_data, replay_count: replay_count,
        replay_interval: replay_interval, spoof_name: spoof_name, timeout: timeout
    });

    if (result.success) { addLog('ble_attack', `BLE attack started (mode: ${mode})`); }
    else { alert(`Failed to start BLE attack: ${result.error}`); }
}

async function stopBLEAttack() {
    const result = await apiCall('/api/ble-attack/stop', 'POST');
    if (!result.success) { alert(`Failed to stop BLE attack: ${result.error}`); }
}

// --- Dragonblood WPA3 ---

async function startDragonblood() {
    const interface_name = document.getElementById('dragonblood-interface').value;
    const bssid = document.getElementById('dragonblood-bssid').value.trim();

    if (!interface_name) { alert('Please select an interface'); return; }
    if (!bssid) { alert('Please enter target BSSID'); return; }

    const macRegex = /^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/;
    if (!macRegex.test(bssid)) { alert('Invalid BSSID format'); return; }

    if (!confirm('AUTHORIZATION REQUIRED\n\nThis tool tests WPA3 SAE/Dragonfly vulnerabilities.\n\nOnly proceed with written authorization.\n\nDo you confirm?')) {
        return;
    }

    const result = await apiCall('/api/dragonblood/start', 'POST', {
        interface: interface_name, bssid: bssid
    });

    if (result.success) { addLog('dragonblood', `Dragonblood started on ${interface_name} targeting ${bssid}`); }
    else { alert(`Failed to start Dragonblood: ${result.error}`); }
}

async function stopDragonblood() {
    const result = await apiCall('/api/dragonblood/stop', 'POST');
    if (!result.success) { alert(`Failed to stop Dragonblood: ${result.error}`); }
}

// --- KRACK Detection ---

async function startKRACK() {
    const interface_name = document.getElementById('krack-interface').value;

    if (!interface_name) { alert('Please select an interface'); return; }

    const result = await apiCall('/api/krack/start', 'POST', {
        interface: interface_name
    });

    if (result.success) { addLog('krack', `KRACK detection started on ${interface_name}`); }
    else { alert(`Failed to start KRACK detection: ${result.error}`); }
}

async function stopKRACK() {
    const result = await apiCall('/api/krack/stop', 'POST');
    if (!result.success) { alert(`Failed to stop KRACK detection: ${result.error}`); }
}

// --- FragAttacks ---

async function startFragAttacks() {
    const interface_name = document.getElementById('fragattacks-interface').value;
    const bssid = document.getElementById('fragattacks-bssid').value.trim();

    if (!interface_name) { alert('Please select an interface'); return; }
    if (!bssid) { alert('Please enter target BSSID'); return; }

    const macRegex = /^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/;
    if (!macRegex.test(bssid)) { alert('Invalid BSSID format'); return; }

    const result = await apiCall('/api/fragattacks/start', 'POST', {
        interface: interface_name, bssid: bssid
    });

    if (result.success) { addLog('fragattacks', `FragAttacks started on ${interface_name} targeting ${bssid}`); }
    else { alert(`Failed to start FragAttacks: ${result.error}`); }
}

async function stopFragAttacks() {
    const result = await apiCall('/api/fragattacks/stop', 'POST');
    if (!result.success) { alert(`Failed to stop FragAttacks: ${result.error}`); }
}

// --- Wardriving ---

async function startWardriving() {
    const interface_name = document.getElementById('wardriving-interface').value;

    if (!interface_name) { alert('Please select an interface'); return; }

    const result = await apiCall('/api/wardriving/start', 'POST', {
        interface: interface_name
    });

    if (result.success) { addLog('wardriving', `Wardriving started on ${interface_name}`); }
    else { alert(`Failed to start wardriving: ${result.error}`); }
}

async function stopWardriving() {
    const result = await apiCall('/api/wardriving/stop', 'POST');
    if (!result.success) { alert(`Failed to stop wardriving: ${result.error}`); }
}

// --- Cloud C2 ---

async function startCloudC2() {
    if (!confirm('AUTHORIZATION REQUIRED\n\nThis starts a Cloud C2 server for remote agent management.\n\nOnly proceed with written authorization.\n\nDo you confirm?')) {
        return;
    }

    const result = await apiCall('/api/cloud_c2/start', 'POST', {});

    if (result.success) { addLog('cloud_c2', 'Cloud C2 server started on port 8443'); }
    else { alert(`Failed to start Cloud C2: ${result.error}`); }
}

async function stopCloudC2() {
    const result = await apiCall('/api/cloud_c2/stop', 'POST');
    if (!result.success) { alert(`Failed to stop Cloud C2: ${result.error}`); }
}

// --- WEP Attack ---

async function startWEPAttack() {
    const interface_name = document.getElementById('wep-attack-interface').value;
    const bssid = document.getElementById('wep-attack-bssid').value.trim();

    if (!interface_name) { alert('Please select an interface'); return; }
    if (!bssid) { alert('Please enter target BSSID'); return; }

    const macRegex = /^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/;
    if (!macRegex.test(bssid)) { alert('Invalid BSSID format'); return; }

    if (!confirm('AUTHORIZATION REQUIRED\n\nThis tool performs WEP key cracking attacks.\n\nOnly proceed with written authorization.\n\nDo you confirm?')) {
        return;
    }

    const result = await apiCall('/api/wep_attack/start', 'POST', {
        interface: interface_name, bssid: bssid
    });

    if (result.success) { addLog('wep_attack', `WEP attack started on ${interface_name} targeting ${bssid}`); }
    else { alert(`Failed to start WEP attack: ${result.error}`); }
}

async function stopWEPAttack() {
    const result = await apiCall('/api/wep_attack/stop', 'POST');
    if (!result.success) { alert(`Failed to stop WEP attack: ${result.error}`); }
}

// --- FT Attack (802.11r) ---

async function startFTAttack() {
    const interface_name = document.getElementById('ft-attack-interface').value;
    const bssid = document.getElementById('ft-attack-bssid').value.trim();
    const client = document.getElementById('ft-attack-client').value.trim() || null;
    const mode = document.getElementById('ft-attack-mode').value;
    const timeout = parseInt(document.getElementById('ft-attack-timeout').value);

    if (!interface_name) { alert('Please select an interface'); return; }
    if (!bssid) { alert('Please enter target BSSID'); return; }

    const macRegex = /^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/;
    if (!macRegex.test(bssid)) { alert('Invalid BSSID format'); return; }
    if (client && !macRegex.test(client)) { alert('Invalid client MAC format'); return; }

    if (!confirm('AUTHORIZATION REQUIRED\n\nThis tool tests 802.11r FT key reinstallation vulnerabilities.\n\nOnly proceed with written authorization.\n\nDo you confirm?')) {
        return;
    }

    const result = await apiCall('/api/ft-attack/start', 'POST', {
        interface: interface_name, bssid: bssid, client: client,
        mode: mode, timeout: timeout
    });

    if (result.success) { addLog('ft_attack', `FT attack started on ${interface_name} targeting ${bssid} (${mode})`); }
    else { alert(`Failed to start FT attack: ${result.error}`); }
}

async function stopFTAttack() {
    const result = await apiCall('/api/ft-attack/stop', 'POST');
    if (!result.success) { alert(`Failed to stop FT attack: ${result.error}`); }
}

// --- Password Crack ---

async function startPasswordCrack() {
    const capture_file = document.getElementById('password-crack-file').value.trim();
    const wordlist = document.getElementById('password-crack-wordlist').value.trim();
    const tool = document.getElementById('password-crack-tool').value;
    const timeout = parseInt(document.getElementById('password-crack-timeout').value);

    if (!capture_file) { alert('Please enter a capture file path'); return; }

    const result = await apiCall('/api/password-crack/start', 'POST', {
        capture_file: capture_file, wordlist: wordlist,
        tool: tool, timeout: timeout
    });

    if (result.success) { addLog('password_crack', `Password cracking started on ${capture_file}`); }
    else { alert(`Failed to start password cracking: ${result.error}`); }
}

async function stopPasswordCrack() {
    const result = await apiCall('/api/password-crack/stop', 'POST');
    if (!result.success) { alert(`Failed to stop password cracking: ${result.error}`); }
}

// --- Channel MitM ---

async function startChannelMitM() {
    const monitor_iface = document.getElementById('channel-mitm-monitor-interface').value;
    const rogue_iface = document.getElementById('channel-mitm-inject-interface').value;
    const bssid = document.getElementById('channel-mitm-bssid').value.trim();
    const channel = parseInt(document.getElementById('channel-mitm-channel').value);
    const rogue_channel = document.getElementById('channel-mitm-rogue-channel').value.trim() || null;
    const ssid = document.getElementById('channel-mitm-ssid').value.trim() || null;
    const timeout = parseInt(document.getElementById('channel-mitm-timeout').value);

    if (!monitor_iface) { alert('Please select a monitor interface'); return; }
    if (!rogue_iface) { alert('Please select a rogue/inject interface'); return; }
    if (!bssid) { alert('Please enter target BSSID'); return; }

    const macRegex = /^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/;
    if (!macRegex.test(bssid)) { alert('Invalid BSSID format'); return; }

    if (!confirm('AUTHORIZATION REQUIRED\n\nThis tool performs channel-based MitM attacks using two interfaces.\n\nOnly proceed with written authorization.\n\nDo you confirm?')) {
        return;
    }

    const result = await apiCall('/api/channel-mitm/start', 'POST', {
        monitor_interface: monitor_iface, rogue_interface: rogue_iface,
        bssid: bssid, channel: channel,
        rogue_channel: rogue_channel ? parseInt(rogue_channel) : null,
        ssid: ssid, timeout: timeout
    });

    if (result.success) { addLog('channel_mitm', `Channel MitM started: ${rogue_iface}/${monitor_iface} targeting ${bssid}`); }
    else { alert(`Failed to start Channel MitM: ${result.error}`); }
}

async function stopChannelMitM() {
    const result = await apiCall('/api/channel-mitm/stop', 'POST');
    if (!result.success) { alert(`Failed to stop Channel MitM: ${result.error}`); }
}

// --- WiFi Direct ---

async function startWiFiDirect() {
    const interface_name = document.getElementById('wifi-direct-interface').value;
    const mode = document.getElementById('wifi-direct-mode').value;
    const target = document.getElementById('wifi-direct-target').value.trim() || null;
    const timeout = parseInt(document.getElementById('wifi-direct-timeout').value);

    if (!interface_name) { alert('Please select an interface'); return; }

    if (target) {
        const macRegex = /^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/;
        if (!macRegex.test(target)) { alert('Invalid target MAC format'); return; }
    }

    const result = await apiCall('/api/wifi-direct/start', 'POST', {
        interface: interface_name, mode: mode, target: target, timeout: timeout
    });

    if (result.success) { addLog('wifi_direct', `WiFi Direct testing started on ${interface_name} (${mode})`); }
    else { alert(`Failed to start WiFi Direct: ${result.error}`); }
}

async function stopWiFiDirect() {
    const result = await apiCall('/api/wifi-direct/stop', 'POST');
    if (!result.success) { alert(`Failed to stop WiFi Direct: ${result.error}`); }
}

// --- Jamming Detection ---

async function startJammingDetect() {
    const interface_name = document.getElementById('jamming-detect-interface').value;
    const channels = document.getElementById('jamming-detect-channels').value.trim() || null;
    const timeout = parseInt(document.getElementById('jamming-detect-timeout').value);

    if (!interface_name) { alert('Please select an interface'); return; }

    const result = await apiCall('/api/jamming-detect/start', 'POST', {
        interface: interface_name, channels: channels, timeout: timeout
    });

    if (result.success) { addLog('jamming_detect', `Jamming detection started on ${interface_name}`); }
    else { alert(`Failed to start jamming detection: ${result.error}`); }
}

async function stopJammingDetect() {
    const result = await apiCall('/api/jamming-detect/stop', 'POST');
    if (!result.success) { alert(`Failed to stop jamming detection: ${result.error}`); }
}

// --- DHCP/DNS Attack ---

async function startDHCPDNSAttack() {
    const interface_name = document.getElementById('dhcp-dns-attack-interface').value;
    const mode = document.getElementById('dhcp-dns-attack-mode').value;
    const target_ip = document.getElementById('dhcp-dns-attack-target-ip').value.trim() || null;
    const spoof_domain = document.getElementById('dhcp-dns-attack-spoof-domain').value.trim() || null;
    const spoof_ip = document.getElementById('dhcp-dns-attack-spoof-ip').value.trim() || null;
    const timeout = parseInt(document.getElementById('dhcp-dns-attack-timeout').value);

    if (!interface_name) { alert('Please select an interface'); return; }

    if (target_ip) {
        const ipRegex = /^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
        if (!ipRegex.test(target_ip)) { alert('Invalid target IP format'); return; }
    }
    if (spoof_ip) {
        const ipRegex = /^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
        if (!ipRegex.test(spoof_ip)) { alert('Invalid spoof IP format'); return; }
    }

    if (!confirm('AUTHORIZATION REQUIRED\n\nThis tool performs DHCP/DNS attacks on the network.\n\nOnly proceed with written authorization.\n\nDo you confirm?')) {
        return;
    }

    const result = await apiCall('/api/dhcp-dns-attack/start', 'POST', {
        interface: interface_name, mode: mode, target_ip: target_ip,
        spoof_domain: spoof_domain, spoof_ip: spoof_ip, timeout: timeout
    });

    if (result.success) { addLog('dhcp_dns_attack', `DHCP/DNS attack started on ${interface_name} (${mode})`); }
    else { alert(`Failed to start DHCP/DNS attack: ${result.error}`); }
}

async function stopDHCPDNSAttack() {
    const result = await apiCall('/api/dhcp-dns-attack/stop', 'POST');
    if (!result.success) { alert(`Failed to stop DHCP/DNS attack: ${result.error}`); }
}

// --- Portal Bypass ---

async function startPortalBypass() {
    const interface_name = document.getElementById('portal-bypass-interface').value;
    const mode = document.getElementById('portal-bypass-mode').value;
    const dns_domain = document.getElementById('portal-bypass-dns-domain').value.trim() || null;
    const target_ip = document.getElementById('portal-bypass-target-ip').value.trim() || null;
    const timeout = parseInt(document.getElementById('portal-bypass-timeout').value);

    if (!interface_name) { alert('Please select an interface'); return; }

    const result = await apiCall('/api/portal-bypass/start', 'POST', {
        interface: interface_name, mode: mode, dns_domain: dns_domain,
        target_ip: target_ip, timeout: timeout
    });

    if (result.success) { addLog('portal_bypass', `Portal bypass started on ${interface_name} (${mode})`); }
    else { alert(`Failed to start portal bypass: ${result.error}`); }
}

async function stopPortalBypass() {
    const result = await apiCall('/api/portal-bypass/stop', 'POST');
    if (!result.success) { alert(`Failed to stop portal bypass: ${result.error}`); }
}

// --- Multi-Adapter ---

async function discoverMultiAdapter() {
    const result = await apiCall('/api/status');
    if (result && result.interfaces) {
        const count = result.interfaces.length;
        addLog('multi_adapter', `Discovered ${count} interface(s): ${result.interfaces.map(i => i.name).join(', ')}`);
        alert(`Found ${count} interface(s):\n${result.interfaces.map(i => `${i.name} (${i.mode})`).join('\n')}`);
    } else {
        alert('Failed to discover adapters');
    }
}

// --- Report Generator ---

async function generateReport() {
    const format = document.getElementById('report-format').value;
    addLog('reporting', `Report generation requested (format: ${format})`);
    alert('Report generation is available via CLI:\n\nhoover-report --format ' + format + ' --output report.' + format);
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
        <span class="log-time">${escapeHtml(timestamp)}</span>
        <span class="log-tool ${toolClass}">[${escapeHtml(toolLabel)}]</span>
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
