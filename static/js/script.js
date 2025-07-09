let currentScanId = null;
let statusCheckInterval = null;
let startTime = null;

// Initialize event listeners
document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('startScan').addEventListener('click', startScan);
    document.getElementById('stopScan').addEventListener('click', stopScan);
    document.getElementById('downloadReport').addEventListener('click', downloadReport);
    document.getElementById('newScan').addEventListener('click', resetScan);
});

// Start a new scan
async function startScan() {
    const target = document.getElementById('target').value;
    if (!target) {
        showNotification('Please enter a target URL or IP address', 'error');
        return;
    }

    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;

    // Update UI for scan start
    document.getElementById('startScan').style.display = 'none';
    document.getElementById('stopScan').style.display = 'inline-block';
    document.querySelector('.results-container').style.display = 'block';
    startTime = new Date();
    updateDuration();

    try {
        const response = await fetch('/start_scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ target, username, password }),
        });

        const data = await response.json();
        if (data.scan_id) {
            currentScanId = data.scan_id;
            document.getElementById('targetDetail').textContent = target;
            document.getElementById('startTime').textContent = new Date().toLocaleString();
            startStatusCheck();
            showNotification('Scan started successfully', 'success');
        } else {
            throw new Error(data.error || 'Failed to start scan');
        }
    } catch (error) {
        console.error('Error starting scan:', error);
        showNotification(error.message, 'error');
        resetScan();
    }
}

// Stop the current scan
async function stopScan() {
    if (!currentScanId) return;

    try {
        const response = await fetch(`/stop_scan/${currentScanId}`);
        const data = await response.json();
        
        if (data.status === 'success') {
            document.getElementById('stopScan').style.display = 'none';
            updateScanStatus('Stopped');
            showNotification('Scan stopped successfully', 'success');
            if (statusCheckInterval) {
                clearInterval(statusCheckInterval);
                statusCheckInterval = null;
            }
        } else {
            throw new Error(data.error || 'Failed to stop scan');
        }
    } catch (error) {
        console.error('Error stopping scan:', error);
        showNotification(error.message, 'error');
    }
}

// Check scan status periodically
function startStatusCheck() {
    if (statusCheckInterval) {
        clearInterval(statusCheckInterval);
    }

    statusCheckInterval = setInterval(async () => {
        try {
            const response = await fetch(`/scan_status/${currentScanId}`);
            const data = await response.json();
            
            if (data.error) {
                clearInterval(statusCheckInterval);
                updateScanStatus('Error');
                showNotification(data.error, 'error');
                return;
            }
            
            updateScanResults(data);
        } catch (error) {
            console.error('Error checking scan status:', error);
            showNotification('Error updating scan status', 'error');
        }
    }, 2000);
}

// Update scan results in the UI
function updateScanResults(data) {
    try {
        // Update status
        updateScanStatus(data.details.scan_status);
        
        // Update progress
        const progress = calculateProgress(data.details);
        document.querySelector('.progress').style.width = `${progress}%`;
        
        // Update statistics
        document.getElementById('totalRequests').textContent = data.details.total_requests || 0;
        document.getElementById('successRequests').textContent = data.details.successful_requests || 0;
        document.getElementById('failedRequests').textContent = data.details.failed_requests || 0;
        
        // Update vulnerability counts
        updateVulnerabilityCounts(data.summary);
        
        // Update vulnerability list
        updateVulnerabilityList(data.vulnerabilities);
        
        // Update duration
        updateDuration();
    } catch (error) {
        console.error('Error updating scan results:', error);
        showNotification('Error updating scan results', 'error');
    }
}

// Calculate scan progress
function calculateProgress(details) {
    const total = details.total_requests || 0;
    const success = details.successful_requests || 0;
    const failed = details.failed_requests || 0;
    
    if (total === 0) return 0;
    return Math.min(((success + failed) / total) * 100, 100);
}

// Update vulnerability counts
function updateVulnerabilityCounts(summary) {
    document.querySelector('.vuln-stat.critical .count').textContent = summary.critical;
    document.querySelector('.vuln-stat.high .count').textContent = summary.high;
    document.querySelector('.vuln-stat.medium .count').textContent = summary.medium;
    document.querySelector('.vuln-stat.low .count').textContent = summary.low;
}

// Update vulnerability list
function updateVulnerabilityList(vulnerabilities) {
    const list = document.querySelector('.vulnerability-list');
    list.innerHTML = vulnerabilities.map(vuln => `
        <div class="vulnerability-item ${vuln.severity.toLowerCase()}">
            <div class="vuln-header">
                <span class="vuln-name">${vuln.name}</span>
                <span class="vuln-severity">${vuln.severity}</span>
            </div>
            <div class="vuln-description">${vuln.description}</div>
        </div>
    `).join('');
}

// Update scan status
function updateScanStatus(status) {
    const statusText = document.querySelector('.status-text');
    const statusDot = document.querySelector('.status-dot');
    const downloadButton = document.getElementById('downloadReport');
    const stopButton = document.getElementById('stopScan');
    document.getElementById('scanStatus').textContent = status;
    
    statusText.textContent = status;
    statusDot.className = 'status-dot';
    
    // Always hide download button first
    downloadButton.style.display = 'none';
    
    switch(status.toLowerCase()) {
        case 'running':
            statusDot.classList.add('running');
            stopButton.style.display = 'inline-block';
            break;
        case 'completed':
            statusDot.classList.add('completed');
            stopButton.style.display = 'none';
            // Only show download button if we have a valid scan ID
            if (currentScanId) {
                downloadButton.style.display = 'inline-block';
            }
            break;
        case 'error':
            statusDot.classList.add('error');
            stopButton.style.display = 'none';
            break;
        case 'stopped':
            statusDot.classList.add('stopped');
            stopButton.style.display = 'none';
            break;
        default:
            statusDot.classList.add('initializing');
            stopButton.style.display = 'none';
    }
}

// Update scan duration
function updateDuration() {
    if (!startTime) return;
    
    const now = new Date();
    const diff = now - startTime;
    const hours = Math.floor(diff / 3600000);
    const minutes = Math.floor((diff % 3600000) / 60000);
    const seconds = Math.floor((diff % 60000) / 1000);
    
    document.getElementById('duration').textContent = 
        `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
}

// Download scan report
async function downloadReport() {
    if (!currentScanId) {
        showNotification('No scan report available', 'error');
        return;
    }

    try {
        const response = await fetch(`/download_report/${currentScanId}`);
        if (response.ok) {
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `vulnerability_report_${currentScanId}.json`;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);
            showNotification('Report downloaded successfully', 'success');
        } else {
            const errorData = await response.json();
            throw new Error(errorData.error || 'Failed to download report');
        }
    } catch (error) {
        console.error('Error downloading report:', error);
        showNotification(error.message, 'error');
    }
}

// Reset scan state
function resetScan() {
    currentScanId = null;
    if (statusCheckInterval) {
        clearInterval(statusCheckInterval);
        statusCheckInterval = null;
    }
    startTime = null;
    
    // Reset form
    document.getElementById('target').value = '';
    document.getElementById('username').value = '';
    document.getElementById('password').value = '';
    
    // Reset UI
    document.getElementById('startScan').style.display = 'inline-block';
    document.getElementById('stopScan').style.display = 'none';
    document.getElementById('downloadReport').style.display = 'none';
    document.querySelector('.results-container').style.display = 'none';
    document.querySelector('.progress').style.width = '0%';
    
    // Reset counters
    document.getElementById('totalRequests').textContent = '0';
    document.getElementById('successRequests').textContent = '0';
    document.getElementById('failedRequests').textContent = '0';
    document.getElementById('duration').textContent = '00:00:00';
    
    // Reset vulnerability counts
    document.querySelector('.vuln-stat.critical .count').textContent = '0';
    document.querySelector('.vuln-stat.high .count').textContent = '0';
    document.querySelector('.vuln-stat.medium .count').textContent = '0';
    document.querySelector('.vuln-stat.low .count').textContent = '0';
    
    // Clear vulnerability list
    document.querySelector('.vulnerability-list').innerHTML = '';
}

// Show notification
function showNotification(message, type = 'info') {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.textContent = message;
    
    // Add to document
    document.body.appendChild(notification);
    
    // Animate in
    setTimeout(() => notification.classList.add('show'), 10);
    
    // Remove after delay
    setTimeout(() => {
        notification.classList.remove('show');
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}

// Add notification styles
const style = document.createElement('style');
style.textContent = `
    .notification {
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 15px 25px;
        border-radius: 5px;
        color: white;
        font-family: var(--font-secondary);
        transform: translateX(120%);
        transition: transform 0.3s ease;
        z-index: 1000;
    }
    
    .notification.show {
        transform: translateX(0);
    }
    
    .notification.success {
        background-color: var(--primary-color);
    }
    
    .notification.error {
        background-color: var(--danger);
    }
    
    .notification.info {
        background-color: var(--secondary-color);
    }
    
    .vulnerability-item {
        background-color: var(--background-dark);
        border-radius: 5px;
        padding: 1rem;
        margin-bottom: 1rem;
    }
    
    .vulnerability-item:last-child {
        margin-bottom: 0;
    }
    
    .vuln-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 0.5rem;
    }
    
    .vuln-name {
        font-family: var(--font-primary);
        font-weight: 500;
        color: var(--text-primary);
    }
    
    .vuln-severity {
        font-size: 0.8rem;
        padding: 0.2rem 0.5rem;
        border-radius: 3px;
        text-transform: uppercase;
    }
    
    .vulnerability-item.critical .vuln-severity {
        background-color: var(--critical);
        color: white;
    }
    
    .vulnerability-item.high .vuln-severity {
        background-color: var(--high);
        color: white;
    }
    
    .vulnerability-item.medium .vuln-severity {
        background-color: var(--medium);
        color: black;
    }
    
    .vulnerability-item.low .vuln-severity {
        background-color: var(--low);
        color: white;
    }
    
    .vuln-description {
        color: var(--text-secondary);
        font-size: 0.9rem;
    }
    
    .status-dot {
        transition: background-color 0.3s ease;
    }
    
    .status-dot.running {
        background-color: var(--primary-color);
        animation: blink 1s infinite;
    }
    
    .status-dot.completed {
        background-color: var(--low);
        animation: none;
    }
    
    .status-dot.error {
        background-color: var(--danger);
        animation: none;
    }
    
    .status-dot.stopped {
        background-color: var(--high);
        animation: none;
    }
`;

document.head.appendChild(style);