 document.addEventListener('DOMContentLoaded', function() {
    // State management
    let currentScanId = null;
    let selectedScanner = null;
    let statusCheckInterval = null;
    
    // Elements
    const emailSection = document.querySelector('.email-section');
    const scannerSection = document.querySelector('.scanner-section');
    const targetSection = document.querySelector('.target-section');
    const statusSection = document.querySelector('.status-section');
    const progressSection = document.querySelector('.progress-section');
    const resultsSection = document.querySelector('.results-section');
    
    const verifyBtn = document.getElementById('verifyEmail');
    const gmailInput = document.getElementById('gmail');
    const emailStatus = document.getElementById('emailStatus');
    const targetInput = document.getElementById('target');
    const startScanBtn = document.getElementById('startScan');
    const downloadBtn = document.getElementById('downloadReport');
    const newScanBtn = document.getElementById('newScan');
    
    // Email verification
    verifyBtn.addEventListener('click', verifyEmail);
    
    async function verifyEmail() {
        const email = gmailInput.value;
        
        if (!email) {
            showStatus(emailStatus, 'Please enter your Gmail ID', 'error');
            return;
        }
        
        verifyBtn.disabled = true;
        verifyBtn.textContent = 'Verifying...';
        
        try {
            const response = await fetch('/verify_email', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ email: email })
            });
            
            const data = await response.json();
            
            if (data.valid) {
                showStatus(emailStatus, '✓ Email verified successfully', 'success');
                emailSection.style.display = 'none';
                scannerSection.style.display = 'block';
                checkScannerStatus();
            } else {
                showStatus(emailStatus, data.message || 'Invalid Gmail ID', 'error');
            }
        } catch (error) {
            showStatus(emailStatus, 'Verification failed. Please try again.', 'error');
        } finally {
            verifyBtn.disabled = false;
            verifyBtn.textContent = 'Verify & Continue';
        }
    }
    
    // Scanner selection
    document.querySelectorAll('.scanner-card').forEach(card => {
        card.addEventListener('click', function() {
            const scannerType = this.dataset.type;
            
            document.querySelectorAll('.scanner-card').forEach(c => c.classList.remove('selected'));
            this.classList.add('selected');
            
            selectedScanner = scannerType;
            
            if (scannerType === '6') {
                // EXIT selected
                if (confirm('Are you sure you want to exit?')) {
                    window.close();
                }
            } else {
                targetSection.style.display = 'block';
            }
        });
    });
    
    // Check scanner installation status
    async function checkScannerStatus() {
        statusSection.style.display = 'block';
        
        const scanners = [
            { type: 'nmap', name: 'Nmap' },
            { type: 'nikto', name: 'Nikto' },
            { type: 'whatweb', name: 'WhatWeb' },
            { type: 'curl', name: 'Curl' }
        ];
        
        const statusGrid = document.getElementById('scannerStatus');
        statusGrid.innerHTML = '';
        
        for (const scanner of scanners) {
            try {
                const response = await fetch('/check_scanner', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ scanner_type: scanner.type })
                });
                
                const data = await response.json();
                
                const statusItem = document.createElement('div');
                statusItem.className = `status-item ${data.installed ? 'installed' : 'missing'}`;
                statusItem.innerHTML = `
                    <h4>${scanner.name}</h4>
                    <p>${data.installed ? '✓ Installed' : '⚠ Will install temporarily'}</p>
                `;
                statusGrid.appendChild(statusItem);
            } catch (error) {
                console.error('Error checking scanner status:', error);
            }
        }
    }
    
    // Start scan
    startScanBtn.addEventListener('click', startScan);
    
    async function startScan() {
        const target = targetInput.value.trim();
        
        if (!target) {
            alert('Please enter a target URL or IP address');
            return;
        }
        
        if (!selectedScanner) {
            alert('Please select a scan type');
            return;
        }
        
        startScanBtn.disabled = true;
        startScanBtn.textContent = 'Starting Scan...';
        
        progressSection.style.display = 'block';
        updateProgress(10, 'Initializing scanners...');
        
        try {
            const response = await fetch('/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    scan_type: parseInt(selectedScanner),
                    target: target
                })
            });
            
            const data = await response.json();
            
            if (data.scan_id) {
                currentScanId = data.scan_id;
                updateProgress(20, 'Scan started...');
                startStatusPolling();
            } else {
                throw new Error(data.error || 'Failed to start scan');
            }
        } catch (error) {
            alert('Failed to start scan: ' + error.message);
            startScanBtn.disabled = false;
            startScanBtn.textContent = 'Start Security Scan';
            progressSection.style.display = 'none';
        }
    }
    
    // Poll for scan status
    function startStatusPolling() {
        let progress = 20;
        
        statusCheckInterval = setInterval(async () => {
            try {
                const response = await fetch(`/scan_status/${currentScanId}`);
                const data = await response.json();
                
                if (data.status === 'completed') {
                    clearInterval(statusCheckInterval);
                    updateProgress(100, 'Scan completed!');
                    displayResults(data);
                    startScanBtn.disabled = false;
                    startScanBtn.textContent = 'Start Security Scan';
                } else if (data.status === 'failed') {
                    clearInterval(statusCheckInterval);
                    updateProgress(0, 'Scan failed: ' + data.error);
                    startScanBtn.disabled = false;
                    startScanBtn.textContent = 'Start Security Scan';
                } else {
                    // Update progress based on scanner
                    if (data.results) {
                        const scannerCount = Object.keys(data.results).length;
                        progress = 20 + (scannerCount * 20);
                        if (progress > 90) progress = 90;
                    }
                    updateProgress(progress, 'Scanning in progress...');
                }
            } catch (error) {
                console.error('Status check error:', error);
            }
        }, 2000);
    }
    
    function updateProgress(percent, message) {
        document.getElementById('scanProgress').style.width = percent + '%';
        document.getElementById('scanStatus').textContent = message;
    }
    
    function displayResults(data) {
        resultsSection.style.display = 'block';
        
        const resultsContainer = document.getElementById('results');
        let html = '';
        
        // Vulnerability summary
        if (data.vulnerabilities && data.vulnerabilities.length > 0) {
            html += '<h3>Vulnerabilities Found</h3>';
            data.vulnerabilities.forEach((vuln, index) => {
                html += `
                    <div class="result-item">
                        <h4>${index + 1}. ${vuln.title}</h4>
                        <p class="severity-${vuln.severity.toLowerCase()}">Severity: ${vuln.severity}</p>
                        <p>${vuln.description}</p>
                        <p><strong>Impact:</strong> ${vuln.impact}</p>
                        <p><strong>Recommendation:</strong> ${vuln.recommendation}</p>
                    </div>
                `;
            });
        } else {
            html += '<p class="severity-low">No critical vulnerabilities found</p>';
        }
        
        // Scanner outputs (collapsible)
        html += '<h3>Scanner Outputs</h3>';
        for (const [scanner, result] of Object.entries(data.results)) {
            if (result.success) {
                html += `
                    <div class="result-item">
                        <h4>${scanner.toUpperCase()} Results</h4>
                        <pre style="background: #f0f0f0; padding: 10px; border-radius: 5px; overflow-x: auto;">${escapeHtml(result.output || result.headers || 'No output')}</pre>
                    </div>
                `;
            }
        }
        
        resultsContainer.innerHTML = html;
        
        // Setup download button
        downloadBtn.onclick = () => downloadReport(data.scan_id);
    }
    
    function downloadReport(scanId) {
        window.location.href = `/download_report/${scanId}`;
    }
    
    newScanBtn.addEventListener('click', () => {
        // Reset UI
        selectedScanner = null;
        targetInput.value = '';
        progressSection.style.display = 'none';
        resultsSection.style.display = 'none';
        scannerSection.style.display = 'block';
        targetSection.style.display = 'block';
        
        document.querySelectorAll('.scanner-card').forEach(c => c.classList.remove('selected'));
    });
    
    // Helper functions
    function showStatus(element, message, type) {
        element.textContent = message;
        element.className = 'status-message ' + type;
    }
    
    function escapeHtml(unsafe) {
        return unsafe
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }
    
    // Click on example targets
    document.querySelectorAll('.example').forEach(example => {
        example.addEventListener('click', function() {
            targetInput.value = this.textContent;
        });
    });
});
