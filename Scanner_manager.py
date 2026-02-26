import subprocess
import sys
import os
import platform
import shutil
from pathlib import Path

class ScannerManager:
    def __init__(self):
        self.temp_dir = Path(__file__).parent.parent / 'temp_installs'
        self.temp_dir.mkdir(exist_ok=True)
        self.system = platform.system().lower()
        
    def check_scanner_installed(self, scanner_type):
        """Check if a scanner is installed on the system"""
        scanner_commands = {
            'nmap': 'nmap',
            'nikto': 'nikto',
            'whatweb': 'whatweb',
            'curl': 'curl'
        }
        
        scanner_name = scanner_commands.get(str(scanner_type))
        if not scanner_name:
            return False
            
        return shutil.which(scanner_name) is not None
    
    def ensure_scanners(self, scan_type):
        """Ensure required scanners are available, install if not"""
        if scan_type == 'all' or scan_type == 1:
            scanners = ['nmap', 'nikto', 'whatweb', 'curl']
        else:
            scanner_map = {
                2: ['nmap'],
                3: ['nikto'],
                4: ['curl'],
                5: ['whatweb']
            }
            scanners = scanner_map.get(scan_type, [])
        
        for scanner in scanners:
            if not self.check_scanner_installed(scanner):
                self.install_scanner(scanner)
    
    def install_scanner(self, scanner):
        """Temporarily install a scanner"""
        print(f"Installing {scanner} temporarily...")
        
        try:
            if self.system == 'linux':
                self._install_linux(scanner)
            elif self.system == 'darwin':  # macOS
                self._install_macos(scanner)
            elif self.system == 'windows':
                self._install_windows(scanner)
        except Exception as e:
            print(f"Failed to install {scanner}: {e}")
    
    def _install_linux(self, scanner):
        """Install on Linux"""
        install_commands = {
            'nmap': ['sudo', 'apt-get', 'install', '-y', 'nmap'],
            'nikto': ['sudo', 'apt-get', 'install', '-y', 'nikto'],
            'whatweb': ['sudo', 'apt-get', 'install', '-y', 'whatweb'],
            'curl': ['sudo', 'apt-get', 'install', '-y', 'curl']
        }
        
        if scanner in install_commands:
            subprocess.run(install_commands[scanner], check=True)
    
    def _install_macos(self, scanner):
        """Install on macOS using Homebrew"""
        install_commands = {
            'nmap': ['brew', 'install', 'nmap'],
            'nikto': ['brew', 'install', 'nikto'],
            'whatweb': ['brew', 'install', 'whatweb'],
            'curl': ['brew', 'install', 'curl']
        }
        
        if scanner in install_commands:
            subprocess.run(install_commands[scanner], check=True)
    
    def _install_windows(self, scanner):
        """Install on Windows (simplified - would need actual Windows installers)"""
        # For Windows, you might need to download and run installers
        # This is a simplified version
        print(f"Windows installation for {scanner} not fully implemented")
    
    def run_nmap(self, target):
        """Run Nmap scan"""
        try:
            # Basic Nmap scan with vulnerability scripts
            cmd = ['nmap', '-sV', '--script', 'vuln', target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            return {
                'output': result.stdout,
                'error': result.stderr,
                'success': result.returncode == 0
            }
        except subprocess.TimeoutExpired:
            return {'error': 'Nmap scan timed out', 'success': False}
        except Exception as e:
            return {'error': str(e), 'success': False}
    
    def run_nikto(self, target):
        """Run Nikto web scanner"""
        try:
            # Ensure target has http:// prefix for Nikto
            if not target.startswith(('http://', 'https://')):
                target = 'http://' + target
                
            cmd = ['nikto', '-h', target, '-Format', 'txt']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            return {
                'output': result.stdout,
                'error': result.stderr,
                'success': result.returncode == 0
            }
        except subprocess.TimeoutExpired:
            return {'error': 'Nikto scan timed out', 'success': False}
        except Exception as e:
            return {'error': str(e), 'success': False}
    
    def run_whatweb(self, target):
        """Run WhatWeb technology detection"""
        try:
            cmd = ['whatweb', target, '--log-verbose', '-']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            return {
                'output': result.stdout,
                'error': result.stderr,
                'success': result.returncode == 0
            }
        except Exception as e:
            return {'error': str(e), 'success': False}
    
    def run_curl(self, target):
        """Run curl for HTTP header analysis"""
        try:
            # Check various security headers
            cmd = ['curl', '-I', '-L', target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            # Also check SSL/TLS if HTTPS
            headers = result.stdout
            security_analysis = self._analyze_security_headers(headers)
            
            return {
                'headers': headers,
                'security_analysis': security_analysis,
                'success': result.returncode == 0
            }
        except Exception as e:
            return {'error': str(e), 'success': False}
    
    def _analyze_security_headers(self, headers):
        """Analyze security headers from curl output"""
        security_headers = {
            'Strict-Transport-Security': 'HSTS is implemented - Good',
            'Content-Security-Policy': 'CSP is implemented - Good',
            'X-Frame-Options': 'Clickjacking protection - Good',
            'X-Content-Type-Options': 'MIME sniffing protection - Good',
            'X-XSS-Protection': 'XSS protection - Good'
        }
        
        missing = []
        present = []
        
        for header, description in security_headers.items():
            if header.lower() in headers.lower():
                present.append(description)
            else:
                missing.append(f"Missing {header}")
        
        return {
            'present': present,
            'missing': missing,
            'score': len(present) * 20  # Score out of 100
        }
