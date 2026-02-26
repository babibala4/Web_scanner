import gspread
from oauth2client.service_account import ServiceAccountCredentials
from datetime import datetime
import os

class GoogleSheetsLogger:
    def __init__(self):
        self.scope = ['https://spreadsheets.google.com/feeds',
                      'https://www.googleapis.com/auth/drive']
        
        # You need to create a service account and download the JSON key file
        # https://console.developers.google.com/
        self.credentials_file = 'config/google_credentials.json'
        self.sheet_name = 'WebScan Logs'
        
        try:
            if os.path.exists(self.credentials_file):
                self.creds = ServiceAccountCredentials.from_json_keyfile_name(
                    self.credentials_file, self.scope)
                self.client = gspread.authorize(self.creds)
                self.setup_sheet()
            else:
                print("Google credentials not found. Logging to local file only.")
                self.client = None
        except Exception as e:
            print(f"Failed to initialize Google Sheets: {e}")
            self.client = None
    
    def setup_sheet(self):
        """Create or get the logging sheet"""
        try:
            # Try to open existing sheet
            self.sheet = self.client.open(self.sheet_name).sheet1
        except:
            # Create new sheet if it doesn't exist
            self.sheet = self.client.create(self.sheet_name).sheet1
            # Add headers
            headers = ['Timestamp', 'Gmail', 'Scan Type', 'Target URL/IP', 'Vulnerability Stage']
            self.sheet.append_row(headers)
    
    def log_scan(self, scan_data):
        """Log scan data to Google Sheets"""
        try:
            if self.client:
                row = [
                    scan_data['timestamp'],
                    scan_data['gmail'],
                    scan_data['scan_type'],
                    scan_data['target'],
                    scan_data['vuln_stage']
                ]
                self.sheet.append_row(row)
                print("Successfully logged to Google Sheets")
            else:
                # Log to local file as fallback
                self.log_to_file(scan_data)
        except Exception as e:
            print(f"Failed to log to Google Sheets: {e}")
            self.log_to_file(scan_data)
    
    def log_to_file(self, scan_data):
        """Fallback logging to local file"""
        log_file = 'scan_logs.txt'
        with open(log_file, 'a') as f:
            f.write(f"{scan_data['timestamp']},{scan_data['gmail']},"
                   f"{scan_data['scan_type']},{scan_data['target']},"
                   f"{scan_data['vuln_stage']}\n")
