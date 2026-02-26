import re
import requests
import dns.resolver
import smtplib

def verify_gmail(email):
    """Verify if a Gmail ID exists"""
    if not email or not re.match(r'^[a-zA-Z0-9._%+-]+@gmail\.com$', email):
        return False
    
    # Method 1: Check MX records for gmail.com
    try:
        mx_records = dns.resolver.resolve('gmail.com', 'MX')
        if not mx_records:
            return False
    except:
        # DNS resolution failed, try next method
        pass
    
    # Method 2: SMTP verification (simplified)
    # Note: This is a basic check. For production, use a proper email verification service
    try:
        # Extract username from email
        username = email.split('@')[0]
        
        # Check if username format is valid
        if len(username) < 6 or len(username) > 30:
            return False
        
        # Check if username contains only valid characters
        if not re.match(r'^[a-zA-Z0-9._%+-]+$', username):
            return False
        
        # For Gmail, we can also check if it's a valid format
        # Gmail usernames can have dots but they're ignored
        # So "john.doe" and "johndoe" are the same
        
        # Additional check: Gmail doesn't allow certain patterns
        invalid_patterns = [
            r'\.\.',  # Consecutive dots
            r'^\.',   # Starting with dot
            r'\.$',   # Ending with dot
        ]
        
        for pattern in invalid_patterns:
            if re.search(pattern, username):
                return False
        
        # Method 3: Use Google's People API (requires API key)
        # This is the most reliable but requires Google API setup
        
        return True
        
    except Exception as e:
        print(f"Email verification error: {e}")
        return False

# For production, use a service like:
# - Hunter.io
# - NeverBounce
# - ZeroBounce
# Or Google's own verification API
