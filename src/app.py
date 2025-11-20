#!/usr/bin/env python3
"""
Authelia File Admin - Production-ready user management for file-based Authelia

Features:
- File locking for safe concurrent access
- Comprehensive audit logging with HMAC signing
- Automatic log rotation (10MB, 5 backups)
- Input validation and sanitization
- Password complexity validation
- Password breach detection (HaveIBeenPwned)
- Password history tracking (prevent reuse)
- Password expiration policies (auto-expire after N days)
- Security headers (HSTS, CSP, X-Frame-Options)
- Rate limiting
- CSRF protection
- Enhanced security

Author: Dustin @ NYC App House
License: MIT
Version: 1.6.1
"""

import os
import yaml
import re
import logging
import logging.handlers
import json
import html
import hmac
import hashlib
import urllib.request
import urllib.error
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from contextlib import contextmanager
from filelock import FileLock
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from argon2 import PasswordHasher
from argon2.exceptions import Argon2Error

# Initialize Flask app
app = Flask(__name__)

# Security configuration
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', os.urandom(32).hex())
app.config['WTF_CSRF_TIME_LIMIT'] = None  # No expiration for API tokens
app.config['WTF_CSRF_HEADERS'] = ['X-CSRFToken']  # Accept CSRF token from header

# Initialize extensions
CORS(app, resources={r"/api/*": {"origins": "*"}})
csrf = CSRFProtect(app)

# Configuration
USERS_DB_PATH = os.getenv("USERS_DB_PATH", "/config/users_database.yml")
USERS_DB_LOCK = f"{USERS_DB_PATH}.lock"
AUDIT_LOG_PATH = os.getenv("AUDIT_LOG_PATH", "/var/log/authelia-admin-audit.jsonl")

# Audit log HMAC secret key (for tamper detection)
# Generate with: openssl rand -base64 32
AUDIT_HMAC_KEY = os.getenv("AUDIT_HMAC_KEY", os.urandom(32).hex())

# Configure audit logging with rotation
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
audit_logger = logging.getLogger('audit')
# Create audit log directory if it doesn't exist
os.makedirs(os.path.dirname(AUDIT_LOG_PATH), exist_ok=True)
# Use RotatingFileHandler: 10MB max size, keep 5 backup files
audit_handler = logging.handlers.RotatingFileHandler(
    AUDIT_LOG_PATH,
    maxBytes=10*1024*1024,  # 10MB
    backupCount=5
)
audit_handler.setFormatter(logging.Formatter('%(message)s'))
audit_logger.addHandler(audit_handler)
audit_logger.setLevel(logging.INFO)

# Rate limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Security headers configuration
@app.after_request
def set_security_headers(response):
    """
    Add security headers to all responses

    Headers:
    - Strict-Transport-Security (HSTS): Force HTTPS
    - X-Content-Type-Options: Prevent MIME-type sniffing
    - X-Frame-Options: Prevent clickjacking
    - X-XSS-Protection: Enable browser XSS protection
    - Content-Security-Policy: Restrict resource loading
    - Referrer-Policy: Control referrer information
    - Permissions-Policy: Disable unnecessary browser features
    """
    # HSTS: Force HTTPS for 1 year, include subdomains
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'

    # Prevent MIME-type sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'

    # Prevent clickjacking - deny embedding in frames
    response.headers['X-Frame-Options'] = 'DENY'

    # Enable XSS protection in older browsers
    response.headers['X-XSS-Protection'] = '1; mode=block'

    # Content Security Policy - balanced policy for admin interface
    # Allow inline scripts/styles for admin.html (already protected by Authelia)
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )

    # Control referrer information leakage
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'

    # Disable unnecessary browser features
    response.headers['Permissions-Policy'] = (
        'geolocation=(), microphone=(), camera=(), '
        'payment=(), usb=(), magnetometer=(), '
        'gyroscope=(), accelerometer=()'
    )

    return response

# Password policy configuration
PASSWORD_MIN_LENGTH = int(os.getenv("PASSWORD_MIN_LENGTH", "12"))
PASSWORD_REQUIRE_UPPERCASE = os.getenv("PASSWORD_REQUIRE_UPPERCASE", "true").lower() == "true"
PASSWORD_REQUIRE_LOWERCASE = os.getenv("PASSWORD_REQUIRE_LOWERCASE", "true").lower() == "true"
PASSWORD_REQUIRE_DIGIT = os.getenv("PASSWORD_REQUIRE_DIGIT", "true").lower() == "true"
PASSWORD_REQUIRE_SPECIAL = os.getenv("PASSWORD_REQUIRE_SPECIAL", "true").lower() == "true"
PASSWORD_CHECK_BREACH = os.getenv("PASSWORD_CHECK_BREACH", "true").lower() == "true"
PASSWORD_HISTORY_COUNT = int(os.getenv("PASSWORD_HISTORY_COUNT", "5"))  # Keep last N passwords
PASSWORD_EXPIRATION_DAYS = int(os.getenv("PASSWORD_EXPIRATION_DAYS", "0"))  # 0 = never expire

# Email notification configuration
EMAIL_ENABLED = os.getenv("EMAIL_ENABLED", "false").lower() == "true"
SMTP_HOST = os.getenv("SMTP_HOST", "")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USERNAME = os.getenv("SMTP_USERNAME", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM_EMAIL = os.getenv("SMTP_FROM_EMAIL", "noreply@authelia-admin.local")
SMTP_FROM_NAME = os.getenv("SMTP_FROM_NAME", "Authelia Admin")
SMTP_USE_TLS = os.getenv("SMTP_USE_TLS", "true").lower() == "true"
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "")  # Email to send admin notifications

# Input validation limits
MAX_USERNAME_LENGTH = 64
MAX_DISPLAYNAME_LENGTH = 128
MAX_EMAIL_LENGTH = 254  # RFC 5321
MAX_GROUP_LENGTH = 64
MAX_GROUPS_COUNT = 20


def sanitize_string(value, max_length=None):
    """
    Sanitize a string input by escaping HTML and enforcing length limits

    Args:
        value: The string to sanitize
        max_length: Maximum allowed length (None for no limit)

    Returns:
        Sanitized string
    """
    if value is None:
        return ""

    # Convert to string and strip whitespace
    value = str(value).strip()

    # Escape HTML to prevent XSS
    value = html.escape(value)

    # Enforce length limit
    if max_length and len(value) > max_length:
        raise ValueError(f"Input exceeds maximum length of {max_length} characters")

    return value


def validate_email(email):
    """
    Validate email address format and length

    Returns:
        tuple: (is_valid, error_message)
    """
    if not email:
        return False, "Email is required"

    email = email.strip()

    # Check length (RFC 5321)
    if len(email) > MAX_EMAIL_LENGTH:
        return False, f"Email exceeds maximum length of {MAX_EMAIL_LENGTH} characters"

    # Basic format validation
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_pattern, email):
        return False, "Invalid email format"

    # Check for suspicious patterns
    if '..' in email or email.startswith('.') or email.endswith('.'):
        return False, "Invalid email format"

    # Validate local part (before @) length (max 64 chars per RFC 5321)
    local_part = email.split('@')[0]
    if len(local_part) > 64:
        return False, "Email local part exceeds 64 characters"

    return True, None


def validate_username(username):
    """
    Validate username format and length

    Returns:
        tuple: (is_valid, error_message)
    """
    if not username:
        return False, "Username is required"

    username = username.strip()

    # Check length
    if len(username) < 2:
        return False, "Username must be at least 2 characters"
    if len(username) > MAX_USERNAME_LENGTH:
        return False, f"Username exceeds maximum length of {MAX_USERNAME_LENGTH} characters"

    # Only allow alphanumeric, hyphens, and underscores
    if not re.match(r'^[a-zA-Z0-9_-]+$', username):
        return False, "Username must contain only letters, numbers, hyphens, and underscores"

    # Prevent leading/trailing hyphens or underscores
    if username.startswith(('-', '_')) or username.endswith(('-', '_')):
        return False, "Username cannot start or end with hyphen or underscore"

    return True, None


def validate_displayname(displayname):
    """
    Validate display name length

    Returns:
        tuple: (is_valid, error_message)
    """
    if not displayname:
        return True, None  # Display name is optional

    displayname = displayname.strip()

    if len(displayname) > MAX_DISPLAYNAME_LENGTH:
        return False, f"Display name exceeds maximum length of {MAX_DISPLAYNAME_LENGTH} characters"

    return True, None


def validate_groups(groups):
    """
    Validate groups list

    Returns:
        tuple: (is_valid, error_message)
    """
    if not groups:
        return False, "At least one group is required"

    if not isinstance(groups, list):
        return False, "Groups must be a list"

    if len(groups) > MAX_GROUPS_COUNT:
        return False, f"Too many groups (maximum {MAX_GROUPS_COUNT})"

    for group in groups:
        if not isinstance(group, str):
            return False, "Group names must be strings"

        group = group.strip()
        if not group:
            return False, "Group names cannot be empty"

        if len(group) > MAX_GROUP_LENGTH:
            return False, f"Group name exceeds maximum length of {MAX_GROUP_LENGTH} characters"

        # Only allow alphanumeric, hyphens, and underscores
        if not re.match(r'^[a-zA-Z0-9_-]+$', group):
            return False, f"Group name '{group}' contains invalid characters"

    return True, None


def compute_audit_hmac(entry_data):
    """
    Compute HMAC signature for an audit log entry

    This creates a tamper-evident signature using HMAC-SHA256.
    Any modification to the log entry will invalidate the signature.
    """
    # Create canonical representation (sorted keys for consistency)
    canonical = json.dumps(entry_data, sort_keys=True)
    signature = hmac.new(
        AUDIT_HMAC_KEY.encode('utf-8'),
        canonical.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    return signature


def log_audit(action, user, target=None, details=None, success=True):
    """
    Log administrative actions to audit log with HMAC signature

    Each entry is signed with HMAC-SHA256 to detect tampering.
    Logs are automatically rotated at 10MB (keeps 5 backups).
    """
    audit_entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "action": action,
        "user": user,
        "target": target,
        "details": details,
        "success": success,
        "ip": request.remote_addr if request else None
    }

    # Add HMAC signature for tamper detection
    audit_entry["hmac"] = compute_audit_hmac(audit_entry)

    audit_logger.info(json.dumps(audit_entry))


def verify_audit_log(log_path=None, max_lines=None):
    """
    Verify integrity of audit log entries by checking HMAC signatures

    Returns:
        dict: {
            "total": int,
            "valid": int,
            "invalid": int,
            "errors": list of dicts with line number and error message
        }
    """
    if log_path is None:
        log_path = AUDIT_LOG_PATH

    if not os.path.exists(log_path):
        return {
            "total": 0,
            "valid": 0,
            "invalid": 0,
            "errors": [{"error": "Audit log file not found"}]
        }

    results = {
        "total": 0,
        "valid": 0,
        "invalid": 0,
        "errors": []
    }

    try:
        with open(log_path, 'r') as f:
            for line_num, line in enumerate(f, start=1):
                if max_lines and line_num > max_lines:
                    break

                line = line.strip()
                if not line:
                    continue

                results["total"] += 1

                try:
                    entry = json.loads(line)
                except json.JSONDecodeError as e:
                    results["invalid"] += 1
                    results["errors"].append({
                        "line": line_num,
                        "error": f"Invalid JSON: {str(e)}"
                    })
                    continue

                # Check if entry has HMAC (older entries may not)
                if "hmac" not in entry:
                    results["errors"].append({
                        "line": line_num,
                        "error": "Missing HMAC signature (legacy entry)"
                    })
                    continue

                # Extract and verify HMAC
                stored_hmac = entry.pop("hmac")
                computed_hmac = compute_audit_hmac(entry)

                if stored_hmac == computed_hmac:
                    results["valid"] += 1
                else:
                    results["invalid"] += 1
                    results["errors"].append({
                        "line": line_num,
                        "error": "HMAC verification failed - entry may be tampered",
                        "action": entry.get("action"),
                        "timestamp": entry.get("timestamp")
                    })

    except Exception as e:
        results["errors"].append({"error": f"Failed to read log file: {str(e)}"})

    return results


def is_admin(req):
    """Check if the user is an admin based on Remote-Groups header"""
    groups = req.headers.get("Remote-Groups", "")
    return "admins" in groups.split(",")


def get_current_user(req):
    """Get current user from Remote-User header"""
    return req.headers.get("Remote-User", "unknown")


@contextmanager
def locked_users_file(mode='r'):
    """Context manager for safe file access with locking"""
    lock = FileLock(USERS_DB_LOCK, timeout=10)
    try:
        with lock:
            with open(USERS_DB_PATH, mode) as f:
                yield f
    except Exception as e:
        app.logger.error(f"File lock error: {e}")
        raise


def load_users():
    """Load users from the database file with file locking"""
    if not os.path.exists(USERS_DB_PATH):
        return {"users": {}}

    try:
        with locked_users_file('r') as f:
            data = yaml.safe_load(f)
            return data if data else {"users": {}}
    except Exception as e:
        app.logger.error(f"Failed to load users: {e}")
        return {"users": {}}


def save_users(data):
    """Save users to the database file with file locking"""
    try:
        with locked_users_file('w') as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)

        # Authelia automatically watches and reloads the file (watch: true in config)
        # No restart needed!
        return True
    except Exception as e:
        app.logger.error(f"Failed to save users: {e}")
        raise


def check_password_breach(password):
    """
    Check if password has been found in data breaches using HaveIBeenPwned API

    Uses k-anonymity model: Only first 5 chars of SHA-1 hash are sent to API.

    Returns:
        tuple: (is_breached: bool, breach_count: int)
    """
    if not PASSWORD_CHECK_BREACH:
        return False, 0

    try:
        # Hash password with SHA-1
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]

        # Query HaveIBeenPwned API with first 5 chars
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        req = urllib.request.Request(url, headers={'User-Agent': 'Authelia-File-Admin/1.2.0'})

        with urllib.request.urlopen(req, timeout=5) as response:
            hashes = response.read().decode('utf-8')

        # Check if our suffix appears in the response
        for line in hashes.splitlines():
            hash_suffix, count = line.split(':')
            if hash_suffix == suffix:
                return True, int(count)

        return False, 0

    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as e:
        # If API is unavailable, log warning but don't block password
        app.logger.warning(f"HaveIBeenPwned API unavailable: {e}")
        return False, 0
    except Exception as e:
        app.logger.error(f"Unexpected error checking password breach: {e}")
        return False, 0


def validate_password(password):
    """
    Validate password against complexity requirements and breach database

    Returns:
        tuple: (is_valid: bool, errors: list)
    """
    errors = []

    if len(password) < PASSWORD_MIN_LENGTH:
        errors.append(f"Password must be at least {PASSWORD_MIN_LENGTH} characters long")

    if PASSWORD_REQUIRE_UPPERCASE and not re.search(r'[A-Z]', password):
        errors.append("Password must contain at least one uppercase letter")

    if PASSWORD_REQUIRE_LOWERCASE and not re.search(r'[a-z]', password):
        errors.append("Password must contain at least one lowercase letter")

    if PASSWORD_REQUIRE_DIGIT and not re.search(r'\d', password):
        errors.append("Password must contain at least one digit")

    if PASSWORD_REQUIRE_SPECIAL and not re.search(r'[^A-Za-z0-9]', password):
        errors.append("Password must contain at least one special character")

    # Check for breached passwords
    if PASSWORD_CHECK_BREACH:
        is_breached, breach_count = check_password_breach(password)
        if is_breached:
            errors.append(f"Password found in {breach_count:,} data breaches - please choose a different password")

    return len(errors) == 0, errors


def hash_password(password):
    """
    Generate Argon2id hash compatible with Authelia

    Uses the same parameters as Authelia:
    - iterations (time_cost): 3
    - memory: 65536 KiB
    - parallelism: 4
    - hash_len (key_length): 32 bytes
    - salt_len: 16 bytes (default in argon2-cffi)
    """
    try:
        # Create PasswordHasher with Authelia-compatible parameters
        ph = PasswordHasher(
            time_cost=3,           # iterations
            memory_cost=65536,     # memory in KiB
            parallelism=4,         # parallelism
            hash_len=32,           # key_length in bytes
            salt_len=16            # salt_length in bytes
        )

        # Generate hash (already in PHC string format: $argon2id$v=19$...)
        password_hash = ph.hash(password)
        return password_hash
    except Argon2Error as e:
        raise Exception(f"Failed to hash password: {e}")


def check_password_history(password, password_history):
    """
    Check if password matches any password in history

    Args:
        password: Plain text password to check
        password_history: List of Argon2 password hashes

    Returns:
        bool: True if password was used before, False otherwise
    """
    if not password_history or PASSWORD_HISTORY_COUNT == 0:
        return False

    ph = PasswordHasher(
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=32,
        salt_len=16
    )

    for old_hash in password_history:
        try:
            # verify() will raise exception if password doesn't match
            ph.verify(old_hash, password)
            # If we get here, password matches this hash
            return True
        except Argon2Error:
            # Password doesn't match this hash, continue checking
            continue

    return False


def update_password_history(current_hash, password_history):
    """
    Add current password hash to history and maintain limit

    Args:
        current_hash: Current password hash to add to history
        password_history: Existing password history list

    Returns:
        list: Updated password history (limited to PASSWORD_HISTORY_COUNT)
    """
    if PASSWORD_HISTORY_COUNT == 0:
        return []

    # Initialize history if None
    if password_history is None:
        password_history = []

    # Add current hash to beginning of history
    updated_history = [current_hash] + password_history

    # Keep only the configured number of passwords
    return updated_history[:PASSWORD_HISTORY_COUNT]


def check_password_expired(password_changed_at):
    """
    Check if password has expired based on PASSWORD_EXPIRATION_DAYS

    Args:
        password_changed_at: ISO format timestamp of last password change

    Returns:
        tuple: (is_expired: bool, days_until_expiry: int)
    """
    if PASSWORD_EXPIRATION_DAYS == 0:
        return False, None  # Expiration disabled

    if not password_changed_at:
        # No timestamp means password never changed - mark as expired
        return True, 0

    try:
        changed_date = datetime.fromisoformat(password_changed_at)
        now = datetime.utcnow()
        days_since_change = (now - changed_date).days
        days_until_expiry = PASSWORD_EXPIRATION_DAYS - days_since_change

        is_expired = days_until_expiry <= 0

        return is_expired, days_until_expiry

    except (ValueError, TypeError):
        # Invalid timestamp - treat as expired
        return True, 0


def get_password_age_warning(password_changed_at):
    """
    Get warning message if password is approaching expiration

    Args:
        password_changed_at: ISO format timestamp of last password change

    Returns:
        str or None: Warning message if password expiring soon
    """
    if PASSWORD_EXPIRATION_DAYS == 0:
        return None

    is_expired, days_until_expiry = check_password_expired(password_changed_at)

    if is_expired:
        return "Password has expired and must be changed"
    elif days_until_expiry is not None and days_until_expiry <= 7:
        return f"Password will expire in {days_until_expiry} days"

    return None


def send_email(to_email, subject, body_html, body_text=None):
    """
    Send email notification via SMTP

    Args:
        to_email: Recipient email address
        subject: Email subject
        body_html: HTML email body
        body_text: Plain text fallback (optional, auto-generated from HTML if not provided)

    Returns:
        bool: True if sent successfully, False otherwise
    """
    if not EMAIL_ENABLED:
        app.logger.debug(f"Email disabled, would have sent: {subject} to {to_email}")
        return False

    if not SMTP_HOST or not to_email:
        app.logger.warning(f"Email not configured properly. SMTP_HOST: {SMTP_HOST}, to_email: {to_email}")
        return False

    try:
        # Create message
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = f"{SMTP_FROM_NAME} <{SMTP_FROM_EMAIL}>"
        msg['To'] = to_email

        # Attach text and HTML parts
        if body_text:
            part1 = MIMEText(body_text, 'plain')
            msg.attach(part1)

        part2 = MIMEText(body_html, 'html')
        msg.attach(part2)

        # Send email
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
            if SMTP_USE_TLS:
                server.starttls()
            if SMTP_USERNAME and SMTP_PASSWORD:
                server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.send_message(msg)

        app.logger.info(f"Email sent successfully: {subject} to {to_email}")
        return True

    except Exception as e:
        app.logger.error(f"Failed to send email: {e}")
        return False


def send_user_created_notification(username, email, created_by):
    """Send notification when a new user is created"""
    if not EMAIL_ENABLED:
        return

    subject = f"New User Account Created: {username}"

    html_body = f"""
    <html>
      <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
        <h2 style="color: #2c3e50;">New User Account Created</h2>
        <p>A new user account has been created in Authelia File Admin.</p>

        <table style="background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin: 20px 0;">
          <tr><td style="padding: 5px;"><strong>Username:</strong></td><td style="padding: 5px;">{username}</td></tr>
          <tr><td style="padding: 5px;"><strong>Email:</strong></td><td style="padding: 5px;">{email}</td></tr>
          <tr><td style="padding: 5px;"><strong>Created By:</strong></td><td style="padding: 5px;">{created_by}</td></tr>
          <tr><td style="padding: 5px;"><strong>Time:</strong></td><td style="padding: 5px;">{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</td></tr>
        </table>

        <p style="color: #7f8c8d; font-size: 12px;">
          This is an automated notification from Authelia File Admin.
        </p>
      </body>
    </html>
    """

    text_body = f"""
    New User Account Created

    Username: {username}
    Email: {email}
    Created By: {created_by}
    Time: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}

    ---
    This is an automated notification from Authelia File Admin.
    """

    # Send to the new user
    send_email(email, subject, html_body, text_body)

    # Send to admin if configured
    if ADMIN_EMAIL:
        send_email(ADMIN_EMAIL, f"[Admin] {subject}", html_body, text_body)


def send_password_changed_notification(username, email, changed_by):
    """Send notification when password is changed"""
    if not EMAIL_ENABLED:
        return

    subject = f"Password Changed for {username}"

    html_body = f"""
    <html>
      <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
        <h2 style="color: #e74c3c;">Password Changed</h2>
        <p>The password for your account has been changed.</p>

        <table style="background-color: #fff3cd; padding: 15px; border-radius: 5px; margin: 20px 0; border-left: 4px solid #ffc107;">
          <tr><td style="padding: 5px;"><strong>Username:</strong></td><td style="padding: 5px;">{username}</td></tr>
          <tr><td style="padding: 5px;"><strong>Changed By:</strong></td><td style="padding: 5px;">{changed_by}</td></tr>
          <tr><td style="padding: 5px;"><strong>Time:</strong></td><td style="padding: 5px;">{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</td></tr>
        </table>

        <p><strong>If you did not make this change, please contact your administrator immediately.</strong></p>

        <p style="color: #7f8c8d; font-size: 12px;">
          This is an automated security notification from Authelia File Admin.
        </p>
      </body>
    </html>
    """

    text_body = f"""
    Password Changed

    The password for your account has been changed.

    Username: {username}
    Changed By: {changed_by}
    Time: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}

    If you did not make this change, please contact your administrator immediately.

    ---
    This is an automated security notification from Authelia File Admin.
    """

    # Send to user
    send_email(email, subject, html_body, text_body)


def send_password_expiring_notification(username, email, days_remaining):
    """Send notification when password is expiring soon"""
    if not EMAIL_ENABLED or PASSWORD_EXPIRATION_DAYS == 0:
        return

    subject = f"Password Expiring Soon for {username}"

    html_body = f"""
    <html>
      <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
        <h2 style="color: #ff9800;">Password Expiring Soon</h2>
        <p>Your password will expire in <strong>{days_remaining} days</strong>.</p>

        <table style="background-color: #fff3cd; padding: 15px; border-radius: 5px; margin: 20px 0; border-left: 4px solid #ff9800;">
          <tr><td style="padding: 5px;"><strong>Username:</strong></td><td style="padding: 5px;">{username}</td></tr>
          <tr><td style="padding: 5px;"><strong>Days Remaining:</strong></td><td style="padding: 5px;">{days_remaining}</td></tr>
          <tr><td style="padding: 5px;"><strong>Expiration Policy:</strong></td><td style="padding: 5px;">Passwords expire after {PASSWORD_EXPIRATION_DAYS} days</td></tr>
        </table>

        <p>Please change your password soon to avoid account lockout.</p>

        <p style="color: #7f8c8d; font-size: 12px;">
          This is an automated notification from Authelia File Admin.
        </p>
      </body>
    </html>
    """

    text_body = f"""
    Password Expiring Soon

    Your password will expire in {days_remaining} days.

    Username: {username}
    Days Remaining: {days_remaining}
    Expiration Policy: Passwords expire after {PASSWORD_EXPIRATION_DAYS} days

    Please change your password soon to avoid account lockout.

    ---
    This is an automated notification from Authelia File Admin.
    """

    send_email(email, subject, html_body, text_body)


def send_user_deleted_notification(username, email, deleted_by):
    """Send notification when user is deleted"""
    if not EMAIL_ENABLED:
        return

    subject = f"User Account Deleted: {username}"

    html_body = f"""
    <html>
      <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
        <h2 style="color: #e74c3c;">User Account Deleted</h2>
        <p>A user account has been deleted from Authelia File Admin.</p>

        <table style="background-color: #f8d7da; padding: 15px; border-radius: 5px; margin: 20px 0; border-left: 4px solid #e74c3c;">
          <tr><td style="padding: 5px;"><strong>Username:</strong></td><td style="padding: 5px;">{username}</td></tr>
          <tr><td style="padding: 5px;"><strong>Email:</strong></td><td style="padding: 5px;">{email}</td></tr>
          <tr><td style="padding: 5px;"><strong>Deleted By:</strong></td><td style="padding: 5px;">{deleted_by}</td></tr>
          <tr><td style="padding: 5px;"><strong>Time:</strong></td><td style="padding: 5px;">{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</td></tr>
        </table>

        <p style="color: #7f8c8d; font-size: 12px;">
          This is an automated notification from Authelia File Admin.
        </p>
      </body>
    </html>
    """

    text_body = f"""
    User Account Deleted

    Username: {username}
    Email: {email}
    Deleted By: {deleted_by}
    Time: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}

    ---
    This is an automated notification from Authelia File Admin.
    """

    # Send to admin if configured
    if ADMIN_EMAIL:
        send_email(ADMIN_EMAIL, f"[Admin] {subject}", html_body, text_body)


@app.route("/users", methods=["GET"])
@limiter.limit("30 per minute")
def list_users():
    """List all users (admins only)"""
    if not is_admin(request):
        log_audit("list_users", get_current_user(request), success=False, details="Unauthorized")
        return jsonify({"error": "Unauthorized"}), 403

    data = load_users()
    users_list = []
    for username, details in data.get("users", {}).items():
        user_info = {
            "username": username,
            "displayname": details.get("displayname", ""),
            "email": details.get("email", ""),
            "groups": details.get("groups", [])
        }

        # Always include password change timestamp and age
        password_changed_at = details.get("password_changed_at")
        user_info["password_changed_at"] = password_changed_at

        # Calculate password age in days
        if password_changed_at:
            try:
                changed_date = datetime.fromisoformat(password_changed_at)
                password_age_days = (datetime.utcnow() - changed_date).days
                user_info["password_age_days"] = password_age_days
            except (ValueError, TypeError):
                user_info["password_age_days"] = None
        else:
            user_info["password_age_days"] = None

        # Add password expiration info and status
        if PASSWORD_EXPIRATION_DAYS > 0:
            is_expired, days_until_expiry = check_password_expired(password_changed_at)
            user_info["password_expired"] = is_expired
            user_info["password_expires_in_days"] = days_until_expiry

            # Determine status: "expired", "expiring_soon", "ok", or "unknown"
            if is_expired:
                user_info["password_status"] = "expired"
            elif days_until_expiry is not None and days_until_expiry <= 7:
                user_info["password_status"] = "expiring_soon"
            elif days_until_expiry is not None:
                user_info["password_status"] = "ok"
            else:
                user_info["password_status"] = "unknown"
        else:
            # Expiration disabled
            user_info["password_expired"] = False
            user_info["password_expires_in_days"] = None
            user_info["password_status"] = "ok"

        users_list.append(user_info)

    log_audit("list_users", get_current_user(request), details=f"Listed {len(users_list)} users")
    return jsonify({"users": users_list, "total": len(users_list)})


@app.route("/users", methods=["POST"])
@limiter.limit("10 per minute")
def create_user():
    """Create a new user (admins only)"""
    if not is_admin(request):
        log_audit("create_user", get_current_user(request), success=False, details="Unauthorized")
        return jsonify({"error": "Unauthorized"}), 403

    body = request.get_json()
    username = body.get("username", "").strip()
    password = body.get("password", "")
    displayname = body.get("displayname", "").strip()
    email = body.get("email", "").strip()
    groups = body.get("groups", ["users"])

    # Validate required fields
    if not username or not password or not email:
        log_audit("create_user", get_current_user(request), username, success=False, details="Missing fields")
        return jsonify({"error": "Missing required fields: username, password, email"}), 400

    # Validate username
    valid, error = validate_username(username)
    if not valid:
        log_audit("create_user", get_current_user(request), username, success=False, details=f"Invalid username: {error}")
        return jsonify({"error": error}), 400

    # Validate email
    valid, error = validate_email(email)
    if not valid:
        log_audit("create_user", get_current_user(request), username, success=False, details=f"Invalid email: {error}")
        return jsonify({"error": error}), 400

    # Validate display name
    if not displayname:
        displayname = username
    valid, error = validate_displayname(displayname)
    if not valid:
        log_audit("create_user", get_current_user(request), username, success=False, details=f"Invalid displayname: {error}")
        return jsonify({"error": error}), 400

    # Validate groups
    valid, error = validate_groups(groups)
    if not valid:
        log_audit("create_user", get_current_user(request), username, success=False, details=f"Invalid groups: {error}")
        return jsonify({"error": error}), 400

    # Validate password complexity
    is_valid, errors = validate_password(password)
    if not is_valid:
        log_audit("create_user", get_current_user(request), username, success=False, details="Password validation failed")
        return jsonify({"error": "Password does not meet complexity requirements", "details": errors}), 400

    # Sanitize string inputs (HTML escape to prevent XSS)
    try:
        username = sanitize_string(username, MAX_USERNAME_LENGTH)
        displayname = sanitize_string(displayname, MAX_DISPLAYNAME_LENGTH)
        email = sanitize_string(email, MAX_EMAIL_LENGTH)
        groups = [sanitize_string(g, MAX_GROUP_LENGTH) for g in groups]
    except ValueError as e:
        log_audit("create_user", get_current_user(request), username, success=False, details=str(e))
        return jsonify({"error": str(e)}), 400

    # Load existing users
    data = load_users()
    if username in data.get("users", {}):
        log_audit("create_user", get_current_user(request), username, success=False, details="User already exists")
        return jsonify({"error": "User already exists"}), 409

    # Hash the password
    try:
        password_hash = hash_password(password)
    except Exception as e:
        log_audit("create_user", get_current_user(request), username, success=False, details=f"Hash failed")
        return jsonify({"error": str(e)}), 500

    # Add the new user
    if "users" not in data:
        data["users"] = {}

    data["users"][username] = {
        "displayname": displayname,
        "password": password_hash,
        "email": email,
        "groups": groups,
        "password_changed_at": datetime.utcnow().isoformat()
    }

    # Save changes
    try:
        save_users(data)
        log_audit("create_user", get_current_user(request), username, details=f"Groups: {groups}, Email: {email}")

        # Send email notification
        send_user_created_notification(username, email, get_current_user(request))

        return jsonify({
            "message": "User created successfully",
            "username": username
        }), 201
    except Exception as e:
        log_audit("create_user", get_current_user(request), username, success=False, details="Save failed")
        return jsonify({"error": f"Failed to save user: {str(e)}"}), 500


@app.route("/users/<username>", methods=["DELETE"])
@limiter.limit("20 per minute")
def delete_user(username):
    """Delete a user (admins only)"""
    current_user = get_current_user(request)

    # Validate and sanitize username from URL
    try:
        username = username.strip()
        valid, error = validate_username(username)
        if not valid:
            log_audit("delete_user", current_user, username, success=False, details=f"Invalid username: {error}")
            return jsonify({"error": error}), 400
        username = sanitize_string(username, MAX_USERNAME_LENGTH)
    except ValueError as e:
        log_audit("delete_user", current_user, username, success=False, details=str(e))
        return jsonify({"error": str(e)}), 400

    if not is_admin(request):
        log_audit("delete_user", current_user, username, success=False, details="Unauthorized")
        return jsonify({"error": "Unauthorized"}), 403

    # Prevent deleting yourself
    if username == current_user:
        log_audit("delete_user", current_user, username, success=False, details="Cannot delete own account")
        return jsonify({"error": "Cannot delete your own account"}), 400

    data = load_users()
    if username not in data.get("users", {}):
        log_audit("delete_user", current_user, username, success=False, details="User not found")
        return jsonify({"error": "User not found"}), 404

    # Get user email before deletion (for notification)
    user_email = data["users"][username].get("email", "")

    del data["users"][username]

    try:
        save_users(data)
        log_audit("delete_user", current_user, username, details="User deleted")

        # Send email notification
        send_user_deleted_notification(username, user_email, current_user)

        return jsonify({"message": "User deleted successfully"})
    except Exception as e:
        log_audit("delete_user", current_user, username, success=False, details="Save failed")
        return jsonify({"error": f"Failed to delete user: {str(e)}"}), 500


@app.route("/users/<username>/password", methods=["PUT"])
@limiter.limit("10 per minute")
def change_password(username):
    """Change a user's password (admins or self)"""
    current_user = get_current_user(request)

    # Validate and sanitize username from URL
    try:
        username = username.strip()
        valid, error = validate_username(username)
        if not valid:
            log_audit("change_password", current_user, username, success=False, details=f"Invalid username: {error}")
            return jsonify({"error": error}), 400
        username = sanitize_string(username, MAX_USERNAME_LENGTH)
    except ValueError as e:
        log_audit("change_password", current_user, username, success=False, details=str(e))
        return jsonify({"error": str(e)}), 400

    # Allow admins or the user themselves to change password
    if not is_admin(request) and username != current_user:
        log_audit("change_password", current_user, username, success=False, details="Unauthorized")
        return jsonify({"error": "Unauthorized"}), 403

    body = request.get_json()
    new_password = body.get("password")

    if not new_password:
        log_audit("change_password", current_user, username, success=False, details="Missing password")
        return jsonify({"error": "Missing password field"}), 400

    # Validate password complexity
    is_valid, errors = validate_password(new_password)
    if not is_valid:
        log_audit("change_password", current_user, username, success=False, details="Password validation failed")
        return jsonify({"error": "Password does not meet complexity requirements", "details": errors}), 400

    data = load_users()
    if username not in data.get("users", {}):
        log_audit("change_password", current_user, username, success=False, details="User not found")
        return jsonify({"error": "User not found"}), 404

    # Check password history to prevent reuse
    user_data = data["users"][username]
    password_history = user_data.get("password_history", [])

    if check_password_history(new_password, password_history):
        log_audit("change_password", current_user, username, success=False,
                 details=f"Password reused from history (last {PASSWORD_HISTORY_COUNT} passwords)")
        return jsonify({
            "error": f"Password was used recently. Please choose a different password (cannot reuse last {PASSWORD_HISTORY_COUNT} passwords)."
        }), 400

    # Hash the new password
    try:
        password_hash = hash_password(new_password)
    except Exception as e:
        log_audit("change_password", current_user, username, success=False, details="Hash failed")
        return jsonify({"error": str(e)}), 500

    # Update password history (add current hash before changing)
    current_password_hash = user_data.get("password")
    if current_password_hash:
        user_data["password_history"] = update_password_history(current_password_hash, password_history)

    # Update password and timestamp
    data["users"][username]["password"] = password_hash
    data["users"][username]["password_changed_at"] = datetime.utcnow().isoformat()

    try:
        save_users(data)
        log_audit("change_password", current_user, username, details="Password updated (history tracked, expiration reset)")

        # Send email notification
        user_email = data["users"][username].get("email", "")
        send_password_changed_notification(username, user_email, current_user)

        return jsonify({"message": "Password updated successfully"})
    except Exception as e:
        log_audit("change_password", current_user, username, success=False, details="Save failed")
        return jsonify({"error": f"Failed to update password: {str(e)}"}), 500


@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "version": "1.10.0",
        "features": [
            "file_locking",
            "audit_logging",
            "audit_hmac_signing",
            "audit_log_rotation",
            "password_validation",
            "password_breach_detection",
            "password_history_tracking",
            "password_expiration",
            "input_validation",
            "rate_limiting",
            "csrf_protection",
            "security_headers",
            "email_notifications"
        ]
    })


@app.route("/csrf-token", methods=["GET"])
def get_csrf_token():
    """Get CSRF token for frontend"""
    from flask_wtf.csrf import generate_csrf
    token = generate_csrf()
    return jsonify({"csrf_token": token})


@app.route("/audit/verify", methods=["GET"])
@limiter.limit("10 per minute")
def verify_audit():
    """
    Verify audit log integrity by checking HMAC signatures (admins only)

    Query parameters:
        max_lines: Optional limit on number of lines to check
    """
    if not is_admin(request):
        log_audit("verify_audit", get_current_user(request), success=False, details="Unauthorized")
        return jsonify({"error": "Unauthorized"}), 403

    max_lines = request.args.get('max_lines', type=int)

    try:
        results = verify_audit_log(max_lines=max_lines)
        log_audit("verify_audit", get_current_user(request),
                 details=f"Verified {results['total']} entries: {results['valid']} valid, {results['invalid']} invalid")
        return jsonify(results)
    except Exception as e:
        log_audit("verify_audit", get_current_user(request), success=False, details=str(e))
        return jsonify({"error": f"Verification failed: {str(e)}"}), 500


@app.route("/stats", methods=["GET"])
def stats():
    """Get user statistics (admins only)"""
    if not is_admin(request):
        return jsonify({"error": "Unauthorized"}), 403

    data = load_users()
    users = data.get("users", {})

    # Count users per group
    group_counts = {}
    for user_data in users.values():
        for group in user_data.get("groups", []):
            group_counts[group] = group_counts.get(group, 0) + 1

    # Password expiration statistics
    password_stats = {
        "expired": 0,
        "expiring_soon": 0,
        "healthy": 0,
        "no_data": 0
    }

    if PASSWORD_EXPIRATION_DAYS > 0:
        for user_data in users.values():
            password_changed_at = user_data.get("password_changed_at")
            is_expired, days_until_expiry = check_password_expired(password_changed_at)

            if is_expired:
                password_stats["expired"] += 1
            elif days_until_expiry is not None and days_until_expiry <= 7:
                password_stats["expiring_soon"] += 1
            elif days_until_expiry is not None:
                password_stats["healthy"] += 1
            else:
                password_stats["no_data"] += 1
    else:
        # Expiration disabled, all passwords are "healthy"
        password_stats["healthy"] = len(users)

    return jsonify({
        "total_users": len(users),
        "groups": group_counts,
        "password_expiration": password_stats,
        "expiration_enabled": PASSWORD_EXPIRATION_DAYS > 0,
        "expiration_days": PASSWORD_EXPIRATION_DAYS
    })


@app.route("/users/export", methods=["GET"])
@limiter.limit("10 per minute")
def export_users():
    """Export all users to CSV (admins only, without password hashes)"""
    if not is_admin(request):
        log_audit("export_users", get_current_user(request), success=False, details="Unauthorized")
        return jsonify({"error": "Unauthorized"}), 403

    data = load_users()
    users = data.get("users", {})

    # Build CSV content
    import io
    import csv

    output = io.StringIO()
    writer = csv.writer(output)

    # Write header
    writer.writerow(['username', 'displayname', 'email', 'groups'])

    # Write user data
    for username, user_data in users.items():
        writer.writerow([
            username,
            user_data.get('displayname', ''),
            user_data.get('email', ''),
            ','.join(user_data.get('groups', []))
        ])

    csv_content = output.getvalue()
    output.close()

    log_audit("export_users", get_current_user(request), details=f"Exported {len(users)} users")

    from flask import make_response
    response = make_response(csv_content)
    response.headers['Content-Type'] = 'text/csv'
    response.headers['Content-Disposition'] = 'attachment; filename=authelia_users_export.csv'
    return response


@app.route("/users/bulk/import", methods=["POST"])
@limiter.limit("5 per hour")
def bulk_import_users():
    """Import multiple users from CSV (admins only)"""
    if not is_admin(request):
        log_audit("bulk_import", get_current_user(request), success=False, details="Unauthorized")
        return jsonify({"error": "Unauthorized"}), 403

    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400

    if not file.filename.endswith('.csv'):
        return jsonify({"error": "File must be CSV format"}), 400

    # Parse CSV
    import csv
    import io

    try:
        # Read file content
        stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
        csv_reader = csv.DictReader(stream)

        # Validate headers
        required_headers = {'username', 'password', 'email'}
        headers = set(csv_reader.fieldnames or [])
        if not required_headers.issubset(headers):
            return jsonify({
                "error": "CSV must have columns: username, password, email",
                "details": f"Missing: {required_headers - headers}"
            }), 400

        # Process users
        results = {
            'success': [],
            'failed': [],
            'skipped': []
        }

        data = load_users()
        if "users" not in data:
            data["users"] = {}

        for row_num, row in enumerate(csv_reader, start=2):  # Start at 2 (header is 1)
            username = row.get('username', '').strip()
            password = row.get('password', '').strip()
            email = row.get('email', '').strip()
            displayname = row.get('displayname', username).strip()
            groups_str = row.get('groups', 'users').strip()

            # Parse groups
            if groups_str:
                groups = [g.strip() for g in groups_str.split(',') if g.strip()]
            else:
                groups = ['users']

            # Skip if user already exists
            if username in data["users"]:
                results['skipped'].append({
                    'row': row_num,
                    'username': username,
                    'reason': 'User already exists'
                })
                continue

            # Validate required fields
            if not username or not password or not email:
                results['failed'].append({
                    'row': row_num,
                    'username': username or '(empty)',
                    'error': 'Missing required fields'
                })
                continue

            # Validate username
            valid, error = validate_username(username)
            if not valid:
                results['failed'].append({
                    'row': row_num,
                    'username': username,
                    'error': error
                })
                continue

            # Validate email
            valid, error = validate_email(email)
            if not valid:
                results['failed'].append({
                    'row': row_num,
                    'username': username,
                    'error': error
                })
                continue

            # Validate displayname
            if not displayname:
                displayname = username
            valid, error = validate_displayname(displayname)
            if not valid:
                results['failed'].append({
                    'row': row_num,
                    'username': username,
                    'error': error
                })
                continue

            # Validate groups
            valid, error = validate_groups(groups)
            if not valid:
                results['failed'].append({
                    'row': row_num,
                    'username': username,
                    'error': error
                })
                continue

            # Validate password complexity
            is_valid, errors = validate_password(password)
            if not is_valid:
                results['failed'].append({
                    'row': row_num,
                    'username': username,
                    'error': 'Password validation failed',
                    'details': errors
                })
                continue

            # Sanitize string inputs (HTML escape to prevent XSS)
            try:
                username = sanitize_string(username, MAX_USERNAME_LENGTH)
                displayname = sanitize_string(displayname, MAX_DISPLAYNAME_LENGTH)
                email = sanitize_string(email, MAX_EMAIL_LENGTH)
                groups = [sanitize_string(g, MAX_GROUP_LENGTH) for g in groups]
            except ValueError as e:
                results['failed'].append({
                    'row': row_num,
                    'username': username,
                    'error': str(e)
                })
                continue

            # Hash password
            try:
                password_hash = hash_password(password)
            except Exception as e:
                results['failed'].append({
                    'row': row_num,
                    'username': username,
                    'error': f'Password hashing failed: {str(e)}'
                })
                continue

            # Add user
            data["users"][username] = {
                "displayname": displayname,
                "password": password_hash,
                "email": email,
                "groups": groups
            }

            results['success'].append({
                'row': row_num,
                'username': username,
                'email': email,
                'groups': groups
            })

        # Save all changes
        if results['success']:
            try:
                save_users(data)
                log_audit("bulk_import", get_current_user(request),
                         details=f"Imported {len(results['success'])} users, "
                                f"Failed: {len(results['failed'])}, "
                                f"Skipped: {len(results['skipped'])}")
            except Exception as e:
                return jsonify({
                    "error": "Failed to save users",
                    "details": str(e),
                    "partial_results": results
                }), 500

        return jsonify({
            "message": f"Bulk import completed",
            "summary": {
                "success": len(results['success']),
                "failed": len(results['failed']),
                "skipped": len(results['skipped'])
            },
            "results": results
        }), 200 if not results['failed'] else 207  # 207 = Multi-Status

    except Exception as e:
        log_audit("bulk_import", get_current_user(request), success=False,
                 details=f"CSV parsing error: {str(e)}")
        return jsonify({
            "error": "Failed to parse CSV file",
            "details": str(e)
        }), 400


@app.route("/", methods=["GET"])
@app.route("/admin", methods=["GET"])
def admin_interface():
    """Serve the admin interface HTML"""
    try:
        with open("admin.html", "r") as f:
            return f.read(), 200, {"Content-Type": "text/html"}
    except Exception as e:
        return jsonify({"error": "Failed to load admin interface", "details": str(e)}), 500


if __name__ == "__main__":
    # This should not be used in production (use Gunicorn instead)
    app.run(host="0.0.0.0", port=5000, debug=False)
