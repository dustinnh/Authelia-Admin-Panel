# Security Hardening Guide

Production security best practices for Authelia File Admin deployments.

## Pre-Deployment Checklist

- [ ] Generate persistent `SECRET_KEY` and `AUDIT_HMAC_KEY` with `openssl rand -base64 32`
- [ ] Store secrets in `.env` file or sealed secrets manager (not in docker-compose.yml)
- [ ] Configure Authelia reverse proxy with forward_auth (no direct access)
- [ ] Set file permissions: users_database.yml 644, audit log dir 755
- [ ] Enable Authelia file watching: `authentication_backend.file.watch: true`
- [ ] Configure password policy matching your security requirements
- [ ] Set up SMTP for email notifications and security alerts
- [ ] Enable audit log monitoring and review procedures
- [ ] Plan audit log retention (rotate at 10MB, keep 5 backups)
- [ ] Document disaster recovery procedures

## Architecture Security

### 1. Network Isolation (Critical)

Deploy on an isolated internal Docker network with NO published ports:

**Correct** (production):
```yaml
services:
  authelia-file-admin:
    networks:
      - internal  # Private network only
    # NO ports: section
```

**Incorrect** (exposed):
```yaml
services:
  authelia-file-admin:
    ports:
      - "5000:5000"  # DANGER: Direct internet access!
    networks:
      - default
```

Access ONLY through your reverse proxy with Authelia forward_auth protection.

### 2. Authelia Forward Auth (Critical)

The ONLY authentication mechanism. Never bypass this:

**Caddy** (correct):
```caddyfile
admin.example.com {
    # ALL requests go through forward_auth
    forward_auth authelia:9091 {
        uri /api/verify?rd=https://admin.example.com/auth/
        copy_headers Remote-User Remote-Groups Remote-Name Remote-Email
    }
    reverse_proxy authelia-file-admin:5000
}
```

**Nginx** (correct):
```nginx
auth_request /auth;
auth_request_set $remote_user $upstream_http_remote_user;
auth_request_set $remote_groups $upstream_http_remote_groups;
```

**Never** set headers manually (even in development):
```bash
# WRONG - Anyone can claim to be admin!
curl -H "Remote-User: admin" http://localhost:5000/api/admin/users
```

### 3. File Permissions (Critical)

Ensure proper access controls:

```bash
# Users database (readable by container, not world-readable)
chmod 644 /path/to/users_database.yml
ls -la /path/to/users_database.yml
# -rw-r--r-- 1 user user 5000 Nov 20 14:30

# Audit log directory (writable by container only)
chmod 755 /path/to/logs/
chown 1000:1000 /path/to/logs/  # Match container user ID
ls -la | grep logs
# drwxr-xr-x 2 1000 1000 4096 Nov 20 14:30
```

Verify in container:
```bash
docker compose exec authelia-file-admin \
  ls -la /config/users_database.yml /var/log/authelia-admin-audit.jsonl
```

### 4. Secrets Management (Critical)

**Store secrets securely:**

```bash
# Generate ONE TIME with openssl
SECRET_KEY=$(openssl rand -base64 32)
AUDIT_HMAC_KEY=$(openssl rand -base64 32)

# Option 1: Docker secrets (Swarm/Kubernetes)
echo "$SECRET_KEY" | docker secret create secret_key -

# Option 2: .env file with restricted permissions
umask 0077
cat > .env << EOF
SECRET_KEY=$SECRET_KEY
AUDIT_HMAC_KEY=$AUDIT_HMAC_KEY
EOF
chmod 600 .env

# Option 3: Sealed Secrets (Kubernetes)
# Encrypt before committing to git
```

**NEVER commit to git:**
```bash
# .gitignore
.env
*.secrets
*secret*
```

**Key rotation procedure:**
1. Generate new keys
2. Update environment variables
3. Restart container
4. Previous CSRF tokens invalidate (expected)
5. Audit log HMAC verification fails for old entries (expected)

## Password Security Policy

### Recommended Policies

**Standard (most deployments)**:
```yaml
PASSWORD_MIN_LENGTH=12
PASSWORD_REQUIRE_UPPERCASE=true
PASSWORD_REQUIRE_LOWERCASE=true
PASSWORD_REQUIRE_DIGIT=true
PASSWORD_REQUIRE_SPECIAL=true
PASSWORD_CHECK_BREACH=true          # HaveIBeenPwned API
PASSWORD_HISTORY_COUNT=5            # Prevent password reuse
PASSWORD_EXPIRATION_DAYS=90         # 90-day rotation
```

**Strict (regulated industries: healthcare, finance)**:
```yaml
PASSWORD_MIN_LENGTH=16
PASSWORD_REQUIRE_UPPERCASE=true
PASSWORD_REQUIRE_LOWERCASE=true
PASSWORD_REQUIRE_DIGIT=true
PASSWORD_REQUIRE_SPECIAL=true
PASSWORD_CHECK_BREACH=true
PASSWORD_HISTORY_COUNT=12           # Remember last 12 passwords
PASSWORD_EXPIRATION_DAYS=60         # 60-day rotation
```

**Maximum Security**:
```yaml
PASSWORD_MIN_LENGTH=20
PASSWORD_REQUIRE_UPPERCASE=true
PASSWORD_REQUIRE_LOWERCASE=true
PASSWORD_REQUIRE_DIGIT=true
PASSWORD_REQUIRE_SPECIAL=true
PASSWORD_CHECK_BREACH=true
PASSWORD_HISTORY_COUNT=24           # Remember last 24 passwords
PASSWORD_EXPIRATION_DAYS=30         # Monthly change (difficult)
```

### Breach Detection (HaveIBeenPwned)

Enabled by default. Uses k-anonymity to check password safety:

```
1. Client hashes password with SHA1
2. Sends first 5 characters to API (k-anonymity)
3. API returns list of matching hashes
4. Client checks if full hash matches
5. Full password never sent to API
```

**Why this is safe**: API can't determine if password was compromised without the first 5 characters.

**Disable if needed**:
```yaml
PASSWORD_CHECK_BREACH=false  # For offline/isolated deployments
```

## Audit Logging & Compliance

### Audit Trail Contents

Every admin action is logged:

```bash
# View recent audit events
docker compose exec authelia-file-admin \
  tail -n 10 /var/log/authelia-admin-audit.jsonl | jq .

# Example audit entry:
{
  "timestamp": "2025-11-20T15:30:45.123456Z",
  "action": "create_user",
  "user": "admin",
  "target": "newuser",
  "details": "groups=users,email=newuser@example.com",
  "success": true,
  "ip": "10.0.0.5",
  "hmac": "a1b2c3d4e5f6..."  # Tamper detection
}
```

### Verify Audit Integrity

Check for tampering:

```bash
curl -H "Remote-User: admin" -H "Remote-Groups: admins" \
  http://authelia-file-admin:5000/api/admin/audit/verify

# Response:
{
  "total_entries": 156,
  "verified": 156,
  "failed": 0,
  "tampered_entries": []
}
```

**Interpretation**:
- `verified = total_entries`: All entries authenticated ✓
- `failed > 0`: Old entries before HMAC was enabled (expected)
- `tampered_entries`: Audit log has been modified (investigate!)

### Audit Log Retention

Automatic rotation at 10MB:

```bash
# View rotation
ls -la /var/log/authelia-admin-audit*

authelia-admin-audit.jsonl           # Current log
authelia-admin-audit.jsonl.1         # Backups (5 files kept)
authelia-admin-audit.jsonl.2
authelia-admin-audit.jsonl.3
authelia-admin-audit.jsonl.4
authelia-admin-audit.jsonl.5
```

**Retention strategy**:
- Current + 5 backups = ~60MB storage
- For compliance: Archive rotated logs off-system
- Set up log forwarding to SIEM (ELK, Splunk, Datadog)

### Monitoring Audit Logs

Set up alerts for suspicious activity:

```bash
# Failed operations
grep '"success": false' /var/log/authelia-admin-audit.jsonl

# Delete operations
grep '"action": "delete_user"' /var/log/authelia-admin-audit.jsonl

# Bulk imports
grep '"action": "bulk_import"' /var/log/authelia-admin-audit.jsonl

# Failed password changes
grep -E '"action": "change_password".*"success": false' /var/log/authelia-admin-audit.jsonl
```

## Email Notification Security

### SMTP Configuration

**Use TLS (encrypted):**
```yaml
SMTP_USE_TLS=true
SMTP_PORT=587  # TLS
```

**NOT unencrypted:**
```yaml
SMTP_USE_TLS=false
SMTP_PORT=25  # DANGER: Plaintext!
```

### Email Provider Security

**Gmail App Passwords**:
```yaml
SMTP_PASSWORD=your-16-char-app-password  # NOT your Gmail password!
```
Enable 2FA, then generate [App Password](https://myaccount.google.com/apppasswords)

**Office 365**:
Use modern authentication (app passwords or service principal)

**SendGrid**:
```yaml
SMTP_PASSWORD=SG.xxxxxxxxxxxxx  # API key, not password
```

### Notifications Sent

Notifications are sent for:
- User creation (to admin)
- Password change (to user)
- Password expiring (to user, 7 days before)
- Password expired (to user + admin)
- User deletion (to admin)

**Graceful failure**: Email failures don't block operations. If SMTP is down, operations continue and you just don't get notifications.

## Rate Limiting

Default limits protect against brute force:

```
GET /users:                  30 per minute
POST /users (create):        10 per minute
PUT /users/*/password:       10 per minute
DELETE /users/*:             20 per minute
GET /csrf-token:             30 per minute
POST /users/bulk/import:     5 per minute
```

These limits can be adjusted in `src/app.py` if needed:

```python
@limiter.limit("10 per minute")  # ← Adjust here
def create_user():
    ...
```

**Brute force protection**:
- Multiple failed password changes are logged
- Rate limiting prevents automated attacks
- Authelia forward_auth adds another auth layer

## Security Headers

Automatically set by Flask:

```
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'
X-XSS-Protection: 1; mode=block
```

**Do NOT disable** these headers in reverse proxy configuration.

## Input Validation & XSS Prevention

### Validation Rules

- **Usernames**: Alphanumeric + underscore, 3-32 chars
- **Emails**: RFC 5322 format
- **Groups**: Alphanumeric + underscore
- **Passwords**: No validation (all characters allowed after policy check)

Both client and server validate (defense in depth).

### HTML Escaping

All user input is escaped before display:

```javascript
// Frontend escaping
function escapeHtml(text) {
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return text.replace(/[&<>"']/g, m => map[m]);
}

// Backend escaping
html.escape(details)  # Python
```

**Never trust user input in logs or display.**

## CSRF Protection

All POST/PUT/DELETE requests require CSRF token:

```javascript
// Frontend must include token
const response = await fetch('/api/admin/users', {
    method: 'POST',
    headers: {
        'X-CSRFToken': csrfToken,  // ← Required
        'Content-Type': 'application/json'
    },
    body: JSON.stringify(userData)
});
```

**Flask-WTF** automatically validates tokens (transparent to you).

## File Locking

Concurrent access is safe:

```python
# Safe concurrent access
with locked_users_file():
    data = load_users()
    # ... modify ...
    save_users(data)
```

Lock prevents data corruption from simultaneous writes.

## Compliance Considerations

### GDPR
- Audit log documents all user data access
- `PASSWORD_HISTORY_COUNT` protects against weak passwords
- Email notifications are sent for security events
- No encrypted password hashes are logged

### HIPAA
- Requires `PASSWORD_EXPIRATION_DAYS=60` or less
- Requires strong passwords (`PASSWORD_REQUIRE_SPECIAL=true`)
- Audit logs provide accountability
- Set `AUDIT_LOG_PATH` to HIPAA-compliant storage

### PCI-DSS
- `PASSWORD_MIN_LENGTH=12` (requirement)
- `PASSWORD_EXPIRATION_DAYS=90` (requirement)
- `PASSWORD_HISTORY_COUNT=4` (minimum requirement)
- Strong password policy
- Audit logging with integrity checking

### SOC 2
- Audit trail of all admin actions
- Access control (Authelia forward_auth)
- Secrets management (persistent keys)
- File permissions (properly configured)
- Monitoring procedures (audit log review)

## Disaster Recovery

### Backup Strategy

```bash
# Back up critical files
rsync -av /path/to/authelia/users_database.yml \
          /backups/users_database.yml.$(date +%Y%m%d)

rsync -av /path/to/logs/admin/ \
          /backups/audit_logs.$(date +%Y%m%d)

# Back up secrets (in sealed/encrypted format)
gpg --encrypt --recipient key-id .env
rsync -av .env.gpg /backups/
```

### Restore Procedure

```bash
# 1. Stop the application
docker compose down authelia-file-admin

# 2. Restore users database
cp /backups/users_database.yml.20251120 /path/to/authelia/users_database.yml
chmod 644 /path/to/authelia/users_database.yml

# 3. Restart Authelia to reload
docker restart authelia

# 4. Restart the admin tool
docker compose up -d authelia-file-admin

# 5. Verify
docker compose logs authelia-file-admin | grep -i error
```

## Security Review Checklist

Before going to production:

- [ ] Network isolation: No published ports, only internal Docker network
- [ ] Forward auth: Authelia protecting all endpoints
- [ ] Secrets: Generated with openssl, stored in .env with 600 permissions
- [ ] File permissions: users_database.yml 644, logs dir 755
- [ ] Authelia file watching: `watch: true` in configuration
- [ ] Password policy: Matches security requirements
- [ ] Email notifications: SMTP configured with TLS
- [ ] Audit logging: Verified integrity with `/audit/verify`
- [ ] Rate limiting: Not disabled or set too high
- [ ] Security headers: Not disabled in reverse proxy
- [ ] Backup procedure: Tested and documented
- [ ] Incident response: Team knows how to respond to audit anomalies
- [ ] Monitoring: Audit logs reviewed regularly

## Next Steps

- **See [GETTING_STARTED.md](GETTING_STARTED.md)** for deployment
- **See [CONFIGURATION.md](CONFIGURATION.md)** for password policies
- **See [API_EXAMPLES.md](API_EXAMPLES.md)** for integration examples
