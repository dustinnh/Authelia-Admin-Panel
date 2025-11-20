# Configuration Reference

Quick reference for all environment variables and configuration options.

## Essential Variables

These MUST be set for production deployments:

```yaml
USERS_DB_PATH=/config/users_database.yml      # Path to Authelia users database
AUDIT_LOG_PATH=/var/log/authelia-admin-audit.jsonl  # Audit log location
SECRET_KEY=<generated-key>                     # Flask session secret (generate with: openssl rand -base64 32)
AUDIT_HMAC_KEY=<generated-key>                 # Audit log signing key (generate with: openssl rand -base64 32)
```

**Important**: These keys MUST persist across container restarts. Store in `.env` file or docker-compose.yml, not auto-generated.

## Password Policy Variables

Control password complexity requirements:

| Variable | Default | Options | Purpose |
|----------|---------|---------|---------|
| `PASSWORD_MIN_LENGTH` | 12 | 8-128 | Minimum password length |
| `PASSWORD_REQUIRE_UPPERCASE` | true | true/false | Require A-Z characters |
| `PASSWORD_REQUIRE_LOWERCASE` | true | true/false | Require a-z characters |
| `PASSWORD_REQUIRE_DIGIT` | true | true/false | Require 0-9 characters |
| `PASSWORD_REQUIRE_SPECIAL` | true | true/false | Require !@#$%^&* etc |
| `PASSWORD_CHECK_BREACH` | true | true/false | Check HaveIBeenPwned API |
| `PASSWORD_HISTORY_COUNT` | 5 | 0-20 | Prevent reuse of last N passwords (0=disabled) |
| `PASSWORD_EXPIRATION_DAYS` | 0 | 0-365 | Force password change every N days (0=disabled) |

### Configuration Examples

**Relaxed Policy** (small teams, high friction tolerance):
```yaml
PASSWORD_MIN_LENGTH=8
PASSWORD_REQUIRE_UPPERCASE=true
PASSWORD_REQUIRE_LOWERCASE=true
PASSWORD_REQUIRE_DIGIT=true
PASSWORD_REQUIRE_SPECIAL=false      # Allow simple passwords
PASSWORD_CHECK_BREACH=true          # Still check for breaches
PASSWORD_HISTORY_COUNT=0            # Allow password reuse
PASSWORD_EXPIRATION_DAYS=0          # No expiration requirement
```

**Balanced Policy** (recommended for most deployments):
```yaml
PASSWORD_MIN_LENGTH=12
PASSWORD_REQUIRE_UPPERCASE=true
PASSWORD_REQUIRE_LOWERCASE=true
PASSWORD_REQUIRE_DIGIT=true
PASSWORD_REQUIRE_SPECIAL=true
PASSWORD_CHECK_BREACH=true
PASSWORD_HISTORY_COUNT=5            # Remember last 5 passwords
PASSWORD_EXPIRATION_DAYS=90         # 90-day rotation
```

**Strict Policy** (regulated environments, compliance required):
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

### Validation in Real-Time UI

The admin interface shows live password validation:

```
Requirements Checklist:
✓ At least 12 characters
✓ Contains uppercase letter
✓ Contains lowercase letter
✓ Contains number
✓ Contains special character
○ Not in breach database (checking...)
```

Red X = requirement not met, green ✓ = requirement met.

## Email Notification Variables

**Requires**: SMTP server access (Gmail, Office365, SendGrid, etc.)

| Variable | Default | Purpose |
|----------|---------|---------|
| `EMAIL_ENABLED` | false | Enable all email notifications |
| `SMTP_HOST` | localhost | SMTP server hostname |
| `SMTP_PORT` | 587 | SMTP port (587 for TLS, 465 for SSL) |
| `SMTP_USERNAME` | (none) | SMTP authentication username |
| `SMTP_PASSWORD` | (none) | SMTP authentication password |
| `SMTP_FROM_EMAIL` | noreply@authelia-admin.local | Sender email address |
| `SMTP_FROM_NAME` | Authelia Admin | Sender display name |
| `SMTP_USE_TLS` | true | Use TLS encryption |
| `ADMIN_EMAIL` | (none) | Admin email for security notifications |

### Email Provider Setup Examples

**Gmail**:
```yaml
EMAIL_ENABLED=true
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-16-char-app-password  # NOT your Gmail password!
SMTP_FROM_EMAIL=your-email@gmail.com
SMTP_USE_TLS=true
ADMIN_EMAIL=sysadmin@company.com
```

**Office 365**:
```yaml
EMAIL_ENABLED=true
SMTP_HOST=smtp.office365.com
SMTP_PORT=587
SMTP_USERNAME=your-email@company.onmicrosoft.com
SMTP_PASSWORD=your-password
SMTP_FROM_EMAIL=your-email@company.onmicrosoft.com
SMTP_USE_TLS=true
ADMIN_EMAIL=sysadmin@company.com
```

**SendGrid**:
```yaml
EMAIL_ENABLED=true
SMTP_HOST=smtp.sendgrid.net
SMTP_PORT=587
SMTP_USERNAME=apikey
SMTP_PASSWORD=SG.xxxxxxxxxxxxxxx  # Your SendGrid API key
SMTP_FROM_EMAIL=noreply@company.com
SMTP_USE_TLS=true
ADMIN_EMAIL=sysadmin@company.com
```

### Notifications Sent

- **User Created**: New user email + admin notification
- **Password Changed**: User email (password age reset)
- **Password Expiring**: User email (7 days before expiration, if enabled)
- **Password Expired**: User email + admin notification
- **User Deleted**: Admin notification

Failures are logged but don't block operations (graceful degradation).

## Docker Compose Configuration Template

Save as `.env` file alongside docker-compose.yml:

```bash
# Generated secrets (save these!)
SECRET_KEY=$(openssl rand -base64 32)
AUDIT_HMAC_KEY=$(openssl rand -base64 32)

# Paths
USERS_DB_PATH=/config/users_database.yml
AUDIT_LOG_PATH=/var/log/authelia-admin-audit.jsonl

# Password policy (uncomment to customize)
# PASSWORD_MIN_LENGTH=12
# PASSWORD_REQUIRE_UPPERCASE=true
# PASSWORD_REQUIRE_LOWERCASE=true
# PASSWORD_REQUIRE_DIGIT=true
# PASSWORD_REQUIRE_SPECIAL=true
# PASSWORD_CHECK_BREACH=true
# PASSWORD_HISTORY_COUNT=5
# PASSWORD_EXPIRATION_DAYS=90

# Email (uncomment and configure to enable)
# EMAIL_ENABLED=true
# SMTP_HOST=smtp.gmail.com
# SMTP_PORT=587
# SMTP_USERNAME=your-email@gmail.com
# SMTP_PASSWORD=your-app-password
# SMTP_FROM_EMAIL=noreply@company.com
# SMTP_FROM_NAME=Authelia Admin
# SMTP_USE_TLS=true
# ADMIN_EMAIL=sysadmin@company.com
```

Then in `docker-compose.yml`:

```yaml
services:
  authelia-file-admin:
    # ... other config ...
    environment:
      - USERS_DB_PATH=${USERS_DB_PATH}
      - AUDIT_LOG_PATH=${AUDIT_LOG_PATH}
      - SECRET_KEY=${SECRET_KEY}
      - AUDIT_HMAC_KEY=${AUDIT_HMAC_KEY}
      # Add any password policy overrides here
      # - PASSWORD_EXPIRATION_DAYS=90
```

Load with:
```bash
set -a
source .env
set +a
docker compose up -d
```

## Validating Configuration

### Check Loaded Configuration

See what values the application loaded:

```bash
# Health endpoint shows enabled features
curl -H "Remote-User: admin" -H "Remote-Groups: admins" \
  http://authelia-file-admin:5000/health

# Response includes features array:
# "features": ["password_expiration", "email_notifications", "audit_logging", "password_history"]
```

### Test Password Policy

Use the web interface to test:

1. Click **"Create New User"**
2. Type in **Password** field
3. Watch the **Requirements Checklist** update in real-time
4. Should match your configured policy

### Test Email Configuration

Add a test user with an email address, then:

1. Change user's password
2. Check that user received email notification
3. Check logs for SMTP errors:

```bash
docker compose logs authelia-file-admin | grep -i smtp
docker compose logs authelia-file-admin | grep -i email
```

Expected logs (no errors):
```
Sending email to testuser@example.com
Email sent successfully for action: password_changed
```

## Common Configuration Tasks

### Disable Password Breach Checking

Use this if your deployment can't access the internet or you want faster operations:

```yaml
PASSWORD_CHECK_BREACH=false
```

### Require Strong Passwords Immediately

```yaml
PASSWORD_MIN_LENGTH=16
PASSWORD_REQUIRE_SPECIAL=true
PASSWORD_HISTORY_COUNT=10
```

### Enable Strict Compliance Mode

```yaml
PASSWORD_EXPIRATION_DAYS=60        # Force password change every 60 days
PASSWORD_HISTORY_COUNT=12          # Can't reuse last 12 passwords
PASSWORD_CHECK_BREACH=true
PASSWORD_REQUIRE_UPPERCASE=true
PASSWORD_REQUIRE_LOWERCASE=true
PASSWORD_REQUIRE_DIGIT=true
PASSWORD_REQUIRE_SPECIAL=true
ADMIN_EMAIL=compliance@company.com # Notify on user creation/deletion
```

### Minimize Friction (Development/Testing Only)

```yaml
PASSWORD_MIN_LENGTH=8
PASSWORD_REQUIRE_UPPERCASE=false
PASSWORD_REQUIRE_LOWERCASE=false
PASSWORD_REQUIRE_DIGIT=false
PASSWORD_REQUIRE_SPECIAL=false
PASSWORD_CHECK_BREACH=false
PASSWORD_HISTORY_COUNT=0
PASSWORD_EXPIRATION_DAYS=0
EMAIL_ENABLED=false
```

## Environment Variable Hierarchy

If you set the same variable in multiple places, priority is:

1. **Container environment** (highest): `docker compose up -e VAR=value`
2. **docker-compose.yml `environment:` section**
3. **.env file** (if using `source .env`)
4. **Built-in defaults** (lowest)

## Secrets Rotation

To rotate `SECRET_KEY` or `AUDIT_HMAC_KEY`:

1. Generate new keys:
   ```bash
   openssl rand -base64 32  # For SECRET_KEY
   openssl rand -base64 32  # For AUDIT_HMAC_KEY
   ```

2. Update docker-compose.yml with new values

3. Restart container:
   ```bash
   docker compose up -d authelia-file-admin
   ```

**Side effects**:
- Existing CSRF tokens become invalid (users must refresh page)
- Audit logs with old HMAC signatures fail verification (expected)
- New entries will have new HMAC signatures

## Troubleshooting Configuration

### "Configuration value not taking effect"

1. Check it was loaded:
   ```bash
   docker compose exec authelia-file-admin env | grep YOUR_VAR
   ```

2. Restart the container:
   ```bash
   docker compose restart authelia-file-admin
   ```

3. Configuration changes require restart, they're not hot-reloaded.

### "Password policy is rejecting all passwords"

Test each requirement separately:

```bash
# Disable breach checking first (often the culprit)
PASSWORD_CHECK_BREACH=false

# Then test password creation
```

Check logs:
```bash
docker compose logs authelia-file-admin | grep -i password | head -20
```

### "Email not sending, but no errors in logs"

1. Verify email is enabled:
   ```bash
   docker compose exec authelia-file-admin env | grep EMAIL
   ```

2. Test SMTP connectivity:
   ```bash
   docker compose exec authelia-file-admin python3 -c \
     "import smtplib; s=smtplib.SMTP('$SMTP_HOST', $SMTP_PORT); print('Connected')"
   ```

3. Check credentials in error logs:
   ```bash
   docker compose logs authelia-file-admin | grep -i "authentication failed"
   ```

## Next Steps

- **See [GETTING_STARTED.md](GETTING_STARTED.md)** for deployment walkthrough
- **See [SECURITY.md](SECURITY.md)** for hardening recommendations
- **See [API_EXAMPLES.md](API_EXAMPLES.md)** for integration examples
