# Getting Started with Authelia File Admin

Quick setup guide for deploying Authelia File Admin in your environment.

## Prerequisites

- **Docker** (v20.10+) and Docker Compose (v2.0+)
- **Authelia** instance running with file-based authentication (`users_database.yml`)
- **Reverse Proxy** (Caddy, Nginx, Traefik) with forward_auth capability
- **Authelia Config** must have `watch: true` enabled for file watching

## Quick Deployment (5 minutes)

### Step 1: Generate Secrets

Generate persistent secrets that won't reset on container restart:

```bash
SECRET_KEY=$(openssl rand -base64 32)
AUDIT_HMAC_KEY=$(openssl rand -base64 32)

echo "SECRET_KEY=$SECRET_KEY"
echo "AUDIT_HMAC_KEY=$AUDIT_HMAC_KEY"
```

Save these values—you'll need them in your environment or docker-compose.yml.

### Step 2: Create Docker Compose File

Save as `docker-compose.yml` in your Authelia stack directory:

```yaml
version: '3.8'

services:
  authelia-file-admin:
    image: authelia-file-admin:latest  # Or build: ./authelia-file-admin
    container_name: authelia-file-admin
    restart: unless-stopped
    networks:
      - internal
    volumes:
      - ./authelia:/config              # Authelia config directory
      - ./logs/admin:/var/log            # Audit logs
    environment:
      - USERS_DB_PATH=/config/users_database.yml
      - AUDIT_LOG_PATH=/var/log/authelia-admin-audit.jsonl
      - SECRET_KEY=${SECRET_KEY}         # From Step 1
      - AUDIT_HMAC_KEY=${AUDIT_HMAC_KEY} # From Step 1
      - PASSWORD_EXPIRATION_DAYS=90      # Optional: enable password rotation
      - EMAIL_ENABLED=false              # Enable when SMTP ready
    depends_on:
      - authelia

networks:
  internal:
    external: true
```

### Step 3: Configure Reverse Proxy

**Caddy example** (add to your Caddyfile):

```caddyfile
admin.example.com {
    handle_path /api/admin/* {
        forward_auth authelia:9091 {
            uri /api/verify?rd=https://admin.example.com/auth/
            copy_headers Remote-User Remote-Groups Remote-Name Remote-Email
        }
        reverse_proxy authelia-file-admin:5000
    }

    handle {
        forward_auth authelia:9091 {
            uri /api/verify?rd=https://admin.example.com/auth/
            copy_headers Remote-User Remote-Groups Remote-Name Remote-Email
        }
        reverse_proxy authelia-file-admin:5000
    }
}
```

**Nginx example** (add to your config):

```nginx
location /api/admin/ {
    proxy_pass http://authelia-file-admin:5000;
    proxy_set_header Remote-User $remote_user;
    proxy_set_header Remote-Groups $remote_groups;

    # Forward auth with Authelia
    auth_request /auth;
    auth_request_set $remote_user $upstream_http_remote_user;
    auth_request_set $remote_groups $upstream_http_remote_groups;
}

location = /auth {
    internal;
    proxy_pass http://authelia:9091/api/verify?rd=https://admin.example.com/auth/;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
}
```

### Step 4: Start Services

```bash
# Create log directory if needed
mkdir -p logs/admin

# Start the container
docker compose up -d authelia-file-admin

# Watch logs
docker compose logs -f authelia-file-admin
```

### Step 5: Verify Installation

Check the health endpoint (requires forward_auth from your reverse proxy):

```bash
curl -H "Remote-User: admin" -H "Remote-Groups: admins" \
  http://authelia-file-admin:5000/health
```

Expected response:
```json
{
  "status": "healthy",
  "version": "1.10.0",
  "features": ["password_expiration", "email_notifications", "audit_logging"]
}
```

Access the web interface: **https://admin.example.com**

## First-Time Setup Walkthrough

### 1. Log In
- Enter Authelia credentials (must be admin)
- You're authenticated via forward_auth from your reverse proxy
- No local login credentials needed

### 2. Dashboard Overview
- **Statistics cards**: Total users, admin count, regular users
- **Password health** (if `PASSWORD_EXPIRATION_DAYS > 0`): Expired, expiring soon, healthy
- **User table**: All users with password status

### 3. Create Your First Test User

Click **"Create New User"** button:
- **Username**: `testuser`
- **Display Name**: `Test User`
- **Email**: `test@example.com`
- **Groups**: Leave empty or add `users`
- **Password**: Generate one (uses real-time validation)
  - Must be 12+ characters
  - At least 1 uppercase, 1 lowercase, 1 digit, 1 special character
  - Green checkmark = ready to save

Click **Save User**

### 4. Verify in Authelia

Check that the user appears in Authelia's login:

```bash
# View the users database
docker exec authelia cat /config/users_database.yml | grep -A 5 "testuser"
```

Wait 5-10 seconds for Authelia's file watcher to reload. Then try logging in with `testuser`.

### 5. Audit Trail

View what was logged:

```bash
docker compose exec authelia-file-admin \
  tail -n 5 /var/log/authelia-admin-audit.jsonl | jq .
```

You should see a `create_user` event with timestamp, user, target, and HMAC signature.

## Common Post-Deployment Tasks

### Verify Authelia File Watching

**Required**: Authelia must have `watch: true` enabled:

```bash
# Check Authelia config
docker exec authelia cat /config/configuration.yml | grep -A 3 "authentication_backend"
```

Look for:
```yaml
authentication_backend:
  file:
    watch: true  # ← Must be present
    path: /config/users_database.yml
```

If missing, add it and restart Authelia:
```bash
docker restart authelia
```

### Fix Permission Errors

If you see `Permission denied` errors when creating users:

```bash
# Fix users database permissions
chmod 644 /path/to/authelia/users_database.yml

# Fix audit log directory
chmod 755 logs/admin
chown 1000:1000 logs/admin  # Container user ID
```

### Enable Email Notifications (Optional)

Set in docker-compose.yml:

```yaml
environment:
  - EMAIL_ENABLED=true
  - SMTP_HOST=smtp.gmail.com
  - SMTP_PORT=587
  - SMTP_USERNAME=your-email@gmail.com
  - SMTP_PASSWORD=your-app-password
  - SMTP_FROM_EMAIL=admin@example.com
  - ADMIN_EMAIL=sysadmin@example.com
```

Restart:
```bash
docker compose up -d authelia-file-admin
```

### Enable Password Expiration (Optional)

Add to docker-compose.yml to require password changes every 90 days:

```yaml
environment:
  - PASSWORD_EXPIRATION_DAYS=90
```

The dashboard will show password health metrics once enabled.

## Troubleshooting

### "Page shows 'Unauthorized' or '403 Forbidden'"

The reverse proxy isn't passing forward_auth headers correctly.

1. Check reverse proxy logs for auth failures
2. Verify `Remote-User` and `Remote-Groups` headers are being copied
3. Ensure Authelia remote user is an admin in their groups

### "Create User button does nothing"

CSRF token isn't loading.

```bash
# Check if endpoint responds
curl -H "Remote-User: admin" http://authelia-file-admin:5000/api/admin/csrf-token
```

If empty response, check Flask logs:
```bash
docker compose logs authelia-file-admin | grep -i csrf
```

### "User appears in admin tool but not in Authelia"

File watching isn't enabled in Authelia.

```bash
# Check Authelia config
docker exec authelia cat /config/configuration.yml | grep "watch:"
```

If `watch: false`, enable it and restart Authelia:
```bash
docker restart authelia
```

### File Permission Denied Errors

```bash
# Check current permissions
ls -la /path/to/authelia/users_database.yml
ls -la logs/admin/

# Fix them
chmod 644 /path/to/authelia/users_database.yml
chmod 755 logs/admin
```

## Next Steps

1. **Read the Configuration guide** to set password policies and email notifications
2. **Review Security guide** for production hardening
3. **Check API Examples** to automate user management
4. **Set up audit log monitoring** for compliance

See the [README.md](../README.md) for comprehensive reference documentation.
