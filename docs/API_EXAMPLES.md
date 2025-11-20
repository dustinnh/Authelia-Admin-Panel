# API Integration Examples

Practical code examples for integrating with Authelia File Admin API.

## Authentication

All API requests require forward_auth headers from Authelia. The reverse proxy handles this automatically.

For direct API testing, you must include Authelia headers:

```bash
curl -H "Remote-User: admin" \
     -H "Remote-Groups: admins" \
     -H "Remote-Name: Administrator" \
     -H "Remote-Email: admin@example.com" \
     http://authelia-file-admin:5000/api/admin/users
```

Headers required:
- `Remote-User`: Username (from Authelia)
- `Remote-Groups`: Comma-separated groups (must include "admins" for admin endpoints)

## Common Operations

### 1. Get CSRF Token

Required before POST/PUT/DELETE requests:

**cURL**:
```bash
curl -H "Remote-User: admin" -H "Remote-Groups: admins" \
  http://authelia-file-admin:5000/api/admin/csrf-token | jq .csrf_token -r
```

**Python**:
```python
import requests

headers = {
    "Remote-User": "admin",
    "Remote-Groups": "admins"
}

response = requests.get(
    "http://authelia-file-admin:5000/api/admin/csrf-token",
    headers=headers
)
csrf_token = response.json()["csrf_token"]
print(f"CSRF Token: {csrf_token}")
```

**JavaScript**:
```javascript
const headers = {
    "Remote-User": "admin",
    "Remote-Groups": "admins"
};

const response = await fetch(
    "http://authelia-file-admin:5000/api/admin/csrf-token",
    { headers }
);
const data = await response.json();
const csrfToken = data.csrf_token;
console.log(`CSRF Token: ${csrfToken}`);
```

### 2. List All Users

**cURL**:
```bash
curl -H "Remote-User: admin" -H "Remote-Groups: admins" \
  http://authelia-file-admin:5000/api/admin/users | jq .
```

Response includes password metadata:
```json
{
  "users": [
    {
      "username": "john",
      "display_name": "John Doe",
      "email": "john@example.com",
      "groups": ["users", "developers"],
      "password_age_days": 45,
      "password_expired": false,
      "password_last_changed": "2025-10-06T14:32:00Z"
    }
  ]
}
```

**Python**:
```python
import requests
import json

headers = {
    "Remote-User": "admin",
    "Remote-Groups": "admins"
}

response = requests.get(
    "http://authelia-file-admin:5000/api/admin/users",
    headers=headers
)
users = response.json()["users"]

for user in users:
    print(f"{user['username']}: {user['email']} (groups: {', '.join(user['groups'])})")
    print(f"  Password age: {user['password_age_days']} days")
    print(f"  Expired: {user['password_expired']}")
```

**JavaScript**:
```javascript
const headers = {
    "Remote-User": "admin",
    "Remote-Groups": "admins"
};

const response = await fetch(
    "http://authelia-file-admin:5000/api/admin/users",
    { headers }
);
const data = await response.json();

data.users.forEach(user => {
    console.log(`${user.username}: ${user.email}`);
    console.log(`  Password age: ${user.password_age_days} days`);
    console.log(`  Expired: ${user.password_expired}`);
});
```

### 3. Create a New User

**cURL**:
```bash
CSRF_TOKEN=$(curl -s -H "Remote-User: admin" -H "Remote-Groups: admins" \
  http://authelia-file-admin:5000/api/admin/csrf-token | jq -r .csrf_token)

curl -X POST -H "Remote-User: admin" -H "Remote-Groups: admins" \
  -H "Content-Type: application/json" \
  -H "X-CSRFToken: $CSRF_TOKEN" \
  -d '{
    "username": "newuser",
    "display_name": "New User",
    "email": "newuser@example.com",
    "password": "SecurePass123!@#",
    "groups": ["users"]
  }' \
  http://authelia-file-admin:5000/api/admin/users
```

**Python**:
```python
import requests

headers = {
    "Remote-User": "admin",
    "Remote-Groups": "admins"
}

# Get CSRF token
csrf_response = requests.get(
    "http://authelia-file-admin:5000/api/admin/csrf-token",
    headers=headers
)
csrf_token = csrf_response.json()["csrf_token"]

# Create user
headers["X-CSRFToken"] = csrf_token
headers["Content-Type"] = "application/json"

user_data = {
    "username": "newuser",
    "display_name": "New User",
    "email": "newuser@example.com",
    "password": "SecurePass123!@#",
    "groups": ["users"]
}

response = requests.post(
    "http://authelia-file-admin:5000/api/admin/users",
    headers=headers,
    json=user_data
)

if response.status_code == 201:
    print(f"User created: {response.json()['username']}")
else:
    print(f"Error: {response.json()['error']}")
```

**JavaScript**:
```javascript
async function createUser() {
    const headers = {
        "Remote-User": "admin",
        "Remote-Groups": "admins"
    };

    // Get CSRF token
    const csrfResponse = await fetch(
        "http://authelia-file-admin:5000/api/admin/csrf-token",
        { headers }
    );
    const csrfToken = (await csrfResponse.json()).csrf_token;

    // Create user
    const response = await fetch(
        "http://authelia-file-admin:5000/api/admin/users",
        {
            method: "POST",
            headers: {
                ...headers,
                "X-CSRFToken": csrfToken,
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                username: "newuser",
                display_name: "New User",
                email: "newuser@example.com",
                password: "SecurePass123!@#",
                groups: ["users"]
            })
        }
    );

    if (response.ok) {
        const data = await response.json();
        console.log(`User created: ${data.username}`);
    } else {
        const error = await response.json();
        console.error(`Error: ${error.error}`);
    }
}
```

### 4. Change User Password

**cURL**:
```bash
CSRF_TOKEN=$(curl -s -H "Remote-User: admin" -H "Remote-Groups: admins" \
  http://authelia-file-admin:5000/api/admin/csrf-token | jq -r .csrf_token)

curl -X PUT -H "Remote-User: admin" -H "Remote-Groups: admins" \
  -H "Content-Type: application/json" \
  -H "X-CSRFToken: $CSRF_TOKEN" \
  -d '{"password": "NewPass456!@#"}' \
  http://authelia-file-admin:5000/api/admin/users/testuser/password
```

**Python**:
```python
import requests

def change_user_password(username, new_password):
    headers = {
        "Remote-User": "admin",
        "Remote-Groups": "admins"
    }

    # Get CSRF token
    csrf_response = requests.get(
        "http://authelia-file-admin:5000/api/admin/csrf-token",
        headers=headers
    )
    csrf_token = csrf_response.json()["csrf_token"]

    # Change password
    headers["X-CSRFToken"] = csrf_token
    headers["Content-Type"] = "application/json"

    response = requests.put(
        f"http://authelia-file-admin:5000/api/admin/users/{username}/password",
        headers=headers,
        json={"password": new_password}
    )

    if response.status_code == 200:
        print(f"Password changed for {username}")
    else:
        print(f"Error: {response.json()['error']}")

change_user_password("testuser", "NewPass456!@#")
```

**JavaScript**:
```javascript
async function changePassword(username, newPassword) {
    const headers = {
        "Remote-User": "admin",
        "Remote-Groups": "admins"
    };

    // Get CSRF token
    const csrfResponse = await fetch(
        "http://authelia-file-admin:5000/api/admin/csrf-token",
        { headers }
    );
    const csrfToken = (await csrfResponse.json()).csrf_token;

    // Change password
    const response = await fetch(
        `http://authelia-file-admin:5000/api/admin/users/${username}/password`,
        {
            method: "PUT",
            headers: {
                ...headers,
                "X-CSRFToken": csrfToken,
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ password: newPassword })
        }
    );

    if (response.ok) {
        console.log(`Password changed for ${username}`);
    } else {
        const error = await response.json();
        console.error(`Error: ${error.error}`);
    }
}

changePassword("testuser", "NewPass456!@#");
```

### 5. Delete a User

**cURL**:
```bash
CSRF_TOKEN=$(curl -s -H "Remote-User: admin" -H "Remote-Groups: admins" \
  http://authelia-file-admin:5000/api/admin/csrf-token | jq -r .csrf_token)

curl -X DELETE -H "Remote-User: admin" -H "Remote-Groups: admins" \
  -H "X-CSRFToken: $CSRF_TOKEN" \
  http://authelia-file-admin:5000/api/admin/users/testuser
```

**Python**:
```python
import requests

def delete_user(username):
    headers = {
        "Remote-User": "admin",
        "Remote-Groups": "admins"
    }

    # Get CSRF token
    csrf_response = requests.get(
        "http://authelia-file-admin:5000/api/admin/csrf-token",
        headers=headers
    )
    csrf_token = csrf_response.json()["csrf_token"]

    # Delete user
    headers["X-CSRFToken"] = csrf_token

    response = requests.delete(
        f"http://authelia-file-admin:5000/api/admin/users/{username}",
        headers=headers
    )

    if response.status_code == 200:
        print(f"User deleted: {username}")
    else:
        print(f"Error: {response.json()['error']}")

delete_user("testuser")
```

**JavaScript**:
```javascript
async function deleteUser(username) {
    const headers = {
        "Remote-User": "admin",
        "Remote-Groups": "admins"
    };

    // Get CSRF token
    const csrfResponse = await fetch(
        "http://authelia-file-admin:5000/api/admin/csrf-token",
        { headers }
    );
    const csrfToken = (await csrfResponse.json()).csrf_token;

    // Delete user
    const response = await fetch(
        `http://authelia-file-admin:5000/api/admin/users/${username}`,
        {
            method: "DELETE",
            headers: {
                ...headers,
                "X-CSRFToken": csrfToken
            }
        }
    );

    if (response.ok) {
        console.log(`User deleted: ${username}`);
    } else {
        const error = await response.json();
        console.error(`Error: ${error.error}`);
    }
}

deleteUser("testuser");
```

### 6. Get Dashboard Statistics

**cURL**:
```bash
curl -H "Remote-User: admin" -H "Remote-Groups: admins" \
  http://authelia-file-admin:5000/api/admin/stats | jq .
```

Response:
```json
{
  "total_users": 25,
  "admin_users": 3,
  "regular_users": 22,
  "groups": {
    "admins": 3,
    "users": 20,
    "developers": 5
  },
  "password_stats": {
    "expired": 2,
    "expiring_soon": 5,
    "healthy": 18
  }
}
```

**Python**:
```python
import requests
import json

headers = {
    "Remote-User": "admin",
    "Remote-Groups": "admins"
}

response = requests.get(
    "http://authelia-file-admin:5000/api/admin/stats",
    headers=headers
)
stats = response.json()

print(f"Total users: {stats['total_users']}")
print(f"Admin users: {stats['admin_users']}")
print(f"Regular users: {stats['regular_users']}")
print(f"\nPassword Health:")
print(f"  Expired: {stats['password_stats']['expired']}")
print(f"  Expiring soon: {stats['password_stats']['expiring_soon']}")
print(f"  Healthy: {stats['password_stats']['healthy']}")
```

### 7. Export Users to CSV

**cURL**:
```bash
curl -H "Remote-User: admin" -H "Remote-Groups: admins" \
  http://authelia-file-admin:5000/api/admin/users/export \
  -o users.csv
```

**Python**:
```python
import requests

headers = {
    "Remote-User": "admin",
    "Remote-Groups": "admins"
}

response = requests.get(
    "http://authelia-file-admin:5000/api/admin/users/export",
    headers=headers
)

with open("users.csv", "w") as f:
    f.write(response.text)

print("Users exported to users.csv")
```

### 8. Bulk Import Users from CSV

**cURL**:
```bash
# Create CSV file
cat > import.csv << 'EOF'
username,display_name,email,password,groups
alice,Alice Smith,alice@example.com,SecurePass123!@#,users
bob,Bob Jones,bob@example.com,SecurePass456!@#,users;developers
charlie,Charlie Brown,charlie@example.com,SecurePass789!@#,users;admins
EOF

CSRF_TOKEN=$(curl -s -H "Remote-User: admin" -H "Remote-Groups: admins" \
  http://authelia-file-admin:5000/api/admin/csrf-token | jq -r .csrf_token)

curl -X POST -H "Remote-User: admin" -H "Remote-Groups: admins" \
  -H "X-CSRFToken: $CSRF_TOKEN" \
  -F "file=@import.csv" \
  http://authelia-file-admin:5000/api/admin/users/bulk/import
```

**Python**:
```python
import requests

headers = {
    "Remote-User": "admin",
    "Remote-Groups": "admins"
}

# Get CSRF token
csrf_response = requests.get(
    "http://authelia-file-admin:5000/api/admin/csrf-token",
    headers=headers
)
csrf_token = csrf_response.json()["csrf_token"]

# Bulk import
headers["X-CSRFToken"] = csrf_token

with open("import.csv", "rb") as f:
    files = {"file": f}
    response = requests.post(
        "http://authelia-file-admin:5000/api/admin/users/bulk/import",
        headers=headers,
        files=files
    )

result = response.json()
print(f"Created: {result['created']}")
print(f"Failed: {result['failed']}")
if result['failed'] > 0:
    print(f"Errors: {result['errors']}")
```

## Rate Limiting

API endpoints have rate limits:

| Endpoint | Limit | Window |
|----------|-------|--------|
| `GET /users` | 30 | per minute |
| `POST /users` | 10 | per minute |
| `PUT /users/*/password` | 10 | per minute |
| `DELETE /users/*` | 20 | per minute |
| `/api/admin/csrf-token` | 30 | per minute |

If you exceed the limit, you'll get a 429 response:
```json
{
  "error": "Rate limit exceeded"
}
```

**Handling in code**:

```python
import requests
import time

def create_user_with_retry(user_data, max_retries=3):
    for attempt in range(max_retries):
        try:
            response = requests.post(
                "http://authelia-file-admin:5000/api/admin/users",
                headers=headers,
                json=user_data
            )

            if response.status_code == 429:
                wait_time = int(response.headers.get('Retry-After', 60))
                print(f"Rate limited. Waiting {wait_time}s...")
                time.sleep(wait_time)
                continue

            return response
        except Exception as e:
            print(f"Attempt {attempt + 1} failed: {e}")
            if attempt < max_retries - 1:
                time.sleep(5)

    raise Exception("Failed after max retries")
```

## Error Handling

Always check response status codes:

```python
response = requests.post(...)

if response.status_code == 201:
    print("User created successfully")
elif response.status_code == 400:
    # Invalid input
    error = response.json()
    print(f"Validation error: {error['details']}")
elif response.status_code == 403:
    # Authorization failed
    print("Not authorized to perform this action")
elif response.status_code == 500:
    # Server error
    print(f"Server error: {response.json()['error']}")
```

## Next Steps

- **See [GETTING_STARTED.md](GETTING_STARTED.md)** for deployment
- **See [CONFIGURATION.md](CONFIGURATION.md)** for password policies
- **See [SECURITY.md](SECURITY.md)** for production hardening
