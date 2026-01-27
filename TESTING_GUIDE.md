# OAuth2 Testing Guide

This comprehensive guide covers all testing scenarios for the OAuth2 implementation, including client credentials flow, form login, and authorization code flow.

## Table of Contents

1. [Setup Instructions](#setup-instructions)
2. [Client Credentials Flow Testing](#client-credentials-flow-testing)
3. [Form Login Testing](#form-login-testing)
4. [Authorization Code Flow Testing](#authorization-code-flow-testing)
5. [Testing with Postman](#testing-with-postman)
6. [Troubleshooting](#troubleshooting)
7. [Complete Test Script](#complete-test-script)

## Setup Instructions

### Start Both Servers

**Terminal 1** - Auth Server:
```bash
cd oauth2-authserver
mvn spring-boot:run
```

**Terminal 2** - Resource Server:  
```bash
cd microservice1
mvn spring-boot:run
```

### Available Clients

| Client ID | Secret | Role | Endpoint Access |
|-----------|--------|------|-----------------|
| inventoryclient | secret123 | ROLE_ADMIN | /endpoint1 ✅ |
| cartopsclient | secret456 | ROLE_USER | /endpoint2 ✅ |
| reportsclient | secret789 | ROLE_MANAGER | /endpoint3 ✅ |

### Available Users

| Username | Password | Role | Endpoint Access |
|----------|----------|------|-----------------|
| admin | admin123 | ROLE_ADMIN | /endpoint1 ✅ |
| john.doe | password123 | ROLE_CUSTOMER | /customer ✅ |
| alice.smith | alice123 | ROLE_CUSTOMER | /customer ✅ |
| bob.jones | bob123 | ROLE_CUSTOMER | /customer ✅ |

## Client Credentials Flow Testing

### 1. Get Token for inventoryclient (ROLE_ADMIN)

```bash
curl -X POST http://localhost:8443/oauth2/token \
  -u inventoryclient:secret123 \
  -d "grant_type=client_credentials"
```

**Response:**
```json
{
  "access_token": "eyJraWQiOi...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

### 2. Use Token to Access endpoint1

```bash
# Copy the access_token from above and use it here:
curl http://localhost:8080/endpoint1 \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN_HERE"
```

**Expected Response:**
```json
{
  "message": "Access Granted to Endpoint 1 (ADMIN)",
  "authorities": ["ROLE_ADMIN", "SCOPE_read", "SCOPE_write", "SCOPE_delete"]
}
```

### 3. Test Other Clients

**Get token for cartopsclient (ROLE_USER)**:
```bash
curl -X POST http://localhost:8443/oauth2/token \
  -u cartopsclient:secret456 \
  -d "grant_type=client_credentials"
```

**Get token for reportsclient (ROLE_MANAGER)**:
```bash
curl -X POST http://localhost:8443/oauth2/token \
  -u reportsclient:secret789 \
  -d "grant_type=client_credentials"
```

### 4. Test Authorization Failures

**inventoryclient trying /endpoint2 (should fail)**:
```bash
TOKEN=$(curl -s -X POST http://localhost:8443/oauth2/token \
  -u inventoryclient:secret123 \
  -d "grant_type=client_credentials" | jq -r '.access_token')

curl -w "HTTP %{http_code}\n" http://localhost:8080/endpoint2 \
  -H "Authorization: Bearer $TOKEN"
```

**Expected**: `HTTP 403` (ADMIN cannot access USER endpoint)

## Form Login Testing

### 1. Admin User (Has ROLE_ADMIN)

1. **Open browser:**
   ```
   http://localhost:8443/login
   ```

2. **Login with admin:**
   - Username: `admin`
   - Password: `admin123`

3. **After clicking "Sign in":**
   - ✅ Redirected to `http://localhost:8080/endpoint1`
   - ✅ Shows: "Access Granted to Endpoint 1 (ADMIN)"

### 2. Customer User (Has ROLE_CUSTOMER)

1. **Open browser:**
   ```
   http://localhost:8443/login
   ```

2. **Login with customer:**
   - Username: `john.doe`
   - Password: `password123`

3. **After clicking "Sign in":**
   - ✅ Redirected to `http://localhost:8080/customer`
   - ✅ Shows: "Access Granted to Customer Endpoint"

## Authorization Code Flow Testing

### 1. Initiate Authorization Code Flow

Open your browser and navigate to:
```
http://localhost:8443/oauth2/authorize?response_type=code&client_id=webapp&redirect_uri=http://localhost:8080/callback&scope=read
```

### 2. Login with User Credentials

- Username: `john.doe`
- Password: `password123`

### 3. Approve Access

Click "Approve" on the consent screen.

### 4. Capture Authorization Code

You'll be redirected to:
```
http://localhost:8080/callback?code=AUTHORIZATION_CODE_HERE
```

### 5. Exchange Code for Token

```bash
curl -X POST http://localhost:8443/oauth2/token \
  -u webapp:webappSecret \
  -d "grant_type=authorization_code" \
  -d "code=AUTHORIZATION_CODE_HERE" \
  -d "redirect_uri=http://localhost:8080/callback"
```

### 6. Use Token to Access Resources

```bash
curl http://localhost:8080/customer \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN_HERE"
```

## Testing with Postman

### Get Token

1. **New Request** → `POST`
2. **URL**: `http://localhost:8443/oauth2/token`
3. **Authorization** tab:
   - Type: `Basic Auth`
   - Username: `inventoryclient`
   - Password: `secret123`
4. **Body** tab:
   - Select: `x-www-form-urlencoded`
   - Add: `grant_type` = `client_credentials`
5. Click **Send**

### Use Token

1. **New Request** → `GET`
2. **URL**: `http://localhost:8080/endpoint1`
3. **Headers** tab:
   - Key: `Authorization`
   - Value: `Bearer <paste_token_here>`
4. Click **Send**

## Troubleshooting

### "401 Unauthorized"
- **Cause**: Missing or expired token
- **Fix**: Get a new token

### "403 Forbidden"
- **Cause**: Wrong role for endpoint
- **Check**: Token has correct role claim
```bash
echo $TOKEN | cut -d'.' -f2 | base64 -d | jq '.roles'
```

### "Connection refused"
- **Cause**: Server not running
- **Fix**: Start servers

### Decode JWT Token

```bash
# Get token
TOKEN=$(curl -s -X POST http://localhost:8443/oauth2/token \
  -u inventoryclient:secret123 \
  -d "grant_type=client_credentials" | jq -r '.access_token')

# Decode (without verification - for inspection only)
echo $TOKEN | cut -d'.' -f2 | base64 -d 2>/dev/null | jq '.'
```

**Shows**:
```json
{
  "sub": "inventoryclient",
  "aud": "inventoryclient",
  "roles": ["ROLE_ADMIN"],
  "scope": "read write delete",
  "iss": "http://localhost:8443",
  "exp": 1765030427,
  "iat": 1765026827
}
```

Or visit: https://jwt.io and paste the token

## Complete Test Script

```bash
#!/bin/bash

echo "=========================="
echo "OAuth2 Complete Flow Test"
echo "=========================="
echo ""

# 1. Get token from Auth Server
echo "1. Requesting JWT token from Auth Server (port 8443)..."
RESPONSE=$(curl -s -X POST http://localhost:8443/oauth2/token \
  -u inventoryclient:secret123 \
  -d "grant_type=client_credentials")

echo "Response:"
echo $RESPONSE | jq '.'
echo ""

# 2. Extract token
TOKEN=$(echo $RESPONSE | jq -r '.access_token')
EXPIRES=$(echo $RESPONSE | jq -r '.expires_in')

echo "✅ Token obtained! Expires in: $EXPIRES seconds"
echo "Token (first 50 chars): ${TOKEN:0:50}..."
echo ""

# 3. Use token to access Resource Server
echo "2. Accessing Resource Server endpoint (port 8080)..."
echo ""

echo "GET /endpoint1 (requires ROLE_ADMIN):"
curl -s http://localhost:8080/endpoint1 \
  -H "Authorization: Bearer $TOKEN" | jq '.'
echo ""

echo "GET /endpoint2 (requires ROLE_USER - should fail):"
curl -s -w "HTTP Status: %{http_code}\n" http://localhost:8080/endpoint2 \
  -H "Authorization: Bearer $TOKEN"
echo ""

echo "=========================="
echo "Test Complete!"
echo "=========================="
```

### One-Liner Tests

```bash
# Test all 3 clients with their correct endpoints
for CLIENT in "inventoryclient:secret123:1" "cartopsclient:secret456:2" "reportsclient:secret789:3"; do
  IFS=':' read -r USER PASS ENDPOINT <<< "$CLIENT"
  echo "Testing $USER -> /endpoint$ENDPOINT"
  TOKEN=$(curl -s -X POST http://localhost:8443/oauth2/token -u $USER:$PASS -d "grant_type=client_credentials" | jq -r '.access_token')
  curl -s http://localhost:8080/endpoint$ENDPOINT -H "Authorization: Bearer $TOKEN" | jq -r '.message'
  echo ""
done
```

## Expected Results

### ✅ Success Scenarios

- `inventoryclient` token → `/endpoint1` → 200 OK
- `cartopsclient` token → `/endpoint2` → 200 OK
- `reportsclient` token → `/endpoint3` → 200 OK
- `admin` login → `/endpoint1` → 200 OK
- `john.doe` login → `/customer` → 200 OK

### ❌ Forbidden Scenarios

- `inventoryclient` token → `/endpoint2` → 403 Forbidden (ADMIN trying to access USER endpoint)
- `cartopsclient` token → `/endpoint1` → 403 Forbidden (USER trying to access ADMIN endpoint)
- `john.doe` login → `/endpoint1` → 403 Forbidden (CUSTOMER trying to access ADMIN endpoint)
