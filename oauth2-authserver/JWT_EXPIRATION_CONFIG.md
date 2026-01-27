# JWT Token Expiration Configuration

## ✅ Now Configurable via application.yml

The JWT token expiration (`expires_in`) is now fully configurable!

## Configuration

**File**: `oauth2-authserver/src/main/resources/application.yml`

```yaml
security:
  jwt:
    access-token-validity-minutes: 60  # Token expires in 60 minutes
```

## Code Location

**AuthServerConfig.java** (Line 98):
```java
@Value("${security.jwt.access-token-validity-minutes:60}")
private int tokenValidityMinutes;

// Used in TokenSettings
.tokenSettings(TokenSettings.builder()
    .accessTokenTimeToLive(Duration.ofMinutes(tokenValidityMinutes))
    .build())
```

## Examples

### 5 Minutes (for testing)
```yaml
security:
  jwt:
    access-token-validity-minutes: 5
```

Result: `"expires_in": 299` (5 minutes - 1 second)

### 30 Minutes
```yaml
security:
  jwt:
    access-token-validity-minutes: 30
```

Result: `"expires_in": 1799`

### 2 Hours
```yaml
security:
  jwt:
    access-token-validity-minutes: 120
```

Result: `"expires_in": 7199`

### 24 Hours
```yaml
security:
  jwt:
    access-token-validity-minutes: 1440  # 24 * 60
```

Result: `"expires_in": 86399`

## How It Works

### Token Response

When you request a token:
```bash
curl -X POST http://localhost:8443/oauth2/token \
  -u inventoryclient:secret123 \
  -d "grant_type=client_credentials"
```

**Response**:
```json
{
  "access_token": "eyJraW...",
  "token_type": "Bearer",
  "expires_in": 3599  ← This value comes from config!
}
```

### Why 3599 instead of 3600?

Spring subtracts 1 second for safety margin:
- Config: 60 minutes = 3600 seconds
- Response: 3599 seconds
- This ensures token doesn't expire during transmission

## JWT Claims

The `exp` claim in the JWT reflects this configuration:
```json
{
  "sub": "inventoryclient",
  "exp": 1765030427,  ← Current time + configured validity
  "iat": 1765026827,  ← Token issued at
  ...
}
```

## Relationship with Key Rotation

**Important**: Token validity should be **less than** key rotation interval!

### ✅ Good Configuration
```yaml
security:
  key-rotation:
    interval-hours: 24      # Keys rotate every 24 hours
  jwt:
    access-token-validity-minutes: 120  # Tokens expire in 2 hours
```

**Why**: All tokens expire before keys rotate, so no tokens become invalid due to rotation.

### ⚠️ Risky Configuration
```yaml
security:
  key-rotation:
    interval-hours: 1       # Keys rotate every hour
  jwt:
    access-token-validity-minutes: 120  # Tokens valid for 2 hours
```

**Problem**: Tokens issued just before rotation will become invalid when keys rotate after 1 hour!

## Production Recommendations

| Use Case | Recommended Validity |
|----------|---------------------|
| **API-to-API** | 15-60 minutes |
| **Mobile Apps** | 60-120 minutes |
| **Web Apps** | 30-60 minutes |
| **Long-running Jobs** | 180-360 minutes (use refresh tokens ideally) |

### General Rule
- Short-lived tokens = Better security
- Longer-lived tokens = Fewer token requests
- Balance based on your needs

## Testing Different Values

### Test 5-Minute Tokens

1. Set config:
   ```yaml
   security:
     jwt:
       access-token-validity-minutes: 5
   ```

2. Restart server

3. Get token:
   ```bash
   curl -X POST http://localhost:8443/oauth2/token \
     -u inventoryclient:secret123 \
     -d "grant_type=client_credentials" | jq .expires_in
   ```

4. Output: `299` (5 minutes - 1 second)

5. Wait 6 minutes and try using the token:
   ```bash
   curl http://localhost:8080/endpoint1 \
     -H "Authorization: Bearer <old_token>"
   ```

6. Result: `401 Unauthorized` (token expired)

## Summary: All Configurable Properties

```yaml
security:
  # Key rotation
  key-rotation:
    interval-hours: 24
  
  # Token expiration  
  jwt:
    access-token-validity-minutes: 60
```

Both are now externalized to `application.yml` with sensible defaults!
