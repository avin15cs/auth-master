# RSA Key Rotation - 24 Hour Policy

## Overview

The Authorization Server automatically rotates RSA keys every **24 hours** for enhanced security.

## How It Works

### On Server Startup

1. **Check for existing keys** in `keys/` directory
2. **Check timestamp** from `keys/key_timestamp.txt`
3. **Calculate age** = Current time - Timestamp

### Decision Logic

```
If keys exist AND age < 24 hours:
    → Load existing keys
    → Display key age
    
If keys exist AND age >= 24 hours:
    → Archive old keys to keys/archive/
    → Generate new RSA key pair
    → Save new keys + timestamp
    → Log rotation event
    
If keys don't exist:
    → Generate new RSA key pair
    → Save keys + timestamp
```

## File Structure

```
keys/
├── private_key.pem          # Current private key
├── public_key.pem           # Current public key  
├── key_timestamp.txt        # Creation timestamp
└── archive/                 # Old keys (for debugging)
    ├── private_key_20251206_183000.pem
    ├── public_key_20251206_183000.pem
    ├── private_key_20251207_183000.pem
    └── public_key_20251207_183000.pem
```

## Key Rotation Impact

### ⚠️ What Happens When Keys Rotate

**JWTs signed with old key become INVALID immediately**

- Resource Server fetches new public key from `/oauth2/jwks`
- Old JWTs fail signature verification
- Clients must request new tokens

### Mitigation Strategy

For production, implement **grace period**:
- Keep old key active for 1 hour after rotation
- Return BOTH old and new keys in JWK Set
- Resource Server validates against both keys
- Gradual cutover as clients refresh tokens

## Testing Key Rotation

### Force Rotation (Manual)

```bash
# Delete timestamp to force rotation on next startup
rm oauth2-authserver/keys/key_timestamp.txt

# Or modify timestamp (make it old)
echo "1700000000000" > oauth2-authserver/keys/key_timestamp.txt

# Restart server
pkill -f oauth2-authserver
cd oauth2-authserver && mvn spring-boot:run
```

### Check Key Age

```bash
# View timestamp
cat oauth2-authserver/keys/key_timestamp.txt

# Calculate age (milliseconds)
echo $(($(date +%s%3N) - $(cat oauth2-authserver/keys/key_timestamp.txt)))

# Convert to hours
echo "scale=2; ($(($(date +%s%3N) - $(cat oauth2-authserver/keys/key_timestamp.txt))) / 3600000)" | bc
```

### View Archived Keys

```bash
ls -lh oauth2-authserver/keys/archive/
```

## Production Recommendations

### 1. Distributed Systems
- **Problem**: Each server instance generates own keys
- **Solution**: Use shared key storage (Redis, Database, Vault)

### 2. Zero-Downtime Rotation
- Implement JWK Set with multiple keys
- Overlap period: 1-2 hours
- Graceful key retirement

### 3. Monitoring
- Log all rotation events
- Alert on rotation failures
- Track JWT validation errors post-rotation

### 4. Key Backup
- Archive old keys to secure storage (S3, Vault)
- Maintain audit trail
- Comply with regulatory requirements

## Configuration

To change rotation interval, modify in `AuthServerConfig.java`:

```java
long twentyFourHours = 24 * 60 * 60 * 1000; // Change this value
```

Examples:
- 1 hour: `1 * 60 * 60 * 1000`
- 12 hours: `12 * 60 * 60 * 1000`
- 7 days: `7 * 24 * 60 * 60 * 1000`

## Security Benefits

✅ **Limits exposure** - Even if key compromised, only valid 24 hours  
✅ **Compliance** - Meets regulatory requirements for key rotation  
✅ **Defense in depth** - Reduces blast radius of security incidents  
✅ **Audit trail** - Archived keys provide forensic evidence  

## Logs to Monitor

```
Loading existing RSA key pair from files...
Key age: 12 hours

*** RSA keys are older than 24 hours - ROTATING KEYS ***
Old key age: 25 hours
Archived old keys to: keys/archive/*_20251206_183000.pem
RSA key pair saved to keys/ directory
Next rotation scheduled in 24 hours
```
