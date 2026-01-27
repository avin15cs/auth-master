# Configuring Key Rotation Interval

## ✅ Now Configurable via application.yml

The key rotation interval is **no longer hardcoded**! You can now configure it easily.

## Configuration Location

**File**: `oauth2-authserver/src/main/resources/application.yml`

```yaml
# Key Rotation Configuration
security:
  key-rotation:
    interval-hours: 24  # Change this value!
```

## Examples

### 1 Hour Rotation
```yaml
security:
  key-rotation:
    interval-hours: 1
```

### 12 Hour Rotation
```yaml
security:
  key-rotation:
    interval-hours: 12
```

### 7 Day Rotation
```yaml
security:
  key-rotation:
    interval-hours: 168  # 7 * 24 = 168
```

## How It Works

### Code Implementation

**AuthServerConfig.java:**
```java
@Value("${security.key-rotation.interval-hours:24}")
private int keyRotationIntervalHours;
```

- **`@Value`**: Spring annotation to inject property
- **Property**: `security.key-rotation.interval-hours`
- **Default**: 24 (if property not found)

### Logs Show Configuration

**On Server Startup:**
```
Loading existing RSA key pair from files...
Key age: 0 hours (rotation interval: 24 hours)
           ↑                              ↑
    Current age                 Your configured interval
```

**On Rotation:**
```
*** RSA keys are older than 24 hours - ROTATING KEYS ***
                              ↑
                    Your configured interval
```

## Changes Made

1. ✅ Added `security.key-rotation.interval-hours` to `application.yml`
2. ✅ Added `@Value` annotation in `AuthServerConfig.java`
3. ✅ Removed hardcoded `24 * 60 * 60 * 1000` value
4. ✅ Updated logs to show configured interval

## Testing Different Intervals

### Test 1-Hour Rotation

1. Change config:
   ```yaml
   security:
     key-rotation:
       interval-hours: 1
   ```

2. Restart server

3. Check logs:
   ```
   Key age: 0 hours (rotation interval: 1 hours)
   ```

4. Wait 1 hour + 1 minute, restart:
   ```
   *** RSA keys are older than 1 hours - ROTATING KEYS ***
   ```

### Test Without Configuration

If you delete the config, it defaults to 24 hours:
```java
@Value("${security.key-rotation.interval-hours:24}")
//                                                ↑↑ default value  
```

## Production Recommendation

For production, use **12-24 hours**:
- ✅ Good balance between security and stability
- ✅ Follows industry best practices
- ✅ Gives time for monitoring and alerts
