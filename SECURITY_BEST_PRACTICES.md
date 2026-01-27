# Security Best Practices

This document outlines security best practices for OAuth2 and JWT implementations, with a focus on the current project.

## Table of Contents

1. [JWT Security](#jwt-security)
2. [OAuth2 Security](#oauth2-security)
3. [Key Management](#key-management)
4. [Token Validation](#token-validation)
5. [Production Recommendations](#production-recommendations)
6. [Common Vulnerabilities](#common-vulnerabilities)
7. [Interview Questions](#interview-questions)

## JWT Security

### JWT Validation Process

```
┌─────────────────────────────────────────────────────────────────┐
│ 1. CLIENT SENDS REQUEST                                         │
└─────────────────────────────────────────────────────────────────┘
  GET /endpoint1
  Authorization: Bearer eyJraWQiOiJhYmMxMjMi...
                          ↓
┌─────────────────────────────────────────────────────────────────┐
│ 2. SERVLET FILTER CHAIN (Spring Security)                      │
└─────────────────────────────────────────────────────────────────┘
  BearerTokenAuthenticationFilter
    ↓ Extracts token from header
    ↓ Calls AuthenticationManager
                          ↓
┌─────────────────────────────────────────────────────────────────┐
│ 3. JWT AUTHENTICATION PROVIDER                                 │
└─────────────────────────────────────────────────────────────────┘
  JwtAuthenticationProvider
    ↓ Calls JwtDecoder.decode(token)
                          ↓
┌─────────────────────────────────────────────────────────────────┐
│ 4. NIMBUS JWT DECODER                                           │
└─────────────────────────────────────────────────────────────────┘
  NimbusJwtDecoder.decode(String token)
    ↓ Parse JWT: SignedJWT.parse(token)
    ↓ Split into: header.payload.signature
    │
    ├─→ Header: {"kid": "abc123", "alg": "RS256"}
    ├─→ Payload: {"sub": "user", "exp": 1234567890, ...}
    └─→ Signature: [bytes]
                          ↓
┌─────────────────────────────────────────────────────────────────┐
│ 5. JWK SOURCE (THE CACHE!)                                     │
└─────────────────────────────────────────────────────────────────┘
  RemoteJWKSet.get(JWKSelector, Context)
    ↓
    ├─→ Check in-memory cache: Map<String, JWK>
    │   ├─→ Cache HIT? → Return JWK (0 network calls)
    │   └─→ Cache MISS/EXPIRED?
    │       ├─→ HTTP GET http://localhost:8443/oauth2/jwks
    │       ├─→ Parse JSON: {"keys": [{...}]}
    │       ├─→ Update cache: cachedJWKs = keys
    │       ├─→ Set expiration: cacheTime + 300000ms (5 min)
    │       └─→ Return matching JWK
                          ↓
┌─────────────────────────────────────────────────────────────────┐
│ 6. SIGNATURE VERIFICATION                                       │
└─────────────────────────────────────────────────────────────────┘
  RSASSAVerifier.verify(JWSObject, RSAPublicKey)
    ↓
    ├─→ Extract signature from JWT: signatureBytes
    ├─→ Reconstruct signed content: header + "." + payload
    ├─→ Compute expected signature using public key:
    │   ├─→ SHA256withRSA(signedContent, publicKey)
    │   └─→ Compare: expectedSig == actualSig
    └─→ Return: true/false
                          ↓
┌─────────────────────────────────────────────────────────────────┐
│ 7. CLAIMS VALIDATION                                            │
└─────────────────────────────────────────────────────────────────┘
  JwtValidators.validate(Jwt)
    ↓
    ├─→ IssuerValidator: jwt.iss == "http://localhost:8443"
    ├─→ ExpiryValidator: jwt.exp > currentTime
    ├─→ NotBeforeValidator: jwt.nbf <= currentTime (if present)
    └─→ AudienceValidator: jwt.aud matches (if configured)
                          ↓
┌─────────────────────────────────────────────────────────────────┐
│ 8. AUTHORITIES EXTRACTION                                      │
└─────────────────────────────────────────────────────────────────┘
  SecurityConfig.extractAuthorities(Jwt)
    ↓
    ├─→ Extract: roles = jwt.getClaim("roles")
    ├─→ Extract: scope = jwt.getClaim("scope")
    └─→ Create: [ROLE_ADMIN, SCOPE_read, SCOPE_write]
                          ↓
┌─────────────────────────────────────────────────────────────────┐
│ 9. AUTHORIZATION CHECK                                          │
└─────────────────────────────────────────────────────────────────┘
  @PreAuthorize("hasRole('ADMIN')")
    ↓
    ├─→ Get authorities: authentication.getAuthorities()
    ├─→ Check: authorities.contains("ROLE_ADMIN")
    └─→ Allow: true → Proceed to controller
        Deny: false → Return 403 Forbidden
```

### JWK Caching

Caching JWKs is critical for performance and reliability:

**Performance Benefits:**
- Eliminates network latency (typically 50-200ms per request)
- Reduces load on Authorization Server
- Enables microservices to handle thousands of requests/second
- In-memory lookup is < 1ms vs network call 50-200ms

**Reliability Benefits:**
- Service continues working if Auth Server is temporarily down
- No cascading failures
- Graceful degradation (uses stale cache if refresh fails)

**Security Note:**
- Public keys are safe to cache (they're public!)
- Only private keys need protection
- JWKs include key metadata like `kid` and `alg` for proper validation

**Trade-off:**
- Cache must be refreshed to detect key rotation
- Default 5-minute TTL balances freshness vs performance
- Can be configured based on key rotation frequency

### Performance Metrics

| Scenario | Cache Hit | Cache Miss |
|----------|-----------|------------|
| **Latency** | < 1ms | 50-200ms |
| **Throughput** | 10,000 req/s | 50-100 req/s |
| **Auth Server Load** | 0 requests | 1 req per cache miss |
| **Memory Usage** | ~2KB per key | Same |

## OAuth2 Security

### Authorization Code Flow Security

The Authorization Code flow provides several security benefits:

1. **User credentials are never shared with the client application**
   - User enters credentials directly on the Authorization Server
   - Client application never sees or handles passwords

2. **Two-step process prevents token interception**
   - Authorization code is exchanged for token in a server-to-server call
   - Even if code is intercepted, it's useless without client_secret

3. **PKCE (Proof Key for Code Exchange)**
   - Prevents authorization code interception attacks
   - Client generates a code_verifier and code_challenge
   - Authorization Server verifies the code_challenge matches the code_verifier

4. **State parameter prevents CSRF attacks**
   - Client generates a random state value
   - Authorization Server returns the same state value
   - Client verifies the state matches to prevent CSRF

### Form Login vs Password Grant

| Aspect | Form Login (✅ Secure) | Password Grant (❌ Insecure) |
|--------|--------------|-------------------|
| **User Experience** | Browser redirect to login page | Client app collects password |
| **Security** | Password never leaves Auth Server | Client app handles password |
| **OAuth 2.1 Status** | ✅ Recommended | ❌ Deprecated |
| **Spring Support** | ✅ Built-in | ❌ Not supported |
| **Use Case** | Web apps, mobile apps | Legacy systems only |

### Security Difference

#### Password Grant Flow (Insecure)
```
User types password in:
    Mobile App / Web App / Desktop App
           ↓
    Password stored in app memory
           ↓
    App sends password to Auth Server
           ↓
    Gets back JWT token
           
RISK: If app is compromised, password is exposed!
```

#### Form Login Flow (Secure)
```
User types password in:
    Auth Server's Login Page ONLY
           ↓
    Password NEVER leaves Auth Server
           ↓
    Session cookie returned to browser
           ↓
    Browser automatically includes cookie
           
SAFE: Password never exposed to client app!
```

## Key Management

### Key Rotation

Key rotation follows this flow:

1. **Before Rotation:**
   - Resource Server cache has Key A (kid=abc123)
   - All JWTs are signed with Private Key A

2. **Rotation Happens:**
   - Auth Server generates new Key B (kid=xyz789)
   - Makes it available at `/oauth2/jwks` endpoint
   - Issues new JWTs with Key B
   - May keep Key A active for grace period

3. **First Request with New JWT:**
   - Resource Server receives JWT with kid=xyz789
   - Cache miss for xyz789
   - Triggers automatic refresh from `/oauth2/jwks`
   - Downloads and caches both Key A and Key B
   - Validates the new JWT successfully

4. **Subsequent Requests:**
   - Cache hit for xyz789
   - No network calls needed

**Best Practices:**
- Keep old key active for 1-2 hours (grace period)
- Publish multiple keys in JWK Set
- Resource Server supports multiple concurrent keys
- Gradual rollout: issue new tokens while accepting old ones

### Key Storage

- **Private Keys**: Store securely on the Authorization Server only
  - Use file system permissions to restrict access
  - Consider using a key vault in production
  - Archive old keys for audit purposes

- **Public Keys**: Expose via JWKS endpoint
  - No special protection needed (they're public)
  - Include key metadata (kid, alg, etc.)
  - Cache on Resource Servers

## Token Validation

### Claims to Validate

1. **Signature**: Verify the token was signed by the trusted issuer
2. **Expiration (exp)**: Ensure the token hasn't expired
3. **Issuer (iss)**: Verify the token was issued by the expected Authorization Server
4. **Audience (aud)**: Verify the token is intended for this Resource Server
5. **Not Before (nbf)**: If present, ensure the token is already valid
6. **Subject (sub)**: Identify the user or client
7. **Custom Claims**: Validate any application-specific claims

### Debugging JWT Validation Failures

**Enable Debug Logging:**
```yaml
logging:
  level:
    org.springframework.security.oauth2: DEBUG
    com.nimbusds.jose: DEBUG
```

**Check Common Issues:**

- **401 Unauthorized**
  - Verify token is not expired: `jwt.io` → decode → check `exp`
  - Check issuer mismatch: `iss` claim vs `issuer-uri`
  - Verify signature: ensure Auth Server is accessible

- **403 Forbidden**
  - Check authorities: log `authentication.getAuthorities()`
  - Verify role claim is present in JWT
  - Confirm `@PreAuthorize` expression matches

- **Network Issues**
  - Test OIDC discovery: `curl http://authserver/.well-known/openid-configuration`
  - Test JWK endpoint: `curl http://authserver/oauth2/jwks`
  - Check network connectivity, DNS, firewalls

**Decode JWT Manually:**
```bash
# Extract payload
echo $TOKEN | cut -d'.' -f2 | base64 -d | jq '.'

# Check claims
{
  \"iss\": \"http://localhost:8443\",  ← Must match issuer-uri
  \"exp\": 1765030427,                ← Must be future
  \"roles\": [\"ROLE_ADMIN\"]          ← Must exist
}
```

## Production Recommendations

1. **Use HTTPS Everywhere**
   - Secure all endpoints with TLS
   - Use proper certificates from trusted CAs
   - Configure secure TLS versions and ciphers

2. **Token Lifetimes**
   - Access tokens: 15-60 minutes
   - Refresh tokens: 1-14 days with rotation
   - ID tokens: Short-lived (5-10 minutes)

3. **Rate Limiting**
   - Implement rate limiting on token endpoints
   - Protect against brute force attacks
   - Consider IP-based rate limiting

4. **Monitoring and Alerting**
   - Monitor failed authentication attempts
   - Alert on unusual token usage patterns
   - Log security-relevant events

5. **High Availability**
   - Deploy multiple instances of Auth Server
   - Use load balancing
   - Implement proper failover

6. **Database Security**
   - Encrypt sensitive data at rest
   - Use proper access controls
   - Regular backups and security audits

7. **Client Management**
   - Secure client registration process
   - Regular client secret rotation
   - Limit redirect URIs to trusted domains

8. **Token Revocation**
   - Implement token revocation endpoint
   - Consider token blacklisting for critical scenarios
   - Support refresh token rotation

## Common Vulnerabilities

### 1. Improper JWT Validation

**Vulnerability**: Not validating all required claims or signature.

**Mitigation**: 
- Always validate signature, expiration, issuer, and audience
- Use a trusted library for validation
- Never accept unsigned or symmetric-signed tokens when asymmetric is expected

### 2. Insecure Storage of Secrets

**Vulnerability**: Storing client secrets or private keys in code or insecure locations.

**Mitigation**:
- Use environment variables or secure vaults
- Implement proper access controls
- Regular rotation of secrets and keys

### 3. Missing PKCE for Public Clients

**Vulnerability**: Authorization Code flow without PKCE for mobile or SPA clients.

**Mitigation**:
- Always use PKCE for public clients
- Implement S256 code challenge method
- Verify code_verifier matches code_challenge

### 4. Overly Permissive CORS

**Vulnerability**: Allowing any origin to access token endpoints.

**Mitigation**:
- Restrict CORS to specific trusted origins
- Don't use wildcards in production
- Only expose necessary endpoints

### 5. Insufficient Token Entropy

**Vulnerability**: Using predictable or low-entropy tokens.

**Mitigation**:
- Use cryptographically secure random generators
- Ensure sufficient token length and entropy
- Implement proper token formats

## Interview Questions

### Q1: "How does Spring Security validate JWT tokens?"

**Answer:**
"Spring Security uses a multi-step process:

1. **Token Extraction**: `BearerTokenAuthenticationFilter` extracts the JWT from the `Authorization: Bearer` header

2. **Decoding**: `NimbusJwtDecoder` parses the JWT into three parts:
   - Header (contains `kid` - key ID, and `alg` - signature algorithm)
   - Payload (contains claims like `sub`, `exp`, `iss`)
   - Signature (cryptographic signature bytes)

3. **Key Lookup**: Uses `RemoteJWKSet` to find the public key:
   - First checks in-memory cache using the `kid`
   - If not found or cache expired, fetches from the JWK endpoint
   - Caches the keys for 5 minutes by default

4. **Signature Verification**: Verifies the signature using RSA/ECDSA:
   - Reconstructs the signed content: `base64(header).base64(payload)`
   - Computes expected signature using the public key
   - Compares with the actual signature in the JWT

5. **Claims Validation**: Validates standard claims:
   - `exp`: Token must not be expired
   - `iss`: Issuer must match configured issuer-uri
   - `nbf`: Token must be valid (not before)
   - `aud`: Audience must match (if configured)

6. **Authorities Extraction**: Custom converter extracts roles/scopes from claims

7. **Authorization**: `@PreAuthorize` checks if user has required authorities"

### Q2: "Why cache JWKs instead of fetching every time?"

**Answer:**
"Caching JWKs is critical for performance and reliability:

**Performance Benefits:**
- Eliminates network latency (typically 50-200ms per request)
- Reduces load on Authorization Server
- Enables microservices to handle thousands of requests/second
- In-memory lookup is < 1ms vs network call 50-200ms

**Reliability Benefits:**
- Service continues working if Auth Server is temporarily down
- No cascading failures
- Graceful degradation (uses stale cache if refresh fails)

**Security Note:**
- Public keys are safe to cache (they're public!)
- Only private keys need protection
- JWKs include key metadata like `kid` and `alg` for proper validation

**Trade-off:**
- Cache must be refreshed to detect key rotation
- Default 5-minute TTL balances freshness vs performance
- Can be configured based on key rotation frequency"

### Q3: "What happens when the Authorization Server rotates keys?"

**Answer:**
"Key rotation follows this flow:

1. **Before Rotation:**
   - Resource Server cache has Key A (kid=abc123)
   - All JWTs are signed with Private Key A

2. **Rotation Happens:**
   - Auth Server generates new Key B (kid=xyz789)
   - Makes it available at `/oauth2/jwks` endpoint
   - Issues new JWTs with Key B
   - May keep Key A active for grace period

3. **First Request with New JWT:**
   - Resource Server receives JWT with kid=xyz789
   - Cache miss for xyz789
   - Triggers automatic refresh from `/oauth2/jwks`
   - Downloads and caches both Key A and Key B
   - Validates the new JWT successfully

4. **Subsequent Requests:**
   - Cache hit for xyz789
   - No network calls needed

**Best Practices:**
- Keep old key active for 1-2 hours (grace period)
- Publish multiple keys in JWK Set
- Resource Server supports multiple concurrent keys
- Gradual rollout: issue new tokens while accepting old ones"

### Q4: "What's the difference between Password grant and Form Login?"

**Answer:**
"Password grant is an OAuth2 flow where the client application collects the user's credentials and exchanges them for a token in a single API call. It's deprecated in OAuth 2.1 because it requires the client to handle passwords, which violates the principle of delegated authorization.

Form login, on the other hand, is browser-based. The user enters credentials directly on the authorization server's login page, the server creates a session, and the client never sees the password. This is the foundation for the Authorization Code flow, which is the OAuth 2.1 recommended approach.

Spring Authorization Server only supports form login because it enforces modern security best practices."

### Q5: "How would you use a reverse proxy to solve cross-origin issues?"

**Answer:**
"A reverse proxy like Nginx sits in front of multiple backend services and presents them as a single origin to the client. For example, both the Authorization Server on port 8443 and Resource Server on port 8080 can be accessed through Nginx on port 80 using different URL paths like `/auth/*` and `/api/*`. This solves the cookie sharing issue because the browser sees everything as coming from the same origin (port 80).

However, for microservices using OAuth2, the better approach is to use JWT tokens rather than sessions, as they're stateless and don't require shared session storage or cookies."