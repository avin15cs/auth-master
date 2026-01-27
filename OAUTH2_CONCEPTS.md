# OAuth2 Concepts - Comprehensive Guide

This guide explains the key OAuth2 concepts implemented in this project, with a focus on practical understanding and real-world applications.

## Table of Contents

1. [OAuth2 Flow Comparison](#oauth2-flow-comparison)
2. [Client Credentials Flow](#client-credentials-flow)
3. [Authorization Code Flow](#authorization-code-flow)
4. [Form Login vs Password Grant](#form-login-vs-password-grant)
5. [Real-World Example: "Login with Google"](#real-world-example-login-with-google)
6. [Security Considerations](#security-considerations)

## OAuth2 Flow Comparison

| Aspect | Client Credentials | Authorization Code | Password Grant (Deprecated) |
|--------|-------------------|-------------------|----------------------------|
| **Who authenticates?** | Application (client_id/secret) | **User** (username/password) | User via client app |
| **Steps** | 1 step (direct token request) | 2 steps (code → token) | 1 step (direct token request) |
| **User involved?** | No | **Yes - types password** | Yes - types password in client app |
| **Redirect?** | No | **Yes - multiple redirects** | No |
| **JWT subject** | client_id | **username** | username |
| **Use case** | API-to-API | **User login on web/mobile** | Legacy systems only |
| **OAuth 2.1 Status** | ✅ Supported | ✅ Recommended | ❌ Deprecated |
| **Spring Support** | ✅ Supported | ✅ Supported | ❌ Not supported |

## Client Credentials Flow

The Client Credentials flow is designed for machine-to-machine (service-to-service) communication where no user is involved.

### How It Works

```
Client → Auth Server: "I'm inventoryclient, here's my secret"
Auth Server → Client: "Verified! Here's your JWT"
Client → Resource Server: "Here's my JWT"
Resource Server: "JWT valid! Access granted"
```

### Implementation

```bash
# Request
curl -X POST http://localhost:8443/oauth2/token \
  -u inventoryclient:secret123 \
  -d "grant_type=client_credentials"

# Response
{
  "access_token": "eyJhbGc...",  # JWT token
  "token_type": "Bearer",
  "expires_in": 3600
}

# JWT Claims
{
  "sub": "inventoryclient",
  "aud": "inventoryclient",
  "roles": ["ROLE_ADMIN"],
  "scope": "read write delete",
  "iss": "http://localhost:8443",
  "exp": 1765029259,
  "iat": 1765025659
}
```

### When to Use

- Service-to-service communication
- Background jobs
- API access without user context
- Automated processes

## Authorization Code Flow

The Authorization Code flow is designed for user authentication in browser-based applications, mobile apps, and SPAs.

### How It Works

#### Phase 1: Get Authorization Code

1. **User clicks "Login" on your webapp**
   - Webapp redirects browser to Auth Server
   - `http://localhost:8443/oauth2/authorize?response_type=code&client_id=webapp&redirect_uri=http://localhost:8080/callback&scope=read`

2. **User sees login form on Auth Server**
   - User enters username and password
   - Auth Server validates credentials

3. **Auth Server redirects back with code**
   - `http://localhost:8080/callback?code=AUTHORIZATION_CODE_XYZ123`

#### Phase 2: Exchange Code for JWT Token

4. **Webapp backend calls Auth Server**
   - Server-to-server call (browser doesn't see this)
   ```bash
   curl -X POST http://localhost:8443/oauth2/token \
     -u webapp:webappSecret \
     -d "grant_type=authorization_code" \
     -d "code=AUTHORIZATION_CODE_XYZ123" \
     -d "redirect_uri=http://localhost:8080/callback"
   ```

5. **Auth Server responds with JWT**
   ```json
   {
     "access_token": "eyJhbGc...",
     "token_type": "Bearer",
     "expires_in": 3600,
     "refresh_token": "refresh_xyz",
     "scope": "read write"
   }
   ```

6. **JWT contains user information**
   ```json
   {
     "sub": "john.doe",              # This is a USER, not a client!
     "roles": ["ROLE_CUSTOMER"],     # User's roles
     "username": "john.doe",
     "subject_type": "user",
     "exp": 1765123456
   }
   ```

#### Phase 3: Use JWT

7. **Webapp uses JWT to access resources**
   ```bash
   curl http://localhost:8080/customer \
     -H "Authorization: Bearer eyJhbGc..."
   ```

### Why Two Steps?

The two-step process provides important security benefits:

1. **Authorization code is given via browser redirect** (can be intercepted)
2. **But code is USELESS without client_secret!**
3. **Token exchange happens server-to-server** (secure!)

If someone steals the authorization code, they still can't get a token without knowing the client secret.

### When to Use

- Web applications
- Mobile apps
- Single Page Applications (SPAs)
- Any application where a user needs to authenticate

## Form Login vs Password Grant

### Form Login (Recommended)

Form Login is the secure way to implement user authentication in OAuth2.

```
User → Browser → Login Form → Auth Server
                              ↓
                    Authenticated Session
```

- User types password directly on Auth Server
- Password never sent to client application
- Session-based (cookies)
- Supported by Spring Authorization Server
- OAuth 2.1 compliant

### Password Grant (Deprecated)

```
User types in Client App → Client sends to Auth Server
```

- Client app collects password
- Password travels through client
- Stateless (token-based)
- Not supported by Spring Authorization Server
- Deprecated in OAuth 2.1

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

## Real-World Example: "Login with Google"

When you click "Login with Google" on a 3rd party website, you're using the Authorization Code flow:

```
1. User visits: https://medium.com
        ↓
2. Clicks: "Sign in with Google" button
        ↓
3. Medium REDIRECTS browser to Google:
   https://accounts.google.com/o/oauth2/auth?
     response_type=code
     &client_id=medium-app-id
     &redirect_uri=https://medium.com/oauth/callback
     &scope=openid email profile
     &state=random-string-for-security
        ↓
4. Browser NOW at Google's domain!
   User types Gmail & password on GOOGLE'S login page
        ↓
5. Google validates credentials
   Creates session on Google.com
        ↓
6. Google shows: "Medium.com wants to access your profile"
   User clicks "Allow"
        ↓
7. Google REDIRECTS back to Medium:
   https://medium.com/oauth/callback?
     code=AUTHORIZATION_CODE_xyz123
     &state=random-string-for-security
        ↓
8. Medium's backend receives authorization code
   (User's browser is now back on medium.com)
        ↓
9. Medium's SERVER makes direct API call to Google:
   POST https://oauth2.googleapis.com/token
   code=AUTHORIZATION_CODE_xyz123
   &client_id=medium-app-id
   &client_secret=MEDIUM_SECRET
   &redirect_uri=https://medium.com/oauth/callback
   &grant_type=authorization_code
        ↓
10. Google responds with JWT tokens:
    {
      "access_token": "ya29.a0AfH6...",
      "id_token": "eyJhbGciOiJSUzI1NiIs...",
      "expires_in": 3600,
      "refresh_token": "1//0eXxyz..."
    }
        ↓
11. Medium validates JWT, extracts user info
    Creates Medium account/session
        ↓
12. Medium redirects to: https://medium.com/home
    User is now logged in! ✅
```

### Key Security Features

1. **PKCE (Proof Key for Code Exchange)**
   - Prevents authorization code interception

2. **State Parameter**
   - Prevents CSRF attacks

3. **Client Secret**
   - Only the backend knows the client_secret
   - Authorization code is useless to attackers without it

## Security Considerations

### Best Practices

1. **Never use Password Grant**
   - Always use Authorization Code flow for user authentication
   - Password Grant is deprecated in OAuth 2.1

2. **Protect Client Secrets**
   - Store securely on server-side only
   - Never expose in client-side code

3. **Use PKCE for Public Clients**
   - Required for mobile apps and SPAs
   - Recommended for all clients

4. **Validate All Tokens**
   - Check signature
   - Verify expiration
   - Validate issuer and audience

5. **Use Short-Lived Access Tokens**
   - 15-60 minutes is recommended
   - Use refresh tokens for longer sessions

6. **Implement Proper CORS**
   - Restrict allowed origins
   - Only expose necessary endpoints

7. **Use HTTPS Everywhere**
   - Never transmit tokens over HTTP
   - Secure cookies with Secure and HttpOnly flags