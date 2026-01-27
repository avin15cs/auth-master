# Implementation Details

This document provides technical details about the implementation of the OAuth2 Authorization Server and Resource Server.

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Authorization Server Implementation](#authorization-server-implementation)
3. [Resource Server Implementation](#resource-server-implementation)
4. [Form Login Implementation](#form-login-implementation)
5. [Cross-Origin Issues & Solutions](#cross-origin-issues--solutions)
6. [Reverse Proxy Configuration](#reverse-proxy-configuration)
7. [Implementation Challenges](#implementation-challenges)

## Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│  Authorization Server (port 8443)                      │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  Supported Flows:                                       │
│    ✅ Client Credentials                                │
│    ✅ Authorization Code + PKCE (for future use)        │
│    ❌ Password Grant (not supported by design)          │
│                                                         │
│  Data Sources:                                          │
│    • client-registrations.csv (clients)                 │
│    • users.csv (users - ready for Auth Code flow)      │
│    • keys/ (RSA keys with 24-hour rotation)            │
│                                                         │
│  JWT Customization:                                     │
│    • Client: roles, scopes, subject_type=client         │
│    • User: roles, username, subject_type=user           │
│                                                         │
└─────────────────────────────────────────────────────────┘
                           ↓ JWT
┌─────────────────────────────────────────────────────────┐
│  Resource Server / microservice1 (port 8080)           │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  Endpoints:                                             │
│    • /endpoint1 → ROLE_ADMIN                            │
│    • /endpoint2 → ROLE_USER                             │
│    • /endpoint3 → ROLE_MANAGER                          │
│    • /customer  → ROLE_CUSTOMER                         │
│                                                         │
│  Validates JWTs from Auth Server                        │
│  Caches public keys (5-minute TTL)                      │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

## Authorization Server Implementation

### Client Registration

Clients are loaded from `client-registrations.csv`:

```csv
client_id,client_secret,roles,scopes,grant_types
inventoryclient,secret123,ROLE_ADMIN,read write delete,client_credentials
cartopsclient,secret456,ROLE_USER,read,client_credentials
reportsclient,secret789,ROLE_MANAGER,read write,client_credentials
webapp,webappSecret,,read write,authorization_code
```

Implementation in `ClientRegistrationService.java`:

```java
@Service
public class ClientRegistrationService {
    private final Map<String, ClientInfo> clients = new HashMap<>();
    
    @PostConstruct
    public void loadClients() {
        try (CSVReader reader = new CSVReader(new FileReader("src/main/resources/client-registrations.csv"))) {
            // Skip header
            reader.readNext();
            
            String[] line;
            while ((line = reader.readNext()) != null) {
                String clientId = line[0];
                String clientSecret = line[1];
                String roles = line[2];
                String scopes = line[3];
                String grantTypes = line.length > 4 ? line[4] : "client_credentials";
                
                clients.put(clientId, new ClientInfo(clientId, clientSecret, roles, scopes, grantTypes));
            }
        } catch (Exception e) {
            throw new RuntimeException("Error loading client registrations", e);
        }
    }
    
    public ClientInfo getClient(String clientId) {
        return clients.get(clientId);
    }
    
    // Inner class to store client information
    @Data
    @AllArgsConstructor
    public static class ClientInfo {
        private String clientId;
        private String clientSecret;
        private String roles;
        private String scopes;
        private String grantTypes;
        
        public List<String> getRolesList() {
            return Arrays.asList(roles.split("\\s+"));
        }
        
        public List<String> getScopesList() {
            return Arrays.asList(scopes.split("\\s+"));
        }
        
        public List<String> getGrantTypes() {
            return Arrays.asList(grantTypes.split("\\s+"));
        }
    }
}
```

### User Management

Users are loaded from `users.csv`:

```csv
username,password,roles,enabled
john.doe,password123,ROLE_CUSTOMER,true
alice.smith,alice123,ROLE_CUSTOMER,true
bob.jones,bob123,ROLE_CUSTOMER,true
admin,admin123,ROLE_ADMIN,true
```

Implementation in `CustomUserDetailsService.java`:

```java
@Service
public class CustomUserDetailsService implements UserDetailsService {
    private final Map<String, UserInfo> users = new HashMap<>();
    private final PasswordEncoder passwordEncoder;
    
    public CustomUserDetailsService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
        loadUsers();
    }
    
    private void loadUsers() {
        try (CSVReader reader = new CSVReader(new FileReader("src/main/resources/users.csv"))) {
            // Skip header
            reader.readNext();
            
            String[] line;
            while ((line = reader.readNext()) != null) {
                String username = line[0];
                String password = line[1];
                String roles = line[2];
                boolean enabled = Boolean.parseBoolean(line[3]);
                
                users.put(username, new UserInfo(username, password, roles, enabled));
            }
        } catch (Exception e) {
            throw new RuntimeException("Error loading users", e);
        }
    }
    
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserInfo userInfo = users.get(username);
        if (userInfo == null) {
            throw new UsernameNotFoundException("User not found: " + username);
        }
        
        return User.builder()
            .username(userInfo.getUsername())
            .password(passwordEncoder.encode(userInfo.getPassword()))
            .authorities(userInfo.getRolesList().stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList()))
            .disabled(!userInfo.isEnabled())
            .build();
    }
    
    // Inner class to store user information
    @Data
    @AllArgsConstructor
    public static class UserInfo {
        private String username;
        private String password;
        private String roles;
        private boolean enabled;
        
        public List<String> getRolesList() {
            return Arrays.asList(roles.split("\\s+"));
        }
    }
}
```

### JWT Token Customization

JWT tokens are customized in `AuthServerConfig.java`:

```java
@Bean
public OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer(
        ClientRegistrationService clientRegistrationService) {
    return context -> {
        JwtClaimsSet.Builder claims = context.getClaims();
        
        if (context.getTokenType() == OAuth2TokenType.ACCESS_TOKEN) {
            String clientId = context.getRegisteredClient().getClientId();
            
            // Add client roles for client_credentials grant
            if (context.getAuthorizationGrantType().equals(AuthorizationGrantType.CLIENT_CREDENTIALS)) {
                ClientInfo clientInfo = clientRegistrationService.getClient(clientId);
                if (clientInfo != null && !clientInfo.getRoles().isEmpty()) {
                    claims.claim("roles", clientInfo.getRolesList());
                    claims.claim("subject_type", "client");
                }
            }
            // Add user roles for authorization_code grant
            else if (context.getAuthorizationGrantType().equals(AuthorizationGrantType.AUTHORIZATION_CODE)) {
                Authentication principal = context.getPrincipal();
                if (principal instanceof UsernamePasswordAuthenticationToken) {
                    UserDetails user = (UserDetails) principal.getPrincipal();
                    List<String> roles = user.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toList());
                    
                    claims.claim("roles", roles);
                    claims.claim("username", user.getUsername());
                    claims.claim("subject_type", "user");
                }
            }
        }
    };
}
```

### Key Rotation

RSA keys are rotated every 24 hours:

```java
@Scheduled(fixedRate = 24 * 60 * 60 * 1000) // 24 hours
public void rotateKeys() {
    try {
        // Archive current keys
        if (Files.exists(privateKeyPath) && Files.exists(publicKeyPath)) {
            String timestamp = new SimpleDateFormat("yyyyMMdd_HHmmss").format(new Date());
            
            Path archiveDir = Paths.get("keys/archive");
            if (!Files.exists(archiveDir)) {
                Files.createDirectories(archiveDir);
            }
            
            Files.copy(privateKeyPath, 
                Paths.get("keys/archive/private_key_" + timestamp + ".pem"),
                StandardCopyOption.REPLACE_EXISTING);
            
            Files.copy(publicKeyPath,
                Paths.get("keys/archive/public_key_" + timestamp + ".pem"),
                StandardCopyOption.REPLACE_EXISTING);
        }
        
        // Generate new keys
        KeyPair keyPair = generateRsaKey();
        
        // Save private key
        try (FileWriter writer = new FileWriter(privateKeyPath.toFile())) {
            writer.write("-----BEGIN PRIVATE KEY-----\n");
            writer.write(Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded()));
            writer.write("\n-----END PRIVATE KEY-----\n");
        }
        
        // Save public key
        try (FileWriter writer = new FileWriter(publicKeyPath.toFile())) {
            writer.write("-----BEGIN PUBLIC KEY-----\n");
            writer.write(Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
            writer.write("\n-----END PUBLIC KEY-----\n");
        }
        
        // Update timestamp
        try (FileWriter writer = new FileWriter(timestampPath.toFile())) {
            writer.write(String.valueOf(System.currentTimeMillis()));
        }
        
        log.info("RSA key pair rotated successfully");
    } catch (Exception e) {
        log.error("Error rotating RSA keys", e);
    }
}
```

## Resource Server Implementation

### Security Configuration

The Resource Server is configured in `SecurityConfig.java`:

```java
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(authorize -> authorize
                .anyRequest().authenticated()
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt
                    .jwtAuthenticationConverter(jwtAuthenticationConverter())
                )
            );
        
        return http.build();
    }
    
    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter grantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
        grantedAuthoritiesConverter.setAuthoritiesClaimName("roles");
        grantedAuthoritiesConverter.setAuthorityPrefix("");
        
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(grantedAuthoritiesConverter);
        
        return jwtAuthenticationConverter;
    }
}
```

### Protected Endpoints

Endpoints are protected with method security:

```java
@RestController
public class MultiClientController {

    @GetMapping("/endpoint1")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> endpoint1(Authentication auth) {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Access Granted to Endpoint 1 (ADMIN)");
        response.put("authorities", auth.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority)
            .collect(Collectors.toList()));
        return ResponseEntity.ok(response);
    }
    
    @GetMapping("/endpoint2")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<Map<String, Object>> endpoint2(Authentication auth) {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Access Granted to Endpoint 2 (USER)");
        response.put("authorities", auth.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority)
            .collect(Collectors.toList()));
        return ResponseEntity.ok(response);
    }
    
    @GetMapping("/endpoint3")
    @PreAuthorize("hasRole('MANAGER')")
    public ResponseEntity<Map<String, Object>> endpoint3(Authentication auth) {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Access Granted to Endpoint 3 (MANAGER)");
        response.put("authorities", auth.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority)
            .collect(Collectors.toList()));
        return ResponseEntity.ok(response);
    }
    
    @GetMapping("/customer")
    @PreAuthorize("hasRole('CUSTOMER')")
    public ResponseEntity<Map<String, Object>> customer(Authentication auth) {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Access Granted to Customer Endpoint");
        response.put("authorities", auth.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority)
            .collect(Collectors.toList()));
        return ResponseEntity.ok(response);
    }
}
```

## Form Login Implementation

Form-based login is enabled on the Authorization Server:

```java
@Bean
@Order(2)
public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
    http
        .authorizeHttpRequests(authorize -> authorize
            .anyRequest().authenticated()
        )
        .formLogin(form -> form
            .defaultSuccessUrl("http://localhost:8080/customer", true)
        );
    
    return http.build();
}
```

### User Authentication Flow

```
User tries to access protected resource
    ↓
Not logged in?
    ↓
Redirect to: http://localhost:8443/login
    ↓
User sees Spring Security's default login form
    ↓
User enters:
  - Username: john.doe
  - Password: password123
    ↓
Spring calls CustomUserDetailsService
    ↓
User authenticated with ROLE_CUSTOMER
    ↓
Session created
    ↓
Redirect back to original request
```

## Cross-Origin Issues & Solutions

### The Problem

```
Login at:     http://localhost:8443  (Auth Server)
              ↓
Session cookie created for: localhost:8443
              ↓
Redirect to:  http://localhost:8080  (Resource Server)
              ↓
Problem: Session cookie from :8443 is NOT sent to :8080!
```

### Why It Doesn't Work

1. **Form login creates a SESSION cookie** (JSESSIONID)
2. **Session cookies are port-specific**
3. **localhost:8443 ≠ localhost:8080**
4. **Browser won't send :8443 cookie to :8080**

Result: User is redirected but not authenticated at the Resource Server!

### Solutions

#### Solution 1: Use JWT Instead of Session (Best for Microservices)

This requires implementing **Authorization Code Flow** properly:

1. User logs in at Auth Server → Gets authorization code
2. Exchange code for **JWT token**
3. Store JWT in browser (localStorage/cookie)
4. Send JWT to Resource Server in Authorization header

**This is the OAuth2 way!**

#### Solution 2: Same-Origin Deployment (Simple, for demo)

Run both servers on same port using a reverse proxy.

#### Solution 3: Direct Access (Current Working Approach)

**Don't redirect cross-origin with sessions!**

Instead:

1. **Login separately** on Auth Server (gets session)
2. **Get JWT token** via OAuth2 flow
3. **Use JWT** to access Resource Server

## Reverse Proxy Configuration

### Nginx Configuration

```nginx
http {
    # ... other config ...
    
    server {
        listen 80;
        server_name localhost;
        
        # Route /auth/* to Authorization Server
        location /auth/ {
            proxy_pass http://localhost:8443/;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            
            # Important: Cookie path rewriting
            proxy_cookie_path / /auth/;
        }
        
        # Route /api/* to Microservice
        location /api/ {
            proxy_pass http://localhost:8080/;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }
        
        # Optional: Root page
        location / {
            return 200 "OAuth2 Demo\nAuth Server: http://localhost/auth/\nAPI: http://localhost/api/";
            add_header Content-Type text/plain;
        }
    }
}
```

### URL Mapping

| User Types | Nginx Routes To | Backend |
|------------|----------------|---------|
| `http://localhost/auth/login` | → `http://localhost:8443/login` | Auth Server |
| `http://localhost/auth/oauth2/token` | → `http://localhost:8443/oauth2/token` | Auth Server |
| `http://localhost/api/endpoint1` | → `http://localhost:8080/endpoint1` | Microservice1 |
| `http://localhost/api/customer` | → `http://localhost:8080/customer` | Microservice1 |

## Implementation Challenges

### 1. Circular Dependencies

**Problem:**
```
AuthServerConfig needs PasswordEncoder
    ↓
PasswordEncoder was defined in AuthServerConfig
    ↓
CustomUserDetailsService needs PasswordEncoder
    ↓
AuthServerConfig needs CustomUserDetailsService
    ↓
CIRCULAR DEPENDENCY!
```

**Solution:**
Created `SecurityBeansConfig.java`:
```java
@Configuration
public class SecurityBeansConfig {
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
```

Now the dependency chain is linear:
```
SecurityBeansConfig creates PasswordEncoder
    ↓
CustomUserDetailsService uses PasswordEncoder
    ↓
AuthServerConfig uses CustomUserDetailsService
    ✅ NO CYCLE!
```

### 2. Password Grant Not Supported

**Attempted:** Enable `password` grant type for user login

**Result:** `unsupported_grant_type` error

**Why?**
Spring Authorization Server **intentionally does NOT support** Resource Owner Password Credentials grant because:

1. **Deprecated in OAuth 2.1**
   - Security best practices have evolved
   - Direct password handling is discouraged

2. **Anti-pattern**
   - Client applications shouldn't handle user passwords
   - Violates principle of delegated authorization

3. **Spring's Recommendation**
   - Use **Authorization Code + PKCE** for user authentication
   - This is the modern, secure approach

### 3. Hybrid OAuth2 Client and Resource Server

To enable `microservice1` to act as both an OAuth2 Client (for browser-based Form Login) and an OAuth2 Resource Server (for API access via Bearer Tokens), we needed to configure exception handling to ensure browsers still redirect to Login (Form) while API clients receive appropriate 401/403 responses:

```java
.exceptionHandling(exceptions -> exceptions
    .defaultAuthenticationEntryPointFor(
        new LoginUrlAuthenticationEntryPoint("/login"),
        new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
    )
)
```

This ensures that:
- Browser requests (HTML) redirect to login
- API requests (JSON) receive proper 401 responses