# Spring Security OAuth2.0 POC

A proof-of-concept demonstrating Spring Security OAuth2 authentication with **CSV-based role and scope management**.

## Features

- ✅ OAuth2/OIDC Login with multiple clients
- ✅ Role-based access control (RBAC)
- ✅ CSV-driven role/scope mappings
- ✅ Automated integration tests
- ✅ Java 17 + Spring Boot 3.2.0 + Maven

## Quick Start

### Prerequisites
- Java 17+
- Maven 3.6+
- OAuth2 provider accounts (GitHub, Google, etc.)

### Setup

1. **Register OAuth2 Applications**
   
   For GitHub (recommended for POC):
   - Go to Settings → Developer settings → OAuth Apps → New OAuth App
   - Create **3 separate apps** for client1, client2, client3
   - Set Homepage URL: `http://localhost:8080`
   - Set Authorization callback URL: 
     - `http://localhost:8080/login/oauth2/code/client1`
     - `http://localhost:8080/login/oauth2/code/client2`
     - `http://localhost:8080/login/oauth2/code/client3`

2. **Configure Credentials**
   
   Edit `src/main/resources/application.yml`:
   ```yaml
   spring:
     security:
       oauth2:
         client:
           registration:
             client1:
               clientId: <YOUR_GITHUB_CLIENT_ID_1>
               clientSecret: <YOUR_GITHUB_CLIENT_SECRET_1>
             client2:
               clientId: <YOUR_GITHUB_CLIENT_ID_2>
               clientSecret: <YOUR_GITHUB_CLIENT_SECRET_2>
             client3:
               clientId: <YOUR_GITHUB_CLIENT_ID_3>
               clientSecret: <YOUR_GITHUB_CLIENT_SECRET_3>
   ```

3. **Run Application**
   ```bash
   mvn spring-boot:run
   ```

4. **Test**
   - Navigate to `http://localhost:8080/endpoint1`
   - You'll be redirected to login page with 3 options (client1, client2, client3)
   - Login with **client1** → Success (has ROLE_ADMIN)
   - Try accessing `/endpoint2` → 403 Forbidden (needs ROLE_USER)

## How It Works

### CSV-Based Authorization

Edit `src/main/resources/client-roles.csv` to modify permissions:

```csv
client_id,roles,scopes
client1,ROLE_ADMIN,read write delete
client2,ROLE_USER,read
client3,ROLE_MANAGER,read write
```

**No code changes needed!** Just restart the app.

### Endpoint Protection

- `/endpoint1` → **ROLE_ADMIN** only (client1)
- `/endpoint2` → **ROLE_USER** only (client2)
- `/endpoint3` → **ROLE_MANAGER** only (client3)

## Testing

Run automated tests:
```bash
mvn test
```

All tests verify role-based access control using Spring Security Test.

## Project Structure

```
src/
├── main/
│   ├── java/com/example/oauth2poc/
│   │   ├── Oauth2PocApplication.java          # Main class
│   │   ├── SecurityConfig.java                # Security configuration
│   │   ├── ClientRoleMappingService.java      # CSV loader
│   │   ├── MultiClientController.java         # Protected endpoints
│   │   └── HomeController.java                # Home endpoint
│   └── resources/
│       ├── application.yml                    # OAuth2 config
│       └── client-roles.csv                   # Role mappings
└── test/
    └── java/com/example/oauth2poc/
        └── MultiClientControllerTest.java     # Integration tests
```

## Next Steps

- Replace CSV with database lookup
- Add more granular scope-based permissions
- Implement logout functionality
- Add user profile endpoints
- Deploy to production

## License

MIT
