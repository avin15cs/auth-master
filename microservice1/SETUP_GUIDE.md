# Setting Up OAuth2 for Browser Testing

## Quick Setup Guide

### Step 1: Create GitHub OAuth Apps

You need to create **3 separate OAuth Apps** on GitHub:

1. **Go to GitHub Settings**:
   - Visit: https://github.com/settings/developers
   - Click **"OAuth Apps"** → **"New OAuth App"**

2. **Create First App (client1)**:
   - **Application name**: `OAuth2 POC Client 1`
   - **Homepage URL**: `http://localhost:8080`
   - **Authorization callback URL**: `http://localhost:8080/login/oauth2/code/client1`
   - Click **"Register application"**
   - Copy the **Client ID** and generate a **Client Secret** - save these!

3. **Create Second App (client2)**:
   - Repeat with callback URL: `http://localhost:8080/login/oauth2/code/client2`

4. **Create Third App (client3)**:
   - Repeat with callback URL: `http://localhost:8080/login/oauth2/code/client3`

### Step 2: Update application.yml

Replace the placeholders in `src/main/resources/application.yml`:

```yaml
client1:
  clientId: <PASTE_CLIENT_ID_1_HERE>
  clientSecret: <PASTE_CLIENT_SECRET_1_HERE>
  
client2:
  clientId: <PASTE_CLIENT_ID_2_HERE>
  clientSecret: <PASTE_CLIENT_SECRET_2_HERE>
  
client3:
  clientId: <PASTE_CLIENT_ID_3_HERE>
  clientSecret: <PASTE_CLIENT_SECRET_3_HERE>
```

### Step 3: Run the Application

```bash
mvn spring-boot:run
```

### Step 4: Test in Browser

1. **Open**: http://localhost:8080/endpoint1
2. **You'll see a login page** with 3 buttons (client1, client2, client3)
3. **Click "client1"** → redirected to GitHub login
4. **Authorize the app** → redirected back
5. **See the response**:
   ```json
   {
     "message": "Access Granted to Endpoint 1 (ADMIN)",
     "authorities": ["ROLE_ADMIN", "SCOPE_read", "SCOPE_write", "SCOPE_delete", ...]
   }
   ```

### Step 5: Test Authorization

- Try accessing `/endpoint2` → Should get **403 Forbidden** (you're logged in as client1/ADMIN)
- Logout: http://localhost:8080/logout
- Login as **client2** and try `/endpoint2` → Success!

---

## Alternative: Use Single GitHub App for All 3 Clients

If you want to simplify, you can use **one GitHub App** for all clients:

1. Create only **ONE** OAuth App with callback: `http://localhost:8080/login/oauth2/code/github`
2. Use the same Client ID/Secret for all 3 clients in `application.yml`
3. Update `redirectUri` for all clients to use `/github` instead of `/client1`, `/client2`, `/client3`

This works for POC testing but won't demonstrate the full multi-client scenario.

---

## Testing with Postman

**Note**: Postman testing with OAuth2 Login flow is complex because it requires browser interaction. For API testing, you'd typically use **OAuth2 Resource Server** (JWT Bearer tokens) instead of OAuth2 Login.

For now, **browser testing is recommended** for this OAuth2 Login setup.
