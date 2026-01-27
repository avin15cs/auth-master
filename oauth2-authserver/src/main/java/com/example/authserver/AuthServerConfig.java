package com.example.authserver;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.http.MediaType;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Configuration
public class AuthServerConfig {

    private final ClientRegistrationService clientRegistrationService;
    private final CustomUserDetailsService userDetailsService;

    @Value("${security.key-rotation.interval-hours:24}")
    private int keyRotationIntervalHours;

    @Value("${security.jwt.access-token-validity-minutes:60}")
    private int tokenValidityMinutes;

    public AuthServerConfig(ClientRegistrationService clientRegistrationService,
            CustomUserDetailsService userDetailsService) {
        this.clientRegistrationService = clientRegistrationService;
        this.userDetailsService = userDetailsService;
    }

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(Customizer.withDefaults()); // Enable OpenID Connect 1.0

        // Redirect to the login page when not authenticated from the
        // authorization endpoint
        http.exceptionHandling((exceptions) -> exceptions
                .defaultAuthenticationEntryPointFor(
                        new LoginUrlAuthenticationEntryPoint("http://localhost:8443/login"),
                        new MediaTypeRequestMatcher(MediaType.TEXT_HTML)));

        http.oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));

        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http, PasswordEncoder passwordEncoder)
            throws Exception {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder);

        http
                .authenticationProvider(authProvider)
                .authorizeHttpRequests(authorize -> authorize
                        .anyRequest().authenticated())
                // Form login handles the redirect to the login page from the
                // authorization server filter chain
                .formLogin(Customizer.withDefaults());

        return http.build();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository(PasswordEncoder passwordEncoder) {
        List<RegisteredClient> clients = new ArrayList<>();

        for (String clientId : clientRegistrationService.getAllClientIds()) {
            ClientRegistrationService.ClientInfo info = clientRegistrationService.getClientInfo(clientId);

            RegisteredClient.Builder builder = RegisteredClient.withId(UUID.randomUUID().toString())
                    .clientId(clientId)
                    .clientSecret(passwordEncoder.encode(info.getClientSecret()))
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST);

            // Add grant types from CSV
            for (String grantType : info.getGrantTypes()) {
                if ("client_credentials".equals(grantType)) {
                    builder.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS);
                } else if ("password".equals(grantType)) {
                    builder.authorizationGrantType(AuthorizationGrantType.PASSWORD);
                } else if ("authorization_code".equals(grantType)) {
                    builder.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE);
                } else if ("refresh_token".equals(grantType)) {
                    builder.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN);
                }
            }

            // Add redirect URIs from CSV
            for (String redirectUri : info.getRedirectUris()) {
                if (!redirectUri.isEmpty()) {
                    builder.redirectUri(redirectUri);
                }
            }

            // Add scopes
            for (String scope : info.getScopes()) {
                builder.scope(scope);
            }

            // Token settings
            builder.tokenSettings(TokenSettings.builder()
                    .accessTokenTimeToLive(Duration.ofMinutes(tokenValidityMinutes))
                    .build());

            // Client settings for authorization_code flow
            builder.clientSettings(ClientSettings.builder()
                    .requireAuthorizationConsent(true) // Show consent screen
                    .build());

            clients.add(builder.build());
        }

        return new InMemoryRegisteredClientRepository(clients);
    }

    @Bean
    public AuthenticationManager authenticationManager(PasswordEncoder passwordEncoder) {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder);
        return new ProviderManager(authProvider);
    }

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer() {
        return (context) -> {
            Authentication principal = context.getPrincipal();

            if (AuthorizationGrantType.CLIENT_CREDENTIALS.equals(context.getAuthorizationGrantType())) {
                // For client_credentials, the principal is the client ID
                String clientId = principal.getName();
                ClientRegistrationService.ClientInfo clientInfo = clientRegistrationService.getClientInfo(clientId);

                if (clientInfo != null) {
                    // Add roles to JWT
                    context.getClaims().claim("roles", clientInfo.getRoles());
                    // Add scopes
                    context.getClaims().claim("scope", String.join(" ", clientInfo.getScopes()));
                    // Add subject type
                    context.getClaims().claim("subject_type", "client");
                }

            } else if (AuthorizationGrantType.PASSWORD.equals(context.getAuthorizationGrantType())) {
                // For password grant, the principal is the authenticated user
                String username = principal.getName();
                List<String> userRoles = userDetailsService.getUserRoles(username);

                if (!userRoles.isEmpty()) {
                    // Add user roles to JWT
                    context.getClaims().claim("roles", userRoles);
                    // Add subject type
                    context.getClaims().claim("subject_type", "user");
                    // Add username for clarity
                    context.getClaims().claim("username", username);
                }
            } else if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(context.getAuthorizationGrantType())) {
                // For authorization_code grant, the principal is the authenticated user
                String username = principal.getName();
                List<String> userRoles = userDetailsService.getUserRoles(username);

                if (!userRoles.isEmpty()) {
                    // Add user roles to JWT
                    context.getClaims().claim("roles", userRoles);
                    // Add subject type
                    context.getClaims().claim("subject_type", "user");
                    // Add username for clarity
                    context.getClaims().claim("username", username);
                }
            }
        };
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = loadOrGenerateRsaKey(keyRotationIntervalHours);
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    private static KeyPair loadOrGenerateRsaKey(int rotationIntervalHours) {
        try {
            java.io.File privateKeyFile = new java.io.File("keys/private_key.pem");
            java.io.File publicKeyFile = new java.io.File("keys/public_key.pem");
            java.io.File timestampFile = new java.io.File("keys/key_timestamp.txt");

            // Check if keys exist and are still valid (< rotation interval)
            if (privateKeyFile.exists() && publicKeyFile.exists() && timestampFile.exists()) {
                long keyAge = System.currentTimeMillis() - timestampFile.lastModified();
                long rotationInterval = rotationIntervalHours * 60L * 60L * 1000L; // Convert hours to milliseconds

                if (keyAge < rotationInterval) {
                    System.out.println("Loading existing RSA key pair from files...");
                    System.out.println("Key age: " + (keyAge / 3600000) + " hours (rotation interval: "
                            + rotationIntervalHours + " hours)");
                    return loadKeyPairFromFiles(privateKeyFile, publicKeyFile);
                } else {
                    System.out.println(
                            "*** RSA keys are older than " + rotationIntervalHours + " hours - ROTATING KEYS ***");
                    System.out.println("Old key age: " + (keyAge / 3600000) + " hours");

                    // Archive old keys before rotating
                    archiveOldKeys(privateKeyFile, publicKeyFile);

                    // Generate new keys
                    KeyPair keyPair = generateNewRsaKey();
                    saveKeyPairToFiles(keyPair, privateKeyFile, publicKeyFile, timestampFile, rotationIntervalHours);
                    return keyPair;
                }
            } else {
                System.out.println("Generating new RSA key pair and saving to files...");
                KeyPair keyPair = generateNewRsaKey();
                saveKeyPairToFiles(keyPair, privateKeyFile, publicKeyFile, timestampFile, rotationIntervalHours);
                return keyPair;
            }
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to load or generate RSA keys", ex);
        }
    }

    private static void archiveOldKeys(java.io.File privateKeyFile, java.io.File publicKeyFile) {
        try {
            String timestamp = new java.text.SimpleDateFormat("yyyyMMdd_HHmmss").format(new java.util.Date());
            java.io.File archiveDir = new java.io.File("keys/archive");
            archiveDir.mkdirs();

            // Copy old keys to archive
            java.nio.file.Files.copy(
                    privateKeyFile.toPath(),
                    new java.io.File(archiveDir, "private_key_" + timestamp + ".pem").toPath(),
                    java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            java.nio.file.Files.copy(
                    publicKeyFile.toPath(),
                    new java.io.File(archiveDir, "public_key_" + timestamp + ".pem").toPath(),
                    java.nio.file.StandardCopyOption.REPLACE_EXISTING);

            System.out.println("Archived old keys to: keys/archive/*_" + timestamp + ".pem");
        } catch (Exception ex) {
            System.err.println("Warning: Failed to archive old keys: " + ex.getMessage());
        }
    }

    private static KeyPair generateNewRsaKey() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            return keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to generate RSA key pair", ex);
        }
    }

    private static void saveKeyPairToFiles(KeyPair keyPair, java.io.File privateKeyFile,
            java.io.File publicKeyFile, java.io.File timestampFile,
            int rotationIntervalHours) throws Exception {
        // Create keys directory if it doesn't exist
        java.io.File keysDir = new java.io.File("keys");
        if (!keysDir.exists()) {
            keysDir.mkdirs();
        }

        // Save private key
        try (java.io.FileWriter writer = new java.io.FileWriter(privateKeyFile)) {
            writer.write("-----BEGIN PRIVATE KEY-----\n");
            writer.write(java.util.Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded()));
            writer.write("\n-----END PRIVATE KEY-----\n");
        }

        // Save public key
        try (java.io.FileWriter writer = new java.io.FileWriter(publicKeyFile)) {
            writer.write("-----BEGIN PUBLIC KEY-----\n");
            writer.write(java.util.Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
            writer.write("\n-----END PUBLIC KEY-----\n");
        }

        // Save timestamp
        try (java.io.FileWriter writer = new java.io.FileWriter(timestampFile)) {
            writer.write(String.valueOf(System.currentTimeMillis()));
        }

        System.out.println("RSA key pair saved to keys/ directory");
        System.out.println("Next rotation scheduled in " + rotationIntervalHours + " hours");
    }

    private static KeyPair loadKeyPairFromFiles(java.io.File privateKeyFile, java.io.File publicKeyFile)
            throws Exception {
        // Read private key
        String privateKeyPEM = new String(java.nio.file.Files.readAllBytes(privateKeyFile.toPath()))
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        byte[] privateKeyBytes = java.util.Base64.getDecoder().decode(privateKeyPEM);
        java.security.spec.PKCS8EncodedKeySpec privateKeySpec = new java.security.spec.PKCS8EncodedKeySpec(
                privateKeyBytes);
        java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance("RSA");
        java.security.PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

        // Read public key
        String publicKeyPEM = new String(java.nio.file.Files.readAllBytes(publicKeyFile.toPath()))
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");
        byte[] publicKeyBytes = java.util.Base64.getDecoder().decode(publicKeyPEM);
        java.security.spec.X509EncodedKeySpec publicKeySpec = new java.security.spec.X509EncodedKeySpec(publicKeyBytes);
        java.security.PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

        return new KeyPair(publicKey, privateKey);
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .issuer("http://localhost:8443")
                .build();
    }
}
