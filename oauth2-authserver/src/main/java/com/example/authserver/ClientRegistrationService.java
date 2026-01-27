package com.example.authserver;

import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;

import jakarta.annotation.PostConstruct;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.*;

@Service
public class ClientRegistrationService {

    private final Map<String, ClientInfo> clientMappings = new HashMap<>();

    @PostConstruct
    public void loadMappings() {
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(new ClassPathResource("client-registrations.csv").getInputStream()))) {

            String line;
            boolean firstLine = true;

            while ((line = reader.readLine()) != null) {
                if (firstLine) {
                    firstLine = false; // Skip header
                    continue;
                }

                String[] parts = line.split(",", -1); // -1 to keep empty strings
                if (parts.length >= 5) {
                    String clientId = parts[0].trim();
                    String clientSecret = parts[1].trim();
                    String rolesStr = parts[2].trim();
                    String scopesStr = parts[3].trim();
                    String grantTypesStr = parts[4].trim();
                    String redirectUrisStr = parts.length > 5 ? parts[5].trim() : "";

                    List<String> roles = rolesStr.isEmpty() ? Collections.emptyList()
                            : Arrays.asList(rolesStr.split("\\s+"));
                    List<String> scopes = Arrays.asList(scopesStr.split("\\s+"));
                    List<String> grantTypes = Arrays.asList(grantTypesStr.split("\\s+"));
                    List<String> redirectUris = redirectUrisStr.isEmpty() ? Collections.emptyList()
                            : Arrays.asList(redirectUrisStr.split("\\s+"));

                    ClientInfo clientInfo = new ClientInfo(clientSecret, roles, scopes, grantTypes, redirectUris);
                    clientMappings.put(clientId, clientInfo);
                }
            }

            System.out.println("Loaded client registrations: " + clientMappings.keySet());
        } catch (IOException e) {
            throw new RuntimeException("Failed to load client-registrations.csv", e);
        }
    }

    public ClientInfo getClientInfo(String clientId) {
        return clientMappings.get(clientId);
    }

    public Set<String> getAllClientIds() {
        return clientMappings.keySet();
    }

    public static class ClientInfo {
        private final String clientSecret;
        private final List<String> roles;
        private final List<String> scopes;
        private final List<String> grantTypes;
        private final List<String> redirectUris;

        public ClientInfo(String clientSecret, List<String> roles, List<String> scopes, List<String> grantTypes,
                List<String> redirectUris) {
            this.clientSecret = clientSecret;
            this.roles = roles;
            this.scopes = scopes;
            this.grantTypes = grantTypes;
            this.redirectUris = redirectUris;
        }

        public String getClientSecret() {
            return clientSecret;
        }

        public List<String> getRoles() {
            return roles;
        }

        public List<String> getScopes() {
            return scopes;
        }

        public List<String> getGrantTypes() {
            return grantTypes;
        }

        public List<String> getRedirectUris() {
            return redirectUris;
        }
    }
}
