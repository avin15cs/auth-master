package com.example.authserver;

import org.springframework.core.io.ClassPathResource;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import jakarta.annotation.PostConstruct;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.*;
import java.util.stream.Collectors;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final PasswordEncoder passwordEncoder;
    private final Map<String, UserInfo> users = new HashMap<>();

    public CustomUserDetailsService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @PostConstruct
    public void loadUsers() {
        try {
            ClassPathResource resource = new ClassPathResource("users.csv");
            BufferedReader reader = new BufferedReader(new InputStreamReader(resource.getInputStream()));

            String line;
            boolean firstLine = true;

            while ((line = reader.readLine()) != null) {
                if (firstLine) {
                    firstLine = false; // Skip header
                    continue;
                }

                String[] parts = line.split(",");
                if (parts.length >= 4) {
                    String username = parts[0].trim();
                    String password = parts[1].trim();
                    String rolesStr = parts[2].trim();
                    boolean enabled = Boolean.parseBoolean(parts[3].trim());

                    List<String> roles = Arrays.asList(rolesStr.split("\\\\s+"));

                    UserInfo userInfo = new UserInfo(username, password, roles, enabled);
                    users.put(username, userInfo);
                }
            }
            reader.close();

            System.out.println("Loaded users: " + users.keySet());
        } catch (Exception e) {
            throw new RuntimeException("Failed to load users from CSV", e);
        }
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserInfo userInfo = users.get(username);
        if (userInfo == null) {
            throw new UsernameNotFoundException("User not found: " + username);
        }

        List<GrantedAuthority> authorities = userInfo.getRoles().stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());

        return User.builder()
                .username(userInfo.getUsername())
                .password(passwordEncoder.encode(userInfo.getPassword()))
                .authorities(authorities)
                .disabled(!userInfo.isEnabled())
                .build();
    }

    public List<String> getUserRoles(String username) {
        UserInfo userInfo = users.get(username);
        return userInfo != null ? userInfo.getRoles() : Collections.emptyList();
    }

    public static class UserInfo {
        private final String username;
        private final String password;
        private final List<String> roles;
        private final boolean enabled;

        public UserInfo(String username, String password, List<String> roles, boolean enabled) {
            this.username = username;
            this.password = password;
            this.roles = roles;
            this.enabled = enabled;
        }

        public String getUsername() {
            return username;
        }

        public String getPassword() {
            return password;
        }

        public List<String> getRoles() {
            return roles;
        }

        public boolean isEnabled() {
            return enabled;
        }
    }
}
