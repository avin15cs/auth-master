package com.example.oauth2poc;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import java.util.stream.Collectors;

@RestController
public class MultiClientController {

        @GetMapping("/endpoint1")
        @PreAuthorize("hasRole('ADMIN')")
        public Map<String, Object> endpoint1(Authentication authentication) {
                return Map.of(
                                "message", "Access Granted to Endpoint 1 (ADMIN)",
                                "authorities", authentication.getAuthorities().stream()
                                                .map(GrantedAuthority::getAuthority)
                                                .collect(Collectors.toList()));
        }

        @GetMapping("/endpoint2")
        @PreAuthorize("hasRole('USER')")
        public Map<String, Object> endpoint2(Authentication authentication) {
                return Map.of(
                                "message", "Access Granted to Endpoint 2 (USER)",
                                "authorities", authentication.getAuthorities().stream()
                                                .map(GrantedAuthority::getAuthority)
                                                .collect(Collectors.toList()));
        }

        @GetMapping("/endpoint3")
        @PreAuthorize("hasRole('MANAGER')")
        public Map<String, Object> endpoint3(Authentication authentication) {
                return Map.of(
                                "message", "Access Granted to Endpoint 3 (MANAGER)",
                                "authorities", authentication.getAuthorities().stream()
                                                .map(GrantedAuthority::getAuthority)
                                                .collect(Collectors.toList()));
        }

        @GetMapping("/customer")
        @PreAuthorize("hasRole('CUSTOMER')")
        public Map<String, Object> customerEndpoint(Authentication authentication) {
                return Map.of(
                                "message", "Welcome Customer! This is your dedicated endpoint.",
                                "user", authentication.getName(),
                                "authorities", authentication.getAuthorities().stream()
                                                .map(GrantedAuthority::getAuthority)
                                                .collect(Collectors.toList()));
        }
}
