package com.example.oauth2poc;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@Controller
public class OAuth2LoginController {

    @GetMapping("/")
    public String home(Authentication authentication, Model model) {
        if (authentication != null) {
            model.addAttribute("username", authentication.getName());
            model.addAttribute("authorities", authentication.getAuthorities());
        }
        return "home";
    }

    @GetMapping("/token-info")
    @ResponseBody
    public Map<String, Object> getTokenInfo(
            @RegisteredOAuth2AuthorizedClient("webapp") OAuth2AuthorizedClient authorizedClient) {

        Map<String, Object> tokenInfo = new HashMap<>();

        if (authorizedClient != null) {
            OAuth2AccessToken accessToken = authorizedClient.getAccessToken();

            // Access Token Information
            tokenInfo.put("access_token", accessToken.getTokenValue());
            tokenInfo.put("token_type", accessToken.getTokenType().getValue());
            tokenInfo.put("scopes", accessToken.getScopes());
            tokenInfo.put("issued_at", accessToken.getIssuedAt());
            tokenInfo.put("expires_at", accessToken.getExpiresAt());

            // Calculate time remaining
            if (accessToken.getExpiresAt() != null) {
                long secondsRemaining = accessToken.getExpiresAt().getEpochSecond() - Instant.now().getEpochSecond();
                tokenInfo.put("expires_in_seconds", secondsRemaining);
                tokenInfo.put("expires_in_minutes", secondsRemaining / 60);

                // Add status message
                if (secondsRemaining < 0) {
                    tokenInfo.put("status", "EXPIRED - Will auto-refresh on next API call that uses the token");
                } else if (secondsRemaining < 300) {
                    tokenInfo.put("status", "EXPIRING SOON - Less than 5 minutes remaining");
                } else {
                    tokenInfo.put("status", "VALID");
                }
            }

            // Decode JWT (just the payload, not verifying signature)
            try {
                String[] jwtParts = accessToken.getTokenValue().split("\\.");
                if (jwtParts.length >= 2) {
                    String payload = new String(Base64.getUrlDecoder().decode(jwtParts[1]));
                    tokenInfo.put("decoded_jwt_payload", payload);
                }
            } catch (Exception e) {
                tokenInfo.put("jwt_decode_error", e.getMessage());
            }

            // Refresh Token Information
            OAuth2RefreshToken refreshToken = authorizedClient.getRefreshToken();
            if (refreshToken != null) {
                tokenInfo.put("refresh_token", refreshToken.getTokenValue());
                tokenInfo.put("refresh_token_issued_at", refreshToken.getIssuedAt());
                tokenInfo.put("refresh_token_expires_at", refreshToken.getExpiresAt());
            }

            // Client Information
            tokenInfo.put("client_name", authorizedClient.getClientRegistration().getClientName());
            tokenInfo.put("client_id", authorizedClient.getClientRegistration().getClientId());
            tokenInfo.put("principal_name", authorizedClient.getPrincipalName());

        } else {
            tokenInfo.put("error", "No authorized client found. Please login first.");
        }

        return tokenInfo;
    }
}
