package com.example.oauth2poc;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class RedirectFixController {

    @GetMapping("/oauth2/authorize")
    public String fixRedirect(HttpServletRequest request) {
        // Capture the misdirected request on port 8080 and send it to 8443
        String queryString = request.getQueryString();
        String targetUrl = "http://localhost:8443/oauth2/authorize";
        if (queryString != null) {
            targetUrl += "?" + queryString;
        }
        System.out.println("Applying Port Fix: Redirecting from 8080 to 8443");
        return "redirect:" + targetUrl;
    }
}
