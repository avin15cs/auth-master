package com.example.oauth2poc;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.oauth2Login;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;

@SpringBootTest
@AutoConfigureMockMvc
public class MultiClientControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    public void endpoint1_accessibleWithAdminRole() throws Exception {
        mockMvc.perform(get("/endpoint1")
                .with(oauth2Login()
                        .authorities(new SimpleGrantedAuthority("ROLE_ADMIN"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Access Granted to Endpoint 1 (ADMIN)"));
    }

    @Test
    public void endpoint1_forbiddenWithUserRole() throws Exception {
        mockMvc.perform(get("/endpoint1")
                .with(oauth2Login()
                        .authorities(new SimpleGrantedAuthority("ROLE_USER"))))
                .andExpect(status().isForbidden());
    }

    @Test
    public void endpoint2_accessibleWithUserRole() throws Exception {
        mockMvc.perform(get("/endpoint2")
                .with(oauth2Login()
                        .authorities(new SimpleGrantedAuthority("ROLE_USER"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Access Granted to Endpoint 2 (USER)"));
    }

    @Test
    public void endpoint2_forbiddenWithManagerRole() throws Exception {
        mockMvc.perform(get("/endpoint2")
                .with(oauth2Login()
                        .authorities(new SimpleGrantedAuthority("ROLE_MANAGER"))))
                .andExpect(status().isForbidden());
    }

    @Test
    public void endpoint3_accessibleWithManagerRole() throws Exception {
        mockMvc.perform(get("/endpoint3")
                .with(oauth2Login()
                        .authorities(new SimpleGrantedAuthority("ROLE_MANAGER"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Access Granted to Endpoint 3 (MANAGER)"));
    }
}
