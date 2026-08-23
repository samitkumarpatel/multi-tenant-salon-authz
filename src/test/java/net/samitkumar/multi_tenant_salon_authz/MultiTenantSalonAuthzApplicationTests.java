package net.samitkumar.multi_tenant_salon_authz;

import net.samitkumar.multi_tenant_salon_authz.notification.NotificationService;
import net.samitkumar.multi_tenant_salon_authz.salon.SalonInfo;
import net.samitkumar.multi_tenant_salon_authz.salon.SalonUser;
import net.samitkumar.multi_tenant_salon_authz.salon.SalonUserClient;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@Import(TestcontainersConfiguration.class)
@SpringBootTest
class MultiTenantSalonAuthzApplicationTests {

    @Autowired WebApplicationContext context;
    @MockitoBean
    SalonUserClient salonUserClient;
    @MockitoBean
    NotificationService notificationService;
    @Autowired OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer;

    MockMvc mockMvc;

    @BeforeEach
    void setup() {
        mockMvc = MockMvcBuilders.webAppContextSetup(context)
                .apply(springSecurity())
                .build();
    }

    static final SalonUser TEST_USER = new SalonUser("user@salon.com", List.of(
            new SalonInfo("salon-1", "OWNER", true),
            new SalonInfo("salon-2", "STAFF", false)
    ));

    @Test
    void contextLoads() {}

    // --- /ping endpoint ---

    @Test
    void pingRequiresAuthentication() throws Exception {
        mockMvc.perform(get("/ping"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void pingReturnsUserDetailsWhenAuthenticated() throws Exception {
        var auth = UsernamePasswordAuthenticationToken.authenticated(
                TEST_USER, null, TEST_USER.getAuthorities());

        mockMvc.perform(get("/ping").with(authentication(auth)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("PONG"))
                .andExpect(jsonPath("$.requester").value("user@salon.com"))
                .andExpect(jsonPath("$.user_principal.email").value("user@salon.com"))
                .andExpect(jsonPath("$.user_principal.salons", hasSize(2)))
                .andExpect(jsonPath("$.user_principal.salons[0].salonId").value("salon-1"))
                .andExpect(jsonPath("$.user_principal.salons[0].role").value("OWNER"))
                .andExpect(jsonPath("$.user_principal.salons[1].salonId").value("salon-2"))
                .andExpect(jsonPath("$.user_principal.salons[1].role").value("STAFF"));
    }

    // --- Public endpoints ---

    @Test
    void actuatorHealthIsPublic() throws Exception {
        mockMvc.perform(get("/actuator/health"))
                .andExpect(status().isOk());
    }

    @Test
    void ottInfoPageIsPublic() throws Exception {
        mockMvc.perform(get("/ott-info.html"))
                .andExpect(status().isOk());
    }

    @Test
    void loginPageIsPublicAndRendersOttRequestForm() throws Exception {
        mockMvc.perform(get("/login"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith("text/html"))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("/ott/generate")))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("_csrf")))
                .andExpect(content().string(org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString("We couldn't sign you in"))));
    }

    @Test
    void loginPageShowsErrorMessageWhenErrorParamPresent() throws Exception {
        mockMvc.perform(get("/login").param("error", ""))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("We couldn't sign you in")));
    }

    @Test
    void loginPageShowsNotifyErrorMessageWhenTokenNotificationFails() throws Exception {
        mockMvc.perform(get("/login").param("error", "notify"))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("Something went wrong on our end")))
                .andExpect(content().string(org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString("We couldn't sign you in"))));
    }

    @Test
    void loginOttPageIsPublicAndRendersTokenForm() throws Exception {
        mockMvc.perform(get("/login/ask-ott"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith("text/html"))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("/login/ott")))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("_csrf")))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("name=\"token\"")));
    }

    @Test
    void loginOttPagePrefillsTokenFromQueryParam() throws Exception {
        mockMvc.perform(get("/login/ask-ott").param("token", "123456"))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("value=\"123456\"")));
    }

    // --- Full OTT login flow ---

    @Test
    void fullOttLoginFlowGeneratesAndAuthenticatesWithToken() throws Exception {
        when(salonUserClient.getUserIdentity("user@salon.com")).thenReturn(Optional.of(TEST_USER));

        mockMvc.perform(post("/ott/generate")
                        .with(csrf())
                        .param("username", "user@salon.com"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/ott-info.html"));

        @SuppressWarnings("unchecked")
        ArgumentCaptor<Map<String, String>> captor = ArgumentCaptor.forClass(Map.class);
        verify(notificationService).send(eq("user@salon.com"), captor.capture());
        String token = captor.getValue().get("token");
        assertThat(token).isNotBlank();

        mockMvc.perform(post("/login/ott")
                        .with(csrf())
                        .accept(org.springframework.http.MediaType.TEXT_HTML)
                        .param("token", token))
                .andExpect(status().is3xxRedirection())
                .andExpect(result -> assertThat(result.getResponse().getRedirectedUrl())
                        .as("should not bounce back to the login page")
                        .doesNotContain("/login"));
    }

    @Test
    void ottLoginFailsWithUnknownToken() throws Exception {
        mockMvc.perform(post("/login/ott")
                        .with(csrf())
                        .accept(org.springframework.http.MediaType.TEXT_HTML)
                        .param("token", "000000"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login?error"));
    }

    // --- Token customizer ---

    @Test
    void tokenCustomizerAddsSalonsAndRolesToAccessToken() {
        var user = new SalonUser("owner@salon.com", List.of(
                new SalonInfo("s1", "OWNER", true),
                new SalonInfo("s2", "STAFF", false)
        ));
        var principal = UsernamePasswordAuthenticationToken.authenticated(
                user, null, user.getAuthorities());

        var claimsBuilder = JwtClaimsSet.builder()
                .issuer("http://localhost:9000")
                .subject("owner@salon.com")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(3600));

        var context = mock(JwtEncodingContext.class);
        when(context.getTokenType()).thenReturn(OAuth2TokenType.ACCESS_TOKEN);
        when(context.getPrincipal()).thenReturn(principal);
        when(context.getClaims()).thenReturn(claimsBuilder);

        tokenCustomizer.customize(context);

        var claims = claimsBuilder.build();
        assertThat((Object) claims.getClaim("salons")).isNotNull();
        assertThat(claims.<List<String>>getClaim("roles"))
                .containsExactly("OWNER", "STAFF");
    }

    @Test
    void tokenCustomizerSkipsNonAccessTokens() {
        var user = new SalonUser("owner@salon.com", List.of(
                new SalonInfo("s1", "OWNER", true)
        ));
        var principal = UsernamePasswordAuthenticationToken.authenticated(
                user, null, user.getAuthorities());

        var claimsBuilder = JwtClaimsSet.builder()
                .issuer("http://localhost:9000")
                .subject("owner@salon.com")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(3600));

        var context = mock(JwtEncodingContext.class);
        when(context.getTokenType()).thenReturn(new OAuth2TokenType("id_token"));
        when(context.getPrincipal()).thenReturn(principal);

        tokenCustomizer.customize(context);

        var claims = claimsBuilder.build();
        assertThat((Object) claims.getClaim("salons")).isNull();
        assertThat((Object) claims.getClaim("roles")).isNull();
    }
}
