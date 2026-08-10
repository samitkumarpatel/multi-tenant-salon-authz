package net.samitkumar.multi_tenant_saloon_authz;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
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

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@Import(TestcontainersConfiguration.class)
@SpringBootTest
class MultiTenantSaloonAuthzApplicationTests {

    @Autowired WebApplicationContext context;
    @MockitoBean SaloonUserClient saloonUserClient;
    @Autowired OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer;

    MockMvc mockMvc;

    @BeforeEach
    void setup() {
        mockMvc = MockMvcBuilders.webAppContextSetup(context)
                .apply(springSecurity())
                .build();
    }

    static final SaloonUser TEST_USER = new SaloonUser("user@salon.com", List.of(
            new SaloonInfo("saloon-1", "OWNER", true),
            new SaloonInfo("saloon-2", "STAFF", false)
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
                .andExpect(jsonPath("$.user_principal.saloons", hasSize(2)))
                .andExpect(jsonPath("$.user_principal.saloons[0].saloonId").value("saloon-1"))
                .andExpect(jsonPath("$.user_principal.saloons[0].role").value("OWNER"))
                .andExpect(jsonPath("$.user_principal.saloons[1].saloonId").value("saloon-2"))
                .andExpect(jsonPath("$.user_principal.saloons[1].role").value("STAFF"));
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

    // --- Token customizer ---

    @Test
    void tokenCustomizerAddsSaloonsAndRolesToAccessToken() {
        var user = new SaloonUser("owner@salon.com", List.of(
                new SaloonInfo("s1", "OWNER", true),
                new SaloonInfo("s2", "STAFF", false)
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
        assertThat((Object) claims.getClaim("saloons")).isNotNull();
        assertThat(claims.<List<String>>getClaim("roles"))
                .containsExactly("OWNER", "STAFF");
    }

    @Test
    void tokenCustomizerSkipsNonAccessTokens() {
        var user = new SaloonUser("owner@salon.com", List.of(
                new SaloonInfo("s1", "OWNER", true)
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
        assertThat((Object) claims.getClaim("saloons")).isNull();
        assertThat((Object) claims.getClaim("roles")).isNull();
    }
}
