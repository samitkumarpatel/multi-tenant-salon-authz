package net.samitkumar.multi_tenant_saloon_authz;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.util.HashMap;
import java.util.List;
import java.util.NoSuchElementException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@Import(TestcontainersConfiguration.class)
@SpringBootTest
class MultiTenantSaloonAuthzApplicationTests {

    @MockitoBean
    SaloonUserClient saloonUserClient;

    @Autowired
    UserDetailsService userDetailsService;

    @Autowired
    OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer;

    @Test
    void contextLoads() {
    }

    @Test
    void userDetailsServiceLoadsUserFromSaloonClient() {
        var alice = new SaloonUser("alice@example.com", "owner", "saloon-1", true);
        when(saloonUserClient.getUserIdentities("alice@example.com")).thenReturn(List.of(alice));

        var result = (SaloonUser) userDetailsService.loadUserByUsername("alice@example.com");

        assertThat(result.email()).isEqualTo("alice@example.com");
        assertThat(result.role()).isEqualTo("owner");
        assertThat(result.saloonId()).isEqualTo("saloon-1");
        assertThat(result.active()).isTrue();
    }

    @Test
    void userDetailsServiceThrowsWhenUserNotFound() {
        when(saloonUserClient.getUserIdentities("ghost@example.com")).thenReturn(List.of());

        assertThatThrownBy(() -> userDetailsService.loadUserByUsername("ghost@example.com"))
                .isInstanceOf(NoSuchElementException.class);
    }

    @Test
    void tokenCustomizerAddsRoleAndSaloonIdToAccessToken() {
        var user = new SaloonUser("alice@example.com", "OWNER", "saloon-abc", true);
        Authentication auth = mock(Authentication.class);
        when(auth.getPrincipal()).thenReturn(user);

        var captured = new HashMap<String, Object>();
        JwtClaimsSet.Builder claimsBuilder = mock(JwtClaimsSet.Builder.class);
        when(claimsBuilder.claim(anyString(), any())).thenAnswer(inv -> {
            captured.put(inv.getArgument(0), inv.getArgument(1));
            return claimsBuilder;
        });

        JwtEncodingContext context = mock(JwtEncodingContext.class);
        when(context.getTokenType()).thenReturn(OAuth2TokenType.ACCESS_TOKEN);
        when(context.getPrincipal()).thenReturn(auth);
        when(context.getClaims()).thenReturn(claimsBuilder);

        tokenCustomizer.customize(context);

        assertThat(captured)
                .containsEntry("roles", "OWNER")
                .containsEntry("saloon_ids", "saloon-abc");
    }

    @Test
    void tokenCustomizerSkipsNonAccessTokens() {
        JwtEncodingContext context = mock(JwtEncodingContext.class);
        when(context.getTokenType()).thenReturn(OAuth2TokenType.REFRESH_TOKEN);

        tokenCustomizer.customize(context);

        verify(context, never()).getPrincipal();
        verify(context, never()).getClaims();
    }

    @Test
    void tokenCustomizerSkipsNonSaloonUserPrincipal() {
        Authentication auth = mock(Authentication.class);
        when(auth.getPrincipal()).thenReturn("plain-string-principal");

        JwtEncodingContext context = mock(JwtEncodingContext.class);
        when(context.getTokenType()).thenReturn(OAuth2TokenType.ACCESS_TOKEN);
        when(context.getPrincipal()).thenReturn(auth);

        tokenCustomizer.customize(context);

        verify(context, never()).getClaims();
    }
}
