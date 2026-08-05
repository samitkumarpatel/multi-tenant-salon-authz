package net.samitkumar.multi_tenant_saloon_authz;

import org.jspecify.annotations.Nullable;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.service.annotation.GetExchange;
import org.springframework.web.service.annotation.HttpExchange;
import org.springframework.web.service.registry.ImportHttpServices;

import java.util.Collection;
import java.util.List;

@SpringBootApplication
@EnableWebSecurity
@ImportHttpServices(value = SaloonUserClient.class, group = "saloon")
public class MultiTenantSaloonAuthzApplication {

    public static void main(String[] args) {
        SpringApplication.run(MultiTenantSaloonAuthzApplication.class, args);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
            .formLogin(AbstractHttpConfigurer::disable)
            .oneTimeTokenLogin(ott -> ott
                .tokenGenerationSuccessHandler((request, response, oneTimeToken) -> {
                    // TODO: replace with real email delivery (SES / SMTP)
                    IO.println("### OTT link: /login/ott?token=" + oneTimeToken.getTokenValue());
                    response.sendRedirect("/login/ott");
                })
            )
            .oauth2AuthorizationServer(authorizationServer ->
                authorizationServer.oidc(Customizer.withDefaults())
            );

        return http.build();
    }

    @Bean
    UserDetailsService userDetailsService(SaloonUserClient saloonUserClient) {
        return username -> saloonUserClient.getUserIdentities(username).getFirst();
    }

    // Enriches the JWT access token with roles and saloon IDs derived from the view.
    @Bean
    OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
        return context -> {
            if (!context.getTokenType().equals(OAuth2TokenType.ACCESS_TOKEN)) return;
            if (!(context.getPrincipal().getPrincipal() instanceof SaloonUser user)) return;

            context.getClaims()
                    .claim("roles", user.role())
                    .claim("saloon_ids", user.saloonId());
        };
    }
}

@HttpExchange(url = "")
interface SaloonUserClient {
    @GetExchange("/internal/user-identity")
    List<SaloonUser> getUserIdentities(@RequestParam("email") String email);
}

record SaloonUser(String email, String role, String saloonId, Boolean active) implements UserDetails {
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(this::role);
    }

    @Override
    public @Nullable String getPassword() {
        return "";
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return UserDetails.super.isAccountNonExpired();
    }

    @Override
    public boolean isAccountNonLocked() {
        return UserDetails.super.isAccountNonLocked();
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return UserDetails.super.isCredentialsNonExpired();
    }

    @Override
    public boolean isEnabled() {
        return UserDetails.super.isEnabled();
    }
}