package net.samitkumar.multi_tenant_saloon_authz;

import com.fasterxml.jackson.annotation.JsonIgnore;
import org.jspecify.annotations.Nullable;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.service.annotation.GetExchange;
import org.springframework.web.service.annotation.HttpExchange;
import org.springframework.web.service.registry.ImportHttpServices;
import org.springframework.web.servlet.function.RouterFunction;
import org.springframework.web.servlet.function.RouterFunctions;
import org.springframework.web.servlet.function.ServerResponse;

import java.security.Principal;
import java.util.Collection;
import java.util.List;
import java.util.Map;

@SpringBootApplication
@ImportHttpServices(value = SaloonUserClient.class)
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

    // Enriches the JWT access token with roles and saloon IDs derived from the view.
    /*@Bean
    OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
        return context -> {
            if (!context.getTokenType().equals(OAuth2TokenType.ACCESS_TOKEN)) return;
            if (!(context.getPrincipal().getPrincipal() instanceof SaloonUser user)) return;

            context.getClaims()
                    .claim("saloons", user.saloons());
        };
    }*/

    @Bean
    RouterFunction<ServerResponse> routerFunction() {
        return RouterFunctions
                .route()
                .GET("/ping", request -> {

                    var saloonUser = request.principal()
                            .map(p -> (SaloonUser) ((Authentication) p).getPrincipal())
                            .orElse(null);

                    return ServerResponse.ok().body(
                            Map.of(
                                    "message", "PONG",
                                    "requester", request.principal().map(Principal::getName).orElse("anonymous"),
                                    "user_principal", saloonUser != null ? saloonUser : Map.of()
                            )
                    );
                })
                .build();
    }

    /*@Bean
    Customizer<HttpSecurity> httpSecCustomizer() {
        return http -> http
                .authorizeHttpRequests(authz -> {
                    authz.requestMatchers("/oauth2/register").permitAll();
                })
                .formLogin(AbstractHttpConfigurer::disable)
                .oneTimeTokenLogin(ott -> {
                    ott.tokenGenerationSuccessHandler((request, response, oneTimeToken) -> {
                        IO.println("### OTT value=" + oneTimeToken.getTokenValue());
                        response.sendRedirect("/login/ott");
                    });
                });
    }

    @Bean
    Customizer<OAuth2AuthorizationServerConfigurer> authzServerConfigurer() {
        return authzServer -> {
            authzServer.clientRegistrationEndpoint(reg -> reg.openRegistrationAllowed(true));
            authzServer.oidc(oidc -> oidc.providerConfigurationEndpoint(
                    pce -> pce.providerConfigurationCustomizer(config -> config.claim("name", "Samit"))));
        };
    }*/

    @Bean
    UserDetailsService userDetailsService(SaloonUserClient saloonUserClient) {
        return saloonUserClient::getUserIdentity;
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource(@Value("${spring.application.cors-allowed-origin-pattern}") String corsAllowedOriginPattern) {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();
        config.addAllowedHeader("*");
        config.addAllowedMethod("*");
        config.addAllowedOriginPattern(corsAllowedOriginPattern);
        config.setAllowCredentials(true);
        source.registerCorsConfiguration("/**", config);
        return source;
    }
}

@HttpExchange(url = "${spring.application.identity-service-url}")
interface SaloonUserClient {
    @GetExchange("/internal/user-identity")
    SaloonUser getUserIdentity(@RequestParam("email") String email);
}

record SaloonInfo(String saloonId, String role, Boolean active) {}

record SaloonUser(String email, List<SaloonInfo> saloons) implements UserDetails {
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return saloons.stream()
                .map(s -> (GrantedAuthority) s::role)
                .toList();
    }

    @Override
    @JsonIgnore
    public @Nullable String getPassword() {
        return "";
    }

    @Override
    public String getUsername() {
        return email;
    }
}