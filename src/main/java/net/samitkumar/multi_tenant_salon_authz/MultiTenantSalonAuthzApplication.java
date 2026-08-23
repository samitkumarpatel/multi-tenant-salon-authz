package net.samitkumar.multi_tenant_salon_authz;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.samitkumar.multi_tenant_salon_authz.notification.MailJetClient;
import net.samitkumar.multi_tenant_salon_authz.notification.NotificationService;
import net.samitkumar.multi_tenant_salon_authz.ott.CustomOTTService;
import net.samitkumar.multi_tenant_salon_authz.salon.SalonUser;
import net.samitkumar.multi_tenant_salon_authz.salon.SalonUserClient;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.ott.OneTimeTokenService;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.client.support.RestClientHttpServiceGroupConfigurer;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.service.registry.ImportHttpServices;
import org.springframework.web.servlet.function.RouterFunction;
import org.springframework.web.servlet.function.RouterFunctions;
import org.springframework.web.servlet.function.ServerResponse;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.security.Principal;
import java.time.Duration;
import java.util.Map;

@SpringBootApplication
@ImportHttpServices(value = SalonUserClient.class)
@ImportHttpServices(group = "mailjet", types = {MailJetClient.class})
public class MultiTenantSalonAuthzApplication {

    public static void main(String[] args) {
        SpringApplication.run(MultiTenantSalonAuthzApplication.class, args);
    }

    @Bean
    RouterFunction<ServerResponse> routerFunction() {
        return RouterFunctions
                .route()
                .GET("/ping", request -> {

                    var salonUser = request.principal()
                            .map(p -> (SalonUser) ((Authentication) p).getPrincipal())
                            .orElse(null);

                    return ServerResponse.ok().body(
                            Map.of(
                                    "message", "PONG",
                                    "requester", request.principal().map(Principal::getName).orElse("anonymous"),
                                    "user_principal", salonUser != null ? salonUser : Map.of()
                            )
                    );
                })
                .build();
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

    @Bean
    RestClientHttpServiceGroupConfigurer mailjetGroupConfigurer(
            @Value("${spring.application.mailjet.api-key}") String apiKey,
            @Value("${spring.application.mailjet.api-secret}") String apiSecret) {
        return groups -> groups.filterByName("mailjet")
                .forEachClient((name, builder) ->
                        builder.defaultHeaders(h -> h.setBasicAuth(apiKey, apiSecret)));
    }
}

@Slf4j
@Configuration
@RequiredArgsConstructor
@EnableWebSecurity
class SecurityConfig {
    final NotificationService notificationService;
    final SalonUserClient salonUserClient;

    @Bean
    OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
        return context -> {
            if (!context.getTokenType().equals(OAuth2TokenType.ACCESS_TOKEN)) return;
            if (!(context.getPrincipal().getPrincipal() instanceof SalonUser user)) return;

            context.getClaims()
                    .claim("salons", user.salons())
                    .claim("roles", user.getAuthorities().stream()
                            .map(GrantedAuthority::getAuthority)
                            .toList());
        };
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
    UserDetailsService userDetailsService() {
        return username -> salonUserClient.getUserIdentity(username).orElseThrow();
    }

    @Bean
    public OneTimeTokenService oneTimeTokenService() {
        CustomOTTService service = new CustomOTTService();
        service.setTokenExpiresIn(Duration.ofMinutes(3));
        return service;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/actuator/**","/ott-info.html","/login","/login/ask-ott").permitAll()
                        .anyRequest().authenticated())
                .oneTimeTokenLogin(ott -> ott
                        .loginPage("/login")
                        .loginProcessingUrl("/login/ott")
                        .showDefaultSubmitPage(false)
                        .tokenGenerationSuccessHandler((request, response, oneTimeToken) -> {
                            try {
                                salonUserClient.getUserIdentity(oneTimeToken.getUsername())
                                        .ifPresent(user -> {
                                            String tokenLink = ServletUriComponentsBuilder.fromCurrentContextPath()
                                                    .path("/login/ask-ott")
                                                    .queryParam("token", oneTimeToken.getTokenValue())
                                                    .toUriString();
                                            notificationService.send(user.getUsername(), Map.of(
                                                    "token", oneTimeToken.getTokenValue(),
                                                    "tokenLink", tokenLink
                                            ));
                                        });
                                response.sendRedirect("/ott-info.html");
                            } catch (Exception e) {
                                log.error("Error sending notification for one-time token", e);
                                response.sendRedirect("/login?error=notify");
                            }

                        })
                )
                .formLogin(AbstractHttpConfigurer::disable)
                .oauth2AuthorizationServer(authorizationServer ->
                        authorizationServer.oidc(Customizer.withDefaults())
                )
                .cors(Customizer.withDefaults());

        return http.build();
    }
}

