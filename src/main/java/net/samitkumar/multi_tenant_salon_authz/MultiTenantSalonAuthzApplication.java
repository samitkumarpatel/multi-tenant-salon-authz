package net.samitkumar.multi_tenant_salon_authz;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.samitkumar.multi_tenant_salon_authz.notification.MailJetClient;
import net.samitkumar.multi_tenant_salon_authz.notification.NotificationService;
import net.samitkumar.multi_tenant_salon_authz.ott.OTTService;
import net.samitkumar.multi_tenant_salon_authz.salon.SalonUser;
import net.samitkumar.multi_tenant_salon_authz.salon.SalonUserClient;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
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
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.service.registry.ImportHttpServices;
import org.springframework.web.servlet.function.RouterFunction;
import org.springframework.web.servlet.function.RouterFunctions;
import org.springframework.web.servlet.function.ServerResponse;
import org.springframework.web.util.UriComponentsBuilder;

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
        return username -> salonUserClient.getUserIdentity(username).orElseThrow(UserNotfoundException::new);
    }

    @Bean
    public OneTimeTokenService oneTimeTokenService() {
        OTTService service = new OTTService();
        service.setTokenExpiresIn(Duration.ofMinutes(3));
        return service;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .cors(Customizer.withDefaults())
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/actuator/**","/ott-info.html","/ott-login","/ott-login/ask-ott").permitAll()
                        .anyRequest().authenticated())
                .formLogin(AbstractHttpConfigurer::disable)
                .oneTimeTokenLogin(ott ->
                        ott
                                .loginPage("/ott-login")
                                .loginProcessingUrl("/login/ott")
                                .showDefaultSubmitPage(false)
                                .tokenGenerationSuccessHandler((request, response, oneTimeToken) -> {
                                    try {
                                        salonUserClient.getUserIdentity(oneTimeToken.getUsername())
                                                .ifPresent(user -> {
                                                    String tokenLink = UriComponentsBuilder.fromUriString(request.getRequestURL().toString())
                                                            .replacePath(request.getContextPath())
                                                            .replaceQuery(null)
                                                            .fragment(null)
                                                            .path("/ott-login/ask-ott")
                                                            .queryParam("token", oneTimeToken.getTokenValue())
                                                            .toUriString();

                                                    notificationService.send(user.getUsername(), Map.of(
                                                            "token", oneTimeToken.getTokenValue(),
                                                            "tokenLink", tokenLink
                                                    ));
                                                });
                                        response.sendRedirect("/ott-info.html");
                                    } catch (UserNotfoundException e) {
                                        log.error("user not found", e);
                                        response.sendRedirect("/ott-login?error=");
                                    } catch (Exception e) {
                                        log.error("Error sending notification for one-time token", e);
                                        response.sendRedirect("/ott-login?error=notify");
                                    }
                        })
                )
                .oauth2AuthorizationServer(authorizationServer ->
                        authorizationServer.oidc(Customizer.withDefaults())
                );

        return http.build();
    }
}

@ResponseStatus(code = HttpStatus.NOT_FOUND, reason = "User not found")
class UserNotfoundException extends RuntimeException {

    public UserNotfoundException() {
        super("User not found");
    }
}
