package net.samitkumar.multi_tenant_salon_authz.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.samitkumar.multi_tenant_salon_authz.notification.NotificationService;
import net.samitkumar.multi_tenant_salon_authz.ott.OTTService;
import net.samitkumar.multi_tenant_salon_authz.salon.SalonUser;
import net.samitkumar.multi_tenant_salon_authz.salon.SalonUserClient;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.ott.OneTimeTokenService;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.ott.DefaultGenerateOneTimeTokenRequestResolver;
import org.springframework.security.web.authentication.ott.GenerateOneTimeTokenRequestResolver;
import org.springframework.web.util.UriComponentsBuilder;

import java.time.Duration;
import java.util.HashMap;
import java.util.Optional;

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

    /**
     * Picks the token format before {@link OTTService#generate} runs: a short PIN when the
     * user asked for the 6-digit code delivery, a UUID (Spring's own default) otherwise, since
     * a magic-link token is only ever clicked, never typed.
     */
    @Bean
    public GenerateOneTimeTokenRequestResolver generateOneTimeTokenRequestResolver() {
        var delegate = new DefaultGenerateOneTimeTokenRequestResolver();
        return request -> {
            boolean shortToken = "short-token".equals(request.getParameter("loginType"));
            OTTService.useTokenFormatForNextGeneration(shortToken ? OTTService.TokenFormat.PIN : OTTService.TokenFormat.UUID);
            return delegate.resolve(request);
        };
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .cors(Customizer.withDefaults())
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/actuator/**", "/ott/login", "/ott/input", "/ott/sent", "/logout").permitAll()
                        .anyRequest().authenticated())
                .formLogin(AbstractHttpConfigurer::disable)
                .oidcLogout(Customizer.withDefaults())
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessUrl("/ott/login?logout")
                )
                .oneTimeTokenLogin(ott ->
                        ott
                                .loginPage("/ott/login")
                                .loginProcessingUrl("/login/ott")
                                .showDefaultSubmitPage(false)
                                .tokenGenerationSuccessHandler((request, response, oneTimeToken) -> {
                                    boolean magicLink = "magic-link".equals(request.getParameter("loginType"));

                                    Optional<SalonUser> user;
                                    try {
                                        user = salonUserClient.getUserIdentity(oneTimeToken.getUsername());
                                    } catch (Exception e) {
                                        log.error("Unable to look up user identity for one-time token request", e);
                                        response.sendRedirect("/ott/login?error=notify");
                                        return;
                                    }

                                    try {
                                        // An empty Optional just means no account exists for this email. We still
                                        // redirect to the same "check your email"/"enter your code" page below
                                        // either way, so the login form never reveals whether an email is
                                        // registered - this prevents user enumeration.
                                        user.ifPresent(u -> {
                                            var metadata = new HashMap<String, String>();
                                            metadata.put("token", oneTimeToken.getTokenValue());
                                            if (magicLink) {
                                                String tokenLink = UriComponentsBuilder.fromUriString(request.getRequestURL().toString())
                                                        .replacePath(request.getContextPath())
                                                        .replaceQuery(null)
                                                        .fragment(null)
                                                        .path("/ott/input")
                                                        .queryParam("token", oneTimeToken.getTokenValue())
                                                        .toUriString();
                                                metadata.put("tokenLink", tokenLink);
                                            }
                                            notificationService.send(u.getUsername(), metadata);
                                        });
                                        response.sendRedirect(magicLink ? "/ott/sent" : "/ott/input");
                                    } catch (Exception e) {
                                        log.error("Error sending notification for one-time token", e);
                                        response.sendRedirect("/ott/login?error=notify");
                                    }
                                })
                )
                .oauth2AuthorizationServer(authorizationServer ->
                        authorizationServer.oidc(Customizer.withDefaults())
                );

        return http.build();
    }
}
