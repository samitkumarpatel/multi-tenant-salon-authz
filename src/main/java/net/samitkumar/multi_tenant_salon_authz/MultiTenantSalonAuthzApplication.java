package net.samitkumar.multi_tenant_salon_authz;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.Nullable;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.ott.*;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.support.RestClientHttpServiceGroupConfigurer;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.service.annotation.GetExchange;
import org.springframework.web.service.annotation.HttpExchange;
import org.springframework.web.service.annotation.PostExchange;
import org.springframework.web.service.registry.ImportHttpServices;
import org.springframework.web.servlet.function.RouterFunction;
import org.springframework.web.servlet.function.RouterFunctions;
import org.springframework.web.servlet.function.ServerResponse;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.security.Principal;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

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
                        .requestMatchers("/actuator/**","/ott-info.html").permitAll()
                        .anyRequest().authenticated())
                .oneTimeTokenLogin(ott -> ott
                        .tokenGenerationSuccessHandler((request, response, oneTimeToken) -> {
                            try {
                                salonUserClient.getUserIdentity(oneTimeToken.getUsername())
                                        .ifPresent(user -> {
                                            String tokenLink = ServletUriComponentsBuilder.fromCurrentContextPath()
                                                    .path("/login/ott")
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
                                response.sendRedirect("/login?error");
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

class CustomOTTService implements OneTimeTokenService {

    private static final int PIN_LENGTH = 6;
    private static final int MAX_PIN_VALUE = 100_000;

    private final Map<String, OneTimeToken> oneTimeTokenByToken = new ConcurrentHashMap<>();
    private final SecureRandom secureRandom = new SecureRandom();

    private Clock clock = Clock.systemUTC();
    // Consider setting a shorter expiration time for these PINs (typically 5-10 minutes for SMS codes) since they're more susceptible to brute force than UUIDs
    private Duration tokenExpiresIn = Duration.ofMinutes(5);

    @Override
    public OneTimeToken generate(GenerateOneTimeTokenRequest request) {
        String token = generatePin();
        Instant expiresAt = this.clock.instant().plus(this.tokenExpiresIn);
        OneTimeToken ott = new DefaultOneTimeToken(token, request.getUsername(), expiresAt);
        this.oneTimeTokenByToken.put(token, ott);
        cleanExpiredTokensIfNeeded();
        return ott;
    }

    @Override
    public @Nullable OneTimeToken consume(OneTimeTokenAuthenticationToken authenticationToken) {
        OneTimeToken ott = this.oneTimeTokenByToken.remove(authenticationToken.getTokenValue());
        if (ott == null || isExpired(ott)) {
            return null;
        }
        return ott;
    }

    public void setTokenExpiresIn(Duration tokenExpiresIn) {
        Assert.notNull(tokenExpiresIn, "tokenExpiresIn cannot be null");
        Assert.isTrue(!tokenExpiresIn.isNegative() && !tokenExpiresIn.isZero(),
                "tokenExpiresIn must be positive");
        this.tokenExpiresIn = tokenExpiresIn;
    }

    private String generatePin() {
        int pin = secureRandom.nextInt(MAX_PIN_VALUE);
        return String.format("%0" + PIN_LENGTH + "d", pin);
    }

    private void cleanExpiredTokensIfNeeded() {
        if (this.oneTimeTokenByToken.size() < 100) {
            return;
        }
        for (Map.Entry<String, OneTimeToken> entry : this.oneTimeTokenByToken.entrySet()) {
            if (isExpired(entry.getValue())) {
                this.oneTimeTokenByToken.remove(entry.getKey());
            }
        }
    }

    private boolean isExpired(OneTimeToken ott) {
        return this.clock.instant().isAfter(ott.getExpiresAt());
    }
}

@HttpExchange(url = "${spring.application.identity-service-url}")
interface SalonUserClient {
    @GetExchange("/internal/user-identity")
    Optional<SalonUser> getUserIdentity(@RequestParam("email") String email);
}

record SalonInfo(String salonId, String role, Boolean active) {}

record SalonUser(String email, List<SalonInfo> salons) implements UserDetails {
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return salons.stream()
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

@Service
@RequiredArgsConstructor
@Slf4j
class NotificationService {
    final MailJetClient mailJetClient;
    @Value("${spring.application.mailjet.sender}")
    String sender;

    void send(String to, Map<String, String> metadata) {
        log.info("Sending Mailjet notification to {} with metadata {}", to, metadata);
        var mailFrom = new MailjetEmail(sender, "My Salon");
        var tto = new MailjetEmail(to, to);
        var token = metadata.get("token");
        var tokenLink = metadata.get("tokenLink");

        var textMessage = """
                Welcome to My Salon!

                Your one-time login token is: %s

                Use the link below to sign in (copy and paste into your browser if it does not open):
                %s

                If you did not request this, please report it to admin@salonsaas.org
                """.formatted(token, tokenLink);

        var htmlMessage = """
                <p>Hi,</p>
                <p>Your one-time login token for <strong>My Salon</strong> is:</p>
                <h2>%s</h2>
                <p>Or sign in directly: <a href="%s">%s</a></p>
                <p><small>If you did not request this, please contact <a href="mailto:admin@salonsaas.org">admin@salonsaas.org</a></small></p>
                """.formatted(token, tokenLink, tokenLink);
        var request = new MailjetRequest(List.of(
                new MailjetMessage(
                        mailFrom,
                        List.of(tto),
                        "SaloonSaaS OTT",
                        textMessage,
                        htmlMessage
                )
        ));

        var result = mailJetClient.send(request);
        log.info("Mailjet send result: {}", result);
    }
}

record MailjetEmail(
        @JsonProperty("Email") String email,
        @JsonProperty("Name") String name) {}

record MailjetMessage(
        @JsonProperty("From") MailjetEmail from,
        @JsonProperty("To") List<MailjetEmail> to,
        @JsonProperty("Subject") String subject,
        @JsonProperty("TextPart") String textPart,
        @JsonProperty("HTMLPart") String htmlPart) {}

record MailjetRequest(@JsonProperty("Messages") List<MailjetMessage> messages) {}

@HttpExchange("https://api.mailjet.com/v3.1")
interface MailJetClient {
    @PostExchange("/send")
    Map<String, Object> send(@RequestBody MailjetRequest request);
}
