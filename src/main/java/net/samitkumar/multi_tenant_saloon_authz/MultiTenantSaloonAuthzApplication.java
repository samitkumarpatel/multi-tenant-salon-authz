package net.samitkumar.multi_tenant_saloon_authz;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.Nullable;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.authentication.ott.OneTimeToken;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;
import org.springframework.security.web.authentication.ott.RedirectOneTimeTokenGenerationSuccessHandler;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.support.RestClientHttpServiceGroupConfigurer;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.service.annotation.GetExchange;
import org.springframework.web.service.annotation.HttpExchange;
import org.springframework.web.service.annotation.PostExchange;
import org.springframework.web.service.registry.ImportHttpServices;
import org.springframework.web.servlet.function.RouterFunction;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import org.springframework.web.servlet.function.RouterFunctions;
import org.springframework.web.servlet.function.ServerResponse;

import java.io.IOException;
import java.security.Principal;
import java.util.Collection;
import java.util.List;
import java.util.Map;

@SpringBootApplication
@ImportHttpServices(value = SaloonUserClient.class)
@ImportHttpServices(group = "mailjet", types = {MailJetClient.class})
public class MultiTenantSaloonAuthzApplication {

    public static void main(String[] args) {
        SpringApplication.run(MultiTenantSaloonAuthzApplication.class, args);
    }

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

@Configuration
@RequiredArgsConstructor
@EnableWebSecurity
class SecurityConfig {
    final SaloonOttSuccessHandler ottSuccessHandler;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/actuator/**").permitAll()
                        .anyRequest().authenticated())
                .formLogin(AbstractHttpConfigurer::disable)
                .oneTimeTokenLogin(ott -> ott
                        .failureHandler((request, response, exception) -> {
                            response.sendRedirect("/login?error");
                        })
                        .tokenGenerationSuccessHandler(ottSuccessHandler)
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
}

@Component
@RequiredArgsConstructor
@Slf4j
class SaloonOttSuccessHandler implements OneTimeTokenGenerationSuccessHandler {
    final NotificationService notificationService;
    final SaloonUserClient saloonUserClient;
    private final OneTimeTokenGenerationSuccessHandler redirectHandler =
            new RedirectOneTimeTokenGenerationSuccessHandler("/login/ott");

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
                       OneTimeToken oneTimeToken) throws IOException, ServletException {
        try {
            saloonUserClient.getUserIdentity(oneTimeToken.getUsername());
            var tokenLink = ServletUriComponentsBuilder.fromRequest(request)
                    .replacePath("/login/ott")
                    .replaceQuery("token=" + oneTimeToken.getTokenValue())
                    .toUriString();
            notificationService.send(
                    oneTimeToken.getUsername(),
                    Map.of("token", oneTimeToken.getTokenValue(), "tokenLink", tokenLink)
            );
        } catch (Exception e) {
            log.warn("OTT suppressed — email not registered: {}", oneTimeToken.getUsername());
        }
        redirectHandler.handle(request, response, oneTimeToken);
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

@Service
@RequiredArgsConstructor
@Slf4j
class NotificationService {
    final MailJetClient mailJetClient;
    @Value("${spring.application.mailjet.sender}")
    String sender;

    void send(String to, Map<String, String> metadata) {
        log.info("Sending Mailjet notification to {} with metadata {}", to, metadata);
        var mailFrom = new MailjetEmail(sender, "My Saloon");
        var tto = new MailjetEmail(to, to);
        var token = metadata.get("token");
        var tokenLink = metadata.get("tokenLink");

        var textMessage = """
                Welcome to My Saloon!

                Your one-time login token is: %s

                Use the link below to sign in (copy and paste into your browser if it does not open):
                %s

                If you did not request this, please report it to admin@my-saloon.online
                """.formatted(token, tokenLink);

        var htmlMessage = """
                <p>Hi,</p>
                <p>Your one-time login token for <strong>My Saloon</strong> is:</p>
                <h2>%s</h2>
                <p>Or sign in directly: <a href="%s">%s</a></p>
                <p><small>If you did not request this, please contact <a href="mailto:admin@my-saloon.online">admin@my-saloon.online</a></small></p>
                """.formatted(token, tokenLink, tokenLink);
        var request = new MailjetRequest(List.of(
                new MailjetMessage(
                        mailFrom,
                        List.of(tto),
                        "OTT from my-saloon",
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
