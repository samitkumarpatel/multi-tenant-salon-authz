package net.samitkumar.multi_tenant_salon_authz;

import net.samitkumar.multi_tenant_salon_authz.notification.NotificationService;
import net.samitkumar.multi_tenant_salon_authz.salon.SalonInfo;
import net.samitkumar.multi_tenant_salon_authz.salon.SalonUser;
import net.samitkumar.multi_tenant_salon_authz.salon.SalonUserClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

import java.util.List;
import java.util.Map;
import java.util.Optional;

@TestConfiguration(proxyBeanMethods = false)
class TestcontainersConfiguration {

    /**
     * Stands in for the real {@code SalonUserClient} HTTP client so a local/test run never
     * calls out to the identity service. {@code @Primary} so it wins over the real client bean;
     * {@link net.samitkumar.multi_tenant_salon_authz.MultiTenantSalonAuthzApplicationTests} still
     * replaces this exact bean (by name) with a Mockito mock where it needs per-test stubbing.
     */
    @Bean
    @Primary
    SalonUserClient inMemorySalonUserClient() {
        Map<String, SalonUser> users = Map.of(
                "owner@salon.com", new SalonUser("owner@salon.com", List.of(
                        new SalonInfo("salon-1", "OWNER", true)
                )),
                "staff@salon.com", new SalonUser("staff@salon.com", List.of(
                        new SalonInfo("salon-1", "STAFF", true)
                )),
                "user@salon.com", new SalonUser("user@salon.com", List.of(
                        new SalonInfo("salon-1", "OWNER", true),
                        new SalonInfo("salon-2", "STAFF", false)
                ))
        );
        return email -> Optional.ofNullable(users.get(email));
    }

    /**
     * Stands in for the real {@code NotificationService} so a local/test run never calls the
     * real Mailjet API — it just logs what would have been sent. Same {@code @Primary} +
     * named-bean pattern as {@link #inMemorySalonUserClient()}, for the same reason.
     */
    @Bean
    @Primary
    NotificationService inMemoryNotificationService() {
        Logger log = LoggerFactory.getLogger(NotificationService.class);
        // mailJetClient is never used below — send() is fully overridden — so null is safe here.
        return new NotificationService(null) {
            @Override
            public void send(String to, Map<String, String> metadata) {
                log.info("[test] Skipping real Mailjet call — would send to {} with metadata {}", to, metadata);
            }
        };
    }

    @Bean
    RegisteredClientRepository registeredClientRepository() {
        RegisteredClient oidcClient = RegisteredClient.withId("test-oidc-client")
                .clientId("oidc-client")
                .clientSecret("{noop}secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("http://127.0.0.1:8080/login/oauth2/code/oidc-client")
                .postLogoutRedirectUri("http://127.0.0.1:8080/")
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
                .build();
        return new InMemoryRegisteredClientRepository(oidcClient);
    }
}
