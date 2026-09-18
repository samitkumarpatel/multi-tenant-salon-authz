package net.samitkumar.multi_tenant_salon_authz;

import net.samitkumar.multi_tenant_salon_authz.notification.NotificationService;
import net.samitkumar.multi_tenant_salon_authz.salon.SalonInfo;
import net.samitkumar.multi_tenant_salon_authz.salon.SalonUser;
import net.samitkumar.multi_tenant_salon_authz.salon.SalonUserClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.testcontainers.postgresql.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

import java.util.List;
import java.util.Map;
import java.util.Optional;

@TestConfiguration(proxyBeanMethods = false)
class TestcontainersConfiguration {

    @Bean
    @ServiceConnection
    PostgreSQLContainer postgresContainer() {
        return new PostgreSQLContainer(DockerImageName.parse("postgres:16-alpine"));
    }

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

    @Bean
    @Primary
    NotificationService inMemoryNotificationService() {
        // mailJetClient is never used below — send() is fully overridden — so null is safe here.
        return new NotificationService(null) {
            @Override
            public void send(String to, Map<String, String> metadata) {
                System.out.println("[test] Skipping real Mailjet call — would send to %s with metadata %s".formatted(to, metadata));
            }
        };
    }

    @Bean
    RegisteredClientRepository registeredClientRepository() {
        RegisteredClient oidcClient = RegisteredClient
                .withId("test-oidc-client")
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
