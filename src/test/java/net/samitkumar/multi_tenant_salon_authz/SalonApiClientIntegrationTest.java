package net.samitkumar.multi_tenant_salon_authz;

import com.jayway.jsonpath.JsonPath;
import net.samitkumar.multi_tenant_salon_authz.notification.NotificationService;
import net.samitkumar.multi_tenant_salon_authz.salon.SalonUserClient;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** A salon's API clients: created by the salon API only, bound to one salon, short-lived read-only tokens. */
@Import(TestcontainersConfiguration.class)
@SpringBootTest(properties = "spring.application.client-management.api-key=test-key")
class SalonApiClientIntegrationTest {
    static final String KEY = "test-key";

    @Autowired WebApplicationContext context;
    @MockitoBean(name = "inMemorySalonUserClient") SalonUserClient salonUserClient;
    @MockitoBean(name = "inMemoryNotificationService") NotificationService notificationService;

    MockMvc mvc;
    UUID salonA;
    UUID salonB;

    @BeforeEach
    void setUp() {
        mvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
        salonA = UUID.randomUUID();
        salonB = UUID.randomUUID();
    }

    @Test
    void managementEndpointsNeedTheKeyAndRefuseTheIngress() throws Exception {
        mvc.perform(get("/internal/clients").param("salonId", salonA.toString())).andExpect(status().isUnauthorized());
        mvc.perform(get("/internal/clients").param("salonId", salonA.toString()).header("X-Internal-Api-Key", "wrong")).andExpect(status().isUnauthorized());
        // Anything that came through the public ingress carries X-Forwarded-Host and is refused even with the key.
        mvc.perform(get("/internal/clients").param("salonId", salonA.toString()).header("X-Internal-Api-Key", KEY).header("X-Forwarded-Host", "auth.salonsaas.org"))
                .andExpect(status().isNotFound());
        mvc.perform(get("/internal/clients").param("salonId", salonA.toString()).header("X-Internal-Api-Key", KEY)).andExpect(status().isOk());
    }

    @Test
    void aSalonsClientGetsAShortReadOnlyTokenBoundToThatSalon() throws Exception {
        var created = create(salonA, "Accounting sync", List.of("bookings:read", "services:read"));
        var clientId = JsonPath.<String>read(created, "$.client.clientId");
        var secret = JsonPath.<String>read(created, "$.clientSecret");
        assertThat(clientId).startsWith("sc_");

        var token = token(clientId, secret, "bookings:read").andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        assertThat(JsonPath.<Integer>read(token, "$.expires_in")).isLessThanOrEqualTo(900);
        var claims = claims(JsonPath.read(token, "$.access_token"));
        assertThat(JsonPath.<String>read(claims, "$.salon_id")).isEqualTo(salonA.toString());
        assertThat(JsonPath.<String>read(claims, "$.client_type")).isEqualTo("salon-api");
        assertThat(JsonPath.<String>read(claims, "$.sub")).isEqualTo(clientId);
        assertThat(JsonPath.<List<String>>read(claims, "$.scope")).containsExactly("bookings:read");
        // No claims the API trusts for people.
        assertThat(claims).doesNotContain("\"roles\"").doesNotContain("\"salons\"");

        // A scope the client wasn't registered with can't be requested, and a bad secret gets nothing.
        token(clientId, secret, "orders:read").andExpect(status().isBadRequest());
        token(clientId, "not-the-secret", "bookings:read").andExpect(status().isUnauthorized());
    }

    @Test
    void oneSalonCannotSeeRotateOrRevokeAnotherSalonsClients() throws Exception {
        var clientId = JsonPath.<String>read(create(salonA, "Mine", List.of("services:read")), "$.client.clientId");

        assertThat(JsonPath.<List<?>>read(list(salonB), "$")).isEmpty();
        assertThat(JsonPath.<List<?>>read(list(salonA), "$")).hasSize(1);
        mvc.perform(post("/internal/clients/{id}/rotate", clientId).param("salonId", salonB.toString()).header("X-Internal-Api-Key", KEY)).andExpect(status().isNotFound());
        mvc.perform(delete("/internal/clients/{id}", clientId).param("salonId", salonB.toString()).header("X-Internal-Api-Key", KEY)).andExpect(status().isNotFound());
        assertThat(JsonPath.<List<?>>read(list(salonA), "$")).as("untouched by the other salon").hasSize(1);
    }

    @Test
    void rotatingReplacesTheSecretAndRevokingStopsNewTokens() throws Exception {
        var created = create(salonA, "Sync", List.of("bookings:read"));
        var clientId = JsonPath.<String>read(created, "$.client.clientId");
        var oldSecret = JsonPath.<String>read(created, "$.clientSecret");

        var rotated = mvc.perform(post("/internal/clients/{id}/rotate", clientId).param("salonId", salonA.toString()).header("X-Internal-Api-Key", KEY))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        var newSecret = JsonPath.<String>read(rotated, "$.clientSecret");
        assertThat(newSecret).isNotEqualTo(oldSecret);
        token(clientId, oldSecret, "bookings:read").andExpect(status().isUnauthorized());
        token(clientId, newSecret, "bookings:read").andExpect(status().isOk());

        mvc.perform(delete("/internal/clients/{id}", clientId).param("salonId", salonA.toString()).param("actor", "owner@a.test").header("X-Internal-Api-Key", KEY))
                .andExpect(status().isNoContent());
        token(clientId, newSecret, "bookings:read").andExpect(status().isUnauthorized());
        assertThat(JsonPath.<List<?>>read(list(salonA), "$")).isEmpty();
    }

    @Test
    void validatesInputAndCapsClientsPerSalon() throws Exception {
        createRaw(salonA, "", List.of("bookings:read")).andExpect(status().isBadRequest());
        createRaw(salonA, "No scopes", List.of()).andExpect(status().isBadRequest());
        createRaw(salonA, "Bad scope", List.of("admin:write")).andExpect(status().isBadRequest());
        createRaw(salonA, "Customers (personal data)", List.of("customers:read")).andExpect(status().isCreated());

        for (int i = 0; i < 4; i++) create(salonA, "Client " + i, List.of("services:read"));
        createRaw(salonA, "One too many", List.of("services:read")).andExpect(status().isConflict());
        create(salonB, "Other salon is unaffected", List.of("services:read"));
    }

    // ── helpers ──

    private String create(UUID salon, String name, List<String> scopes) throws Exception {
        return createRaw(salon, name, scopes).andExpect(status().isCreated()).andReturn().getResponse().getContentAsString();
    }

    private ResultActions createRaw(UUID salon, String name, List<String> scopes) throws Exception {
        return mvc.perform(post("/internal/clients").header("X-Internal-Api-Key", KEY).contentType(MediaType.APPLICATION_JSON)
                .content(new tools.jackson.databind.json.JsonMapper().writeValueAsString(Map.of("salonId", salon.toString(), "name", name, "scopes", scopes, "createdBy", "owner@a.test"))));
    }

    private String list(UUID salon) throws Exception {
        return mvc.perform(get("/internal/clients").param("salonId", salon.toString()).header("X-Internal-Api-Key", KEY))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
    }

    private ResultActions token(String clientId, String secret, String scope) throws Exception {
        var basic = Base64.getEncoder().encodeToString((clientId + ":" + secret).getBytes(StandardCharsets.UTF_8));
        return mvc.perform(post("/oauth2/token").header("Authorization", "Basic " + basic)
                .param("grant_type", "client_credentials").param("scope", scope));
    }

    private static String claims(String jwt) {
        return new String(Base64.getUrlDecoder().decode(jwt.split("\\.")[1]), StandardCharsets.UTF_8);
    }
}
