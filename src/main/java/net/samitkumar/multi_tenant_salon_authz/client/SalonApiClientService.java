package net.samitkumar.multi_tenant_salon_authz.client;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;

/**
 * API clients owned by one salon: {@code client_credentials} only, read scopes only, tied to a salon for life.
 * Every operation is scoped by the salon id the caller passes, so one salon can never list, rotate or revoke another's.
 */
@Service
class SalonApiClientService {
    static final Set<String> ALLOWED_SCOPES = Set.of(
            "bookings:read", "services:read", "staff:read", "ratings:read", "orders:read", "customers:read", "loyalty:read");

    record ClientView(String clientId, String name, UUID salonId, List<String> scopes, String createdBy,
                      Instant createdAt, Instant secretRotatedAt) {}

    /** The secret is only ever returned here, once; afterwards only its hash exists. */
    record CreatedClient(ClientView client, String clientSecret) {}

    static final class ClientException extends RuntimeException {
        final int status;
        ClientException(int status, String message) { super(message); this.status = status; }
    }

    private static final SecureRandom RANDOM = new SecureRandom();
    private final PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
    private final JdbcClient jdbc;
    private final RegisteredClientRepository clients;
    private final int maxClientsPerSalon;
    private final Duration tokenTtl;

    SalonApiClientService(JdbcClient jdbc, RegisteredClientRepository clients,
                          @Value("${spring.application.client-management.max-clients-per-salon:5}") int maxClientsPerSalon,
                          @Value("${spring.application.client-management.token-ttl:PT15M}") Duration tokenTtl) {
        this.jdbc = jdbc;
        this.clients = clients;
        this.maxClientsPerSalon = maxClientsPerSalon;
        this.tokenTtl = tokenTtl;
    }

    List<ClientView> list(UUID salonId) {
        return jdbc.sql("""
                SELECT client_id, name, salon_id, scopes, created_by, created_at, secret_rotated_at FROM salon_api_client
                WHERE salon_id = :salon AND revoked_at IS NULL ORDER BY created_at, client_id
                """).param("salon", salonId).query(SalonApiClientService::view).list();
    }

    @Transactional
    CreatedClient create(UUID salonId, String rawName, List<String> rawScopes, String createdBy) {
        var name = rawName == null ? "" : rawName.strip();
        if (name.isEmpty() || name.length() > 80) throw new ClientException(400, "A client needs a name of up to 80 characters");
        var scopes = new TreeSet<>(rawScopes == null ? List.<String>of() : rawScopes);
        if (scopes.isEmpty() || !ALLOWED_SCOPES.containsAll(scopes)) throw new ClientException(400, "Choose one or more of: " + new TreeSet<>(ALLOWED_SCOPES));
        if (createdBy == null || createdBy.isBlank()) throw new ClientException(400, "createdBy is required");

        // Serialize creations for one salon so concurrent requests cannot exceed the limit.
        jdbc.sql("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))").param("key", "salon-api-client|" + salonId).query((rs, i) -> 1).list();
        int active = jdbc.sql("SELECT count(*) FROM salon_api_client WHERE salon_id = :salon AND revoked_at IS NULL").param("salon", salonId).query(Integer.class).single();
        if (active >= maxClientsPerSalon) throw new ClientException(409, "This salon already has " + maxClientsPerSalon + " API clients; revoke one first");

        var clientId = "sc_" + token(12);
        var secret = token(32);
        var registered = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(clientId)
                .clientSecret(encoder.encode(secret))
                .clientName(name)
                .clientIdIssuedAt(Instant.now())
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scopes(s -> s.addAll(scopes))
                .clientSettings(ClientSettings.builder().setting(ApiClients.SALON_ID_SETTING, salonId.toString()).build())
                .tokenSettings(TokenSettings.builder().accessTokenTimeToLive(tokenTtl).build())
                .build();
        clients.save(registered);
        jdbc.sql("""
                INSERT INTO salon_api_client (client_id, registered_client_id, salon_id, name, scopes, created_by)
                VALUES (:clientId, :registeredId, :salon, :name, :scopes, :createdBy)
                """).param("clientId", clientId).param("registeredId", registered.getId()).param("salon", salonId)
                .param("name", name).param("scopes", String.join(" ", scopes)).param("createdBy", createdBy.strip()).update();
        return new CreatedClient(find(salonId, clientId), secret);
    }

    /** Issues a new secret; the old one stops working immediately. */
    @Transactional
    CreatedClient rotate(UUID salonId, String clientId) {
        var row = active(salonId, clientId);
        var existing = clients.findById(row.registeredId());
        if (existing == null) throw new ClientException(404, "Client not found");
        var secret = token(32);
        clients.save(RegisteredClient.from(existing).clientSecret(encoder.encode(secret)).build());
        jdbc.sql("UPDATE salon_api_client SET secret_rotated_at = now() WHERE client_id = :clientId AND salon_id = :salon")
                .param("clientId", clientId).param("salon", salonId).update();
        return new CreatedClient(find(salonId, clientId), secret);
    }

    /** No new tokens can be issued afterwards; a token already issued lasts until its (short) expiry. */
    @Transactional
    void revoke(UUID salonId, String clientId, String actor) {
        var row = active(salonId, clientId);
        jdbc.sql("DELETE FROM oauth2_registered_client WHERE id = :id").param("id", row.registeredId()).update();
        jdbc.sql("UPDATE salon_api_client SET revoked_at = now(), revoked_by = :actor WHERE client_id = :clientId AND salon_id = :salon")
                .param("actor", actor == null || actor.isBlank() ? "unknown" : actor.strip()).param("clientId", clientId).param("salon", salonId).update();
    }

    private record Row(String registeredId) {}

    /** Looks the client up by id AND salon, so another salon's client id behaves exactly like one that doesn't exist. */
    private Row active(UUID salonId, String clientId) {
        return jdbc.sql("SELECT registered_client_id FROM salon_api_client WHERE client_id = :clientId AND salon_id = :salon AND revoked_at IS NULL")
                .param("clientId", clientId).param("salon", salonId).query((rs, i) -> new Row(rs.getString(1))).optional()
                .orElseThrow(() -> new ClientException(404, "Client not found"));
    }

    private ClientView find(UUID salonId, String clientId) {
        return jdbc.sql("""
                SELECT client_id, name, salon_id, scopes, created_by, created_at, secret_rotated_at FROM salon_api_client
                WHERE client_id = :clientId AND salon_id = :salon
                """).param("clientId", clientId).param("salon", salonId).query(SalonApiClientService::view).single();
    }

    private static ClientView view(java.sql.ResultSet rs, int row) throws java.sql.SQLException {
        return new ClientView(rs.getString("client_id"), rs.getString("name"), rs.getObject("salon_id", UUID.class),
                List.of(rs.getString("scopes").split(" ")), rs.getString("created_by"),
                rs.getTimestamp("created_at").toInstant(),
                rs.getTimestamp("secret_rotated_at") == null ? null : rs.getTimestamp("secret_rotated_at").toInstant());
    }

    private static String token(int bytes) {
        var raw = new byte[bytes];
        RANDOM.nextBytes(raw);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
    }
}
