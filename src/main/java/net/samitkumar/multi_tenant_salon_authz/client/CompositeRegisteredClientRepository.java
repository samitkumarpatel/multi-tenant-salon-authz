package net.samitkumar.multi_tenant_salon_authz.client;

import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import java.util.function.Supplier;

/**
 * The app clients defined in {@code application.yaml} (read-only, unchanged) plus the database-backed clients
 * salon owners create. Lookups try the static ones first, so a dynamic client can never shadow an app client;
 * saves only ever go to the database.
 */
final class CompositeRegisteredClientRepository implements RegisteredClientRepository {
    private final RegisteredClientRepository statics;
    private final Supplier<RegisteredClientRepository> dynamic;

    CompositeRegisteredClientRepository(RegisteredClientRepository statics, Supplier<RegisteredClientRepository> dynamic) {
        this.statics = statics;
        this.dynamic = dynamic;
    }

    @Override
    public void save(RegisteredClient registeredClient) {
        if (statics.findByClientId(registeredClient.getClientId()) != null) {
            throw new IllegalArgumentException("client_id is reserved by a built-in client");
        }
        dynamic.get().save(registeredClient);
    }

    @Override
    public RegisteredClient findById(String id) {
        var found = statics.findById(id);
        return found != null ? found : dynamic.get().findById(id);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        var found = statics.findByClientId(clientId);
        return found != null ? found : dynamic.get().findByClientId(clientId);
    }
}
