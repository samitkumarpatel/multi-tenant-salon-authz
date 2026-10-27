package net.samitkumar.multi_tenant_salon_authz.client;

/** Names shared between the client store and the token customizer. */
public final class ApiClients {
    /** Where the salon id lives in a client's settings; copied into the {@code salon_id} token claim. */
    public static final String SALON_ID_SETTING = "salon.api.salon-id";

    private ApiClients() {}
}
