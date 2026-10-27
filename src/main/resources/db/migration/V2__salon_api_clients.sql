-- Dynamic OAuth2 clients (client_credentials) created by salon owners. Static app clients stay in application.yaml.
-- Schema of oauth2_registered_client is Spring Authorization Server's own (timestamps as timestamptz, per its note).
CREATE TABLE IF NOT EXISTS oauth2_registered_client (
    id varchar(100) NOT NULL,
    client_id varchar(100) NOT NULL,
    client_id_issued_at timestamptz DEFAULT CURRENT_TIMESTAMP NOT NULL,
    client_secret varchar(200) DEFAULT NULL,
    client_secret_expires_at timestamptz DEFAULT NULL,
    client_name varchar(200) NOT NULL,
    client_authentication_methods varchar(1000) NOT NULL,
    authorization_grant_types varchar(1000) NOT NULL,
    redirect_uris varchar(1000) DEFAULT NULL,
    post_logout_redirect_uris varchar(1000) DEFAULT NULL,
    scopes varchar(1000) NOT NULL,
    client_settings varchar(2000) NOT NULL,
    token_settings varchar(2000) NOT NULL,
    PRIMARY KEY (id)
);
CREATE UNIQUE INDEX IF NOT EXISTS oauth2_registered_client_client_id_uq ON oauth2_registered_client (client_id);

-- Which salon owns each API client, who made it, and when it was revoked. The salon binding that the token carries
-- comes from the client's settings; this table is what the owner's list/rotate/revoke are scoped by.
CREATE TABLE IF NOT EXISTS salon_api_client (
    client_id varchar(100) PRIMARY KEY,
    registered_client_id varchar(100) NOT NULL,
    salon_id uuid NOT NULL,
    name varchar(120) NOT NULL,
    scopes varchar(500) NOT NULL,
    created_by varchar(254) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    secret_rotated_at timestamptz,
    revoked_at timestamptz,
    revoked_by varchar(254)
);
CREATE INDEX IF NOT EXISTS salon_api_client_salon_idx ON salon_api_client (salon_id) WHERE revoked_at IS NULL;
