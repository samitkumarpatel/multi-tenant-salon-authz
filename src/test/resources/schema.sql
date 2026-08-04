-- Simulates the user_identity VIEW from the saloon service for integration tests.
-- In production this view is created by the saloon service (V4__user_identity_view.sql).
CREATE TABLE IF NOT EXISTS user_identity (
    email     VARCHAR(255) NOT NULL,
    role      VARCHAR(50)  NOT NULL,
    saloon_id UUID         NOT NULL,
    active    BOOLEAN      NOT NULL DEFAULT TRUE
);
