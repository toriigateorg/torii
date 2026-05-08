CREATE TABLE services (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    title       TEXT        NOT NULL,
    description TEXT        NOT NULL DEFAULT '',
    service_url TEXT        NOT NULL,
    domain      TEXT        NOT NULL UNIQUE,
    headers     JSONB       NOT NULL DEFAULT '{}'::jsonb,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX services_domain_idx ON services (domain);
