-- name: GetSetting :one
SELECT * FROM app_settings WHERE key = $1;

-- name: UpsertSetting :one
INSERT INTO app_settings (key, value)
VALUES ($1, $2)
ON CONFLICT (key) DO UPDATE
SET value = EXCLUDED.value,
    updated_at = now()
RETURNING *;
