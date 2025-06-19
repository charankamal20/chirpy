-- name: CreateChirp :one
INSERT INTO chirps (id, user_id, body, created_at)
VALUES (gen_random_uuid(), $1, $2, NOW())
RETURNING *;
