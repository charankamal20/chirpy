-- name: CreateChirp :one
INSERT INTO chirps (id, user_id, body, created_at)
VALUES (gen_random_uuid(), $1, $2, NOW())
RETURNING *;


-- name: GetAllChirps :many
SELECT * FROM chirps;

-- name: GetChirp :one
SELECT * FROM chirps WHERE id = $1;
