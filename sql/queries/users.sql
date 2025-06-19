-- name: CreateUser :one
INSERT INTO users (id, email, updated_at, created_at)
VALUES (gen_random_uuid(), $1, NOW(), NOW())
RETURNING *;


-- name: GetUserByEmail :one
SELECT * FROM users WHERE email = $1;


-- name: ResetUsersTable :exec
DELETE FROM users;
