-- name: CreateUser :one
INSERT INTO users (id, email, hashed_password, updated_at, created_at)
VALUES (gen_random_uuid(), $1, $2, NOW(), NOW())
RETURNING *;


-- name: GetUserByEmail :one
SELECT * FROM users WHERE email = $1;


-- name: ResetUsersTable :exec
DELETE FROM users;


-- name: GetPassword :one
select hashed_password from users where email = $1;
