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


-- name: ChangeEmailPassword :exec
update users
set email = $1,
hashed_password = $2,
updated_at = now()
where id = $3;


-- name: UpgradeUserToChirpy :exec
update users
set is_chirpy_red = true,
updated_at = now()
where id = $3;
