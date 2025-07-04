// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.29.0
// source: chirps.sql

package database

import (
	"context"
)

const createChirp = `-- name: CreateChirp :one
INSERT INTO chirps (id, user_id, body, created_at)
VALUES (gen_random_uuid(), $1, $2, NOW())
RETURNING id, user_id, body, created_at, updated_at
`

type CreateChirpParams struct {
	UserID string `json:"user_id"`
	Body   string `json:"body"`
}

func (q *Queries) CreateChirp(ctx context.Context, arg CreateChirpParams) (Chirp, error) {
	row := q.queryRow(ctx, q.createChirpStmt, createChirp, arg.UserID, arg.Body)
	var i Chirp
	err := row.Scan(
		&i.ID,
		&i.UserID,
		&i.Body,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const deleteChirp = `-- name: DeleteChirp :exec
DELETE from chirps
where id = $1
and user_id = $2
`

type DeleteChirpParams struct {
	ID     string `json:"id"`
	UserID string `json:"user_id"`
}

func (q *Queries) DeleteChirp(ctx context.Context, arg DeleteChirpParams) error {
	_, err := q.exec(ctx, q.deleteChirpStmt, deleteChirp, arg.ID, arg.UserID)
	return err
}

const getAllChirps = `-- name: GetAllChirps :many
SELECT id, user_id, body, created_at, updated_at FROM chirps
`

func (q *Queries) GetAllChirps(ctx context.Context) ([]Chirp, error) {
	rows, err := q.query(ctx, q.getAllChirpsStmt, getAllChirps)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []Chirp
	for rows.Next() {
		var i Chirp
		if err := rows.Scan(
			&i.ID,
			&i.UserID,
			&i.Body,
			&i.CreatedAt,
			&i.UpdatedAt,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const getChirp = `-- name: GetChirp :one
SELECT id, user_id, body, created_at, updated_at FROM chirps WHERE id = $1
`

func (q *Queries) GetChirp(ctx context.Context, id string) (Chirp, error) {
	row := q.queryRow(ctx, q.getChirpStmt, getChirp, id)
	var i Chirp
	err := row.Scan(
		&i.ID,
		&i.UserID,
		&i.Body,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}
