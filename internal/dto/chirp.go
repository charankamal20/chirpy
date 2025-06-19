package dto

import (
	"time"

	"github.com/charankamal20/chirpy/internal/database"
)

type ChirpDTO struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	Body      string    `json:"body"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func GetChirpDTO(chirp *database.Chirp) *ChirpDTO {
	return &ChirpDTO{
		ID:        chirp.ID,
		Body:      chirp.Body,
		UserID:    chirp.UserID,
		CreatedAt: chirp.CreatedAt,
		UpdatedAt: chirp.UpdatedAt,
	}
}
