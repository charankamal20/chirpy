package dto

import (
	"time"

	"github.com/charankamal20/chirpy/internal/database"
)

type UserDTO struct {
	ID           string    `json:"id"`
	Email        string    `json:"email"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	Token        string    `json:"token,omitempty"`
	RefreshToken string    `json:"refresh_token,omitempty"`
}

func GetUserDTOFromUser(user *database.User, tokens ...string) *UserDTO {
	if len(tokens) == 0 {
		tokens = append(tokens, "")
	}
	if len(tokens) < 2 {
		tokens = append(tokens, "")
	}

	return &UserDTO{
		ID:           user.ID,
		Email:        user.Email,
		CreatedAt:    user.CreatedAt,
		UpdatedAt:    user.UpdatedAt,
		Token:        tokens[0],
		RefreshToken: tokens[1],
	}
}
