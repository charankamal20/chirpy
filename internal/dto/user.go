package dto

import (
	"time"

	"github.com/charankamal20/chirpy/internal/database"
)

type UserDTO struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func GetUserDTOFromUser(user *database.User) *UserDTO {
	return &UserDTO{
		ID:        user.ID,
		Email:     user.Email,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	}
}
