package auth

import (
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type Auth interface {
	HashPassword(password string) (string, error)
	CheckPasswordHash(hash, password string) error
	MakeJWT(userID uuid.UUID, tokenSecret string, expiresIn time.Duration) (string, error)
}

type CryptoAdapter struct{ }

func (a *CryptoAdapter) HashPassword(password string) (string, error) {
	hashedPass, err := bcrypt.GenerateFromPassword([]byte(password), 5)
	if err != nil {
		return "", err
	}

	return string(hashedPass), nil
}

func (a *CryptoAdapter) CheckPasswordHash(hash, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

func (a *CryptoAdapter) MakeJWT(userID uuid.UUID, tokenSecret string, expiresIn time.Duration) (string, error) {
	jwt.
	return "", nil
}
