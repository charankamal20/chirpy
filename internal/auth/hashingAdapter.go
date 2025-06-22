package auth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type Auth interface {
	HashPassword(password string) (string, error)
	CheckPasswordHash(hash, password string) error
	MakeJWT(userID uuid.UUID, tokenSecret string, expiresIn time.Duration) (string, error)
	ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error)
}

type AuthAdapter struct {
	secret string
}

func (a *AuthAdapter) HashPassword(password string) (string, error) {
	hashedPass, err := bcrypt.GenerateFromPassword([]byte(password), 5)
	if err != nil {
		return "", err
	}

	return string(hashedPass), nil
}

func (a *AuthAdapter) CheckPasswordHash(hash, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

func (a *AuthAdapter) MakeJWT(userID uuid.UUID, tokenSecret string, expiresIn time.Duration) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    "chirpy",
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiresIn)),
		IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
		Subject:   userID.String(),
	})

	tokenString, err := token.SignedString([]byte(tokenSecret))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func (a *AuthAdapter) ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error) {
	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return []byte(tokenSecret), nil
	})
	if err != nil {
		return uuid.Nil, fmt.Errorf("Could not parse token: %+v", err)
	}

	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok || !token.Valid {
		return uuid.Nil, jwt.ErrTokenInvalidClaims
	}

	if claims.Issuer != "chirpy" {
		return uuid.Nil, fmt.Errorf("Invalid issuer: %s", claims.Issuer)
	}

	if claims.ExpiresAt.Time.Before(time.Now()) {
		return uuid.Nil, fmt.Errorf("Token has expired")
	}

	if claims.IssuedAt.Time.After(time.Now()) {
		return uuid.Nil, fmt.Errorf("Token is not yet valid")
	}

	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		return uuid.Nil, err
	}

	return userID, nil
}
