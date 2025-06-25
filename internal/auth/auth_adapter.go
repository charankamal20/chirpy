package auth

import (
	"fmt"
	"net/http"
	"time"

	"github.com/charankamal20/chirpy/internal/cache"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type Auth interface {
	HashPassword(password string) (string, error)
	CheckPasswordHash(hash, password string) error
	MakeNewJWT(userID uuid.UUID, expiresIn time.Duration) (string, string, error)
	MakeJWT(uuid.UUID, string, time.Duration) (string, error)
	ValidateJWT(tokenString string) (uuid.UUID, error)
	GetBearerToken(headers http.Header) (string, error)
	RefreshToken(refresh_token string) (string, error)
	RevokeToken(refresh_token string) error
}

type AuthAdapter struct {
	secret string
	cache  cache.CacheStore
}

func NewAuthAdapter(secret string, cache cache.CacheStore) *AuthAdapter {
	return &AuthAdapter{
		secret: secret,
		cache:  cache,
	}
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

func (a *AuthAdapter) MakeNewJWT(userID uuid.UUID, expiresIn time.Duration) (string, string, error) {
	refresh_token := uuid.NewString()
	token, err := a.MakeJWT(userID, refresh_token, time.Hour)
	if err != nil {
		return "", "", err
	}

	err = a.cache.StoreToken(refresh_token, userID.String(), time.Hour*24)
	if err != nil {
		return "", "", fmt.Errorf("failed to store refresh token: %w", err)
	}

	return token, refresh_token, err
}

func (a *AuthAdapter) MakeJWT(userID uuid.UUID, refresh_token string, expiresIn time.Duration) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		ID:        refresh_token,
		Issuer:    "chirpy",
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiresIn)),
		IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
		Subject:   userID.String(),
	})

	tokenString, err := token.SignedString([]byte(a.secret))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func (a *AuthAdapter) ValidateJWT(tokenString string) (uuid.UUID, error) {
	claims, err := a.getTokenClaims(tokenString)
	if err != nil {
		return uuid.Nil, err
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

func (a *AuthAdapter) validateRefreshToken(refresh_token string) (uuid.UUID, error) {
	userId, err := a.cache.GetUserIDByToken(refresh_token)
	if err != nil || userId == "" {
		return uuid.Nil, fmt.Errorf("Invlaid Token: %w", err)
	}

	return uuid.MustParse(userId), nil
}

func (a *AuthAdapter) GetBearerToken(headers http.Header) (string, error) {
	authHeader := headers.Get("Authorization")
	if authHeader == "" {
		return "", fmt.Errorf("Authorization header is missing")
	}

	if len(authHeader) < 7 || authHeader[:7] != "Bearer " {
		return "", fmt.Errorf("Authorization header format must be Bearer {token}")
	}

	token := authHeader[7:]
	if token == "" {
		return "", fmt.Errorf("Bearer token is empty")
	}
	fmt.Println("Bearer token: ", token)
	return token, nil
}

func (a *AuthAdapter) getTokenClaims(tokenString string) (jwt.RegisteredClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return []byte(a.secret), nil
	})
	if err != nil {
		return jwt.RegisteredClaims{}, fmt.Errorf("Could not parse token: %+v", err)
	}

	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok || !token.Valid {
		return jwt.RegisteredClaims{}, jwt.ErrTokenInvalidClaims
	}

	return *claims, nil
}


func (a *AuthAdapter) RefreshToken(refresh_token string) (string, error) {
	userID, err := a.validateRefreshToken(refresh_token)
	if err != nil {
		return "", fmt.Errorf("Invalid refresh token: %w", err)
	}

	newToken, err := a.MakeJWT(userID, refresh_token, time.Hour)
	if err != nil {
		return "", fmt.Errorf("Failed to create new JWT: %w", err)
	}

	return newToken, nil
}

func (a *AuthAdapter) RevokeToken(refresh_token string) error {
	err := a.cache.DeleteToken(refresh_token)
	if err != nil {
		return fmt.Errorf("Failed to revoke token: %w", err)
	}
	return nil
}
