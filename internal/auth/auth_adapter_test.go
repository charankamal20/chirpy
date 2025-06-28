package auth

import (
	"testing"
	"time"

	"github.com/charankamal20/chirpy/internal/cache"
	"github.com/google/uuid"
)

func getAuthAdapter() (Auth, error) {
	cacheStore, err := cache.NewRefreshTokenCache()
	if err != nil {
		return nil, err
	}

	return NewAuthAdapter("xxxxxxxxxxxxxxxxxxxxxxxxx", cacheStore), nil
}

func TestJwtSigning(t *testing.T) {
	adapter, err := getAuthAdapter()
	if err != nil {
		t.Fatalf("Failed to create Adapter: %v", err)
	}

	userId := uuid.New()

	token, _, err := adapter.MakeNewJWT(userId, time.Hour*24)
	if err != nil {
		t.Fatalf("Failed to create JWT: %v", err)
	}

	t.Log(token)
}

func Test_ValidateToken_ValidToken(t *testing.T) {
	adapter, err := getAuthAdapter()
	if err != nil {
		t.Fatalf("Failed to create Adapter: %v", err)
	}

	userId := uuid.New()

	token, _, err := adapter.MakeNewJWT(userId, time.Hour*24)
	if err != nil {
		t.Fatalf("Failed to create JWT: %v", err)
	}
	t.Logf("Generated JWT: %s", token)

	parsedUserId, err := adapter.ValidateJWT(token)
	if err != nil {
		t.Fatalf("Failed to validate JWT: %v", err)
	}

	if parsedUserId != userId {
		t.Fatalf("Expected user ID %s, got %s", userId, parsedUserId)
	}
}
