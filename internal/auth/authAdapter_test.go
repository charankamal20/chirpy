package auth

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestJwtSigning(t *testing.T) {
	var adapter Auth = &AuthAdapter{}

	userId := uuid.New()

	token, err := adapter.MakeJWT(userId, "abcdefghijklmnopqrstuvwxyz", time.Hour*24)
	if err != nil {
		t.Fatalf("Failed to create JWT: %v", err)
	}

	t.Log(token)
}

func Test_ValidateToken_ValidToken(t *testing.T) {
	var adapter Auth = &AuthAdapter{}

	key := "abcdefghijklmnopqrstuvwxyz"
	userId := uuid.New()

	token, err := adapter.MakeJWT(userId, key, time.Hour*24)
	if err != nil {
		t.Fatalf("Failed to create JWT: %v", err)
	}
	t.Logf("Generated JWT: %s", token)

	parsedUserId, err := adapter.ValidateJWT(token, key)
	if err != nil {
		t.Fatalf("Failed to validate JWT: %v", err)
	}

	if parsedUserId != userId {
		t.Fatalf("Expected user ID %s, got %s", userId, parsedUserId)
	}
}
