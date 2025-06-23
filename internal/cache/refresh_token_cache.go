package cache

import (
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/tidwall/buntdb"
)

type CacheStore interface {
	Close() error
	StoreToken(token string, userID string, ttl time.Duration) error
	GetUserIDByToken(token string) (string, error)
	DeleteToken(token string) error
}

type RefreshTokenCache struct {
	db *buntdb.DB
}

func NewRefreshTokenCache() (*RefreshTokenCache, error) {
	db, err := initRefreshTokenCache()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize refresh token cache: %w", err)
	}

	return &RefreshTokenCache{db: db}, nil
}

func (c *RefreshTokenCache) Close() error {
	return c.db.Close()
}

func (c *RefreshTokenCache) StoreToken(token string, userID string, ttl time.Duration) error {
	return c.db.Update(func(tx *buntdb.Tx) error {
		opts := &buntdb.SetOptions{Expires: true, TTL: ttl}
		_, _, err := tx.Set("refresh:"+token, userID, opts)
		return err
	})
}

func (c *RefreshTokenCache) GetUserIDByToken(token string) (string, error) {
	var userID string
	err := c.db.View(func(tx *buntdb.Tx) error {
		val, err := tx.Get("refresh:" + token)
		if err != nil {
			return err
		}
		userID = val
		return nil
	})
	return userID, err
}

func (c *RefreshTokenCache) DeleteToken(token string) error {
	return c.db.Update(func(tx *buntdb.Tx) error {
		_, err := tx.Delete("refresh:" + token)
		if err == buntdb.ErrNotFound {
			return errors.New("token not found")
		}
		return err
	})
}


func initRefreshTokenCache() (*buntdb.DB, error) {
	db, err := buntdb.Open(":memory:")
	if err != nil {
		return nil, err
	}

	err = db.Update(func(tx *buntdb.Tx) error {
		_, _, err := tx.Set("refresh_tokens", "", nil)
		return err
	})

	if err != nil {
		return nil, err

	}
	return db, nil
}


func main() {
	db, err := buntdb.Open(":memory:")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Set a key/value pair
	err = db.Update(func(tx *buntdb.Tx) error {
		_, _, err := tx.Set("name", "charan", nil)
		return err
	})

	// Read a value
	err = db.View(func(tx *buntdb.Tx) error {
		val, err := tx.Get("name")
		if err != nil {
			return err
		}
		fmt.Println("name:", val)
		return nil
	})
}
