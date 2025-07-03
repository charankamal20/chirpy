// @title Chirpy
// @version 1.0
// @description This is a simple API server.
// @host localhost:8080
// @BasePath /app

package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	_ "github.com/charankamal20/chirpy/docs" // replace with your actual module
	httpSwagger "github.com/swaggo/http-swagger"

	"github.com/charankamal20/chirpy/internal/auth"
	"github.com/charankamal20/chirpy/internal/cache"
	"github.com/charankamal20/chirpy/internal/database"
	"github.com/charankamal20/chirpy/internal/dto"
	"github.com/google/uuid"

	_ "github.com/lib/pq"
)

type apiConfig struct {
	platform       string
	db             *database.Queries
	fileServerHits atomic.Int32
	auth           auth.Auth
	polka_key      string
}

func (c *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.fileServerHits.Add(1)
		fmt.Println("File server hit count incremented:", c.fileServerHits.Load())
		next.ServeHTTP(w, r)
	})
}

func healthCheckHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte("OK"))
	}
}

func (c *apiConfig) getFileServerHitsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hits := c.fileServerHits.Load()
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "text/html")

		data, _ := os.ReadFile("./admin/metrics/index.html")

		w.Write(fmt.Appendf(nil, string(data), hits))
	}
}

func (c *apiConfig) resetHitsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if c.platform != "dev" {
			http.Error(w, "Sensitive", http.StatusForbidden)
			return
		}

		if c.db.ResetUsersTable(r.Context()) != nil {
			http.Error(w, "Failed to reset user table", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
	}
}

type chirpReq struct {
	Body string `json:"body" validate:"required"`
}

func validateChirpHandler(r *http.Request) (*chirpReq, string, int, error) {
	type errorResponse struct {
		Error string `json:"error"`
	}

	userid := (r.Context().Value("id").(uuid.UUID)).String()

	var request chirpReq
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&request)
	if err != nil || request.Body == "" || userid == "" {
		return nil, "", http.StatusBadRequest, fmt.Errorf("Invalid request body")
	}
	// Validate chirp length
	if len(request.Body) > 140 {
		return nil, "", http.StatusBadRequest, fmt.Errorf("Chirp body exceeds 140 characters")
	}

	var profaneWords = []string{" kerfuffle ", " sharbert ", " fornax ", " Kerfuffle ", " Sharbert ", " Fornax "}

	for _, word := range profaneWords {
		request.Body = strings.ReplaceAll(request.Body, word, " **** ")
	}

	return &request, userid, http.StatusOK, nil
}

func (c *apiConfig) getUserFromEmailHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		type userRequest struct {
			Email string `json:"email" validate:"required,email"`
		}

		var request userRequest
		decoder := json.NewDecoder(r.Body)
		err := decoder.Decode(&request)
		if err != nil || request.Email == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request"})
			return
		}

		user, err := c.db.GetUserByEmail(r.Context(), request.Email)
		if err != nil {
			http.Error(w, "Failed to fetch user", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(user); err != nil {
			http.Error(w, "Failed to encode user", http.StatusInternalServerError)
		}
	}
}

func (c *apiConfig) createUserHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		type userRequest struct {
			Email    string `json:"email" validate:"required,email"`
			Password string `json:"password" validate:"required"`
		}

		var request userRequest
		decoder := json.NewDecoder(r.Body)
		err := decoder.Decode(&request)
		if err != nil || request.Email == "" || request.Password == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request"})
			return
		}

		request.Password, err = c.auth.HashPassword(request.Password)
		if err != nil {
			http.Error(w, "Failed to create user", http.StatusInternalServerError)
			return
		}

		user, err := c.db.CreateUser(r.Context(), database.CreateUserParams{
			Email:          request.Email,
			HashedPassword: request.Password,
		})
		if err != nil {
			http.Error(w, "Failed to create user", http.StatusInternalServerError)
			return
		}

		userDto := dto.GetUserDTOFromUser(&user, "")

		w.WriteHeader(http.StatusCreated)
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(userDto); err != nil {
			http.Error(w, "Failed to encode user", http.StatusInternalServerError)
		}
	}
}

func (c *apiConfig) addChirpHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data, userId, status, err := validateChirpHandler(r)
		if err != nil {
			http.Error(w, err.Error(), status)
			return
		}

		chirp, err := c.db.CreateChirp(r.Context(), database.CreateChirpParams{
			Body:   data.Body,
			UserID: userId,
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}

		chirpDto := dto.GetChirpDTO(&chirp)
		w.WriteHeader(http.StatusCreated)
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(chirpDto); err != nil {
			http.Error(w, "Failed to encode chirp", http.StatusInternalServerError)
		}
	}
}

func (c *apiConfig) getAllChirpsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		chirps, err := c.db.GetAllChirps(r.Context())
		if err != nil {
			http.Error(w, "Could not fetch chirps", http.StatusInternalServerError)
			return
		}

		chirpsDto := make([]dto.ChirpDTO, 0)
		for _, chirp := range chirps {
			chirpDto := dto.GetChirpDTO(&chirp)
			chirpsDto = append(chirpsDto, *chirpDto)
		}

		data, err := json.Marshal(chirpsDto)
		if err != nil {
			http.Error(w, "Could not marshal chirps", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "applicaton/json")
		w.Write(data)
	}
}

func (c *apiConfig) getChirpHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("chirpID")
		if id == "" {
			http.Error(w, "id not found", http.StatusBadRequest)
			return
		}

		chirp, err := c.db.GetChirp(r.Context(), id)
		if err != nil {
			http.Error(w, "some error occured", http.StatusInternalServerError)
			return
		}

		chirpDto := dto.GetChirpDTO(&chirp)

		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(chirpDto)
		if err != nil {
			http.Error(w, "some error occured", http.StatusInternalServerError)
			return
		}
	}
}

func (a *apiConfig) loginHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		type userRequest struct {
			Email            string `json:"email" validate:"required,email"`
			Password         string `json:"password" validate:"required"`
			ExpiresInSeconds int    `json:"expires_in_seconds"`
		}

		var request userRequest
		decoder := json.NewDecoder(r.Body)
		err := decoder.Decode(&request)
		if err != nil || request.Email == "" || request.Password == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request"})
			return
		}

		if request.ExpiresInSeconds <= 0 || request.ExpiresInSeconds > 3600 {
			request.ExpiresInSeconds = 3600
		}

		user, err := a.db.GetUserByEmail(r.Context(), request.Email)
		if err != nil {
			http.Error(w, "some error occured: "+err.Error(), http.StatusInternalServerError)
			return
		}

		err = a.auth.CheckPasswordHash(user.HashedPassword, request.Password)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		token, refresh_token, err := a.auth.MakeNewJWT(uuid.MustParse(user.ID), time.Duration(request.ExpiresInSeconds)*time.Second)

		userDto := dto.GetUserDTOFromUser(&user, token, refresh_token)

		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(userDto); err != nil {
			http.Error(w, "Failed to encode user", http.StatusInternalServerError)
		}
	}
}

func (a *apiConfig) autenticateUser(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, err := a.auth.GetBearerToken(r.Header)
		if err != nil {
			http.Error(w, "Token not found", http.StatusUnauthorized)
			return
		}

		userID, err := a.auth.ValidateJWT(token)
		if err != nil {
			http.Error(w, "Invalid token: "+err.Error(), http.StatusUnauthorized)
			return
		}

		ctx := r.Context()
		ctx = context.WithValue(ctx, "id", userID)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

func (a *apiConfig) getRefreshTokenHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		type refreshTokenResponse struct {
			Token string `json:"token" validate:"required"`
		}

		refresh_token, err := a.auth.GetBearerToken(r.Header)
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		new_token, err := a.auth.RefreshToken(refresh_token)
		if err != nil || new_token == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		res := &refreshTokenResponse{
			Token: new_token,
		}

		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(res); err != nil {
			http.Error(w, "Failed to encode response", http.StatusInternalServerError)
			return
		}
	}
}

func (c *apiConfig) revokeTokenHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		refresh_token, err := c.auth.GetBearerToken(r.Header)
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		err = c.auth.RevokeToken(refresh_token)
		if err != nil {
			http.Error(w, "Failed to revoke token", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

func (c *apiConfig) updatePasswordHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		type userRequest struct {
			Email    string `json:"email" validate:"required"`
			Password string `json:"password" validate:"required"`
		}

		var request userRequest
		decoder := json.NewDecoder(r.Body)
		err := decoder.Decode(&request)
		if err != nil || request.Email == "" || request.Password == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request"})
			return
		}

		userID := r.Context().Value("id").(uuid.UUID)
		newHashedPassword, err := c.auth.HashPassword(request.Password)
		if err != nil {
			http.Error(w, "Failed to hash new password", http.StatusInternalServerError)
			return
		}

		err = c.db.ChangeEmailPassword(r.Context(), database.ChangeEmailPasswordParams{
			Email:          request.Email,
			HashedPassword: newHashedPassword,
			ID:             userID.String(),
		})
		if err != nil {
			http.Error(w, "Failed to update password: "+err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

func (a *apiConfig) deleteChirpHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("chirpID")
		if id == "" {
			http.Error(w, "id not found", http.StatusBadRequest)
			return
		}

		userId := (r.Context().Value("id").(uuid.UUID)).String()
		if userId == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		chirp, err := a.db.GetChirp(r.Context(), id)
		if err != nil {
			http.Error(w, "Chirp not found", http.StatusNotFound)
			return
		}

		if chirp.UserID != userId {
			http.Error(w, "Author Mismatch", http.StatusForbidden)
			return
		}

		err = a.db.DeleteChirp(r.Context(), database.DeleteChirpParams{
			ID:     chirp.ID,
			UserID: userId,
		})
		if err != nil {
			http.Error(w, "some error occured", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

func (a *apiConfig) upgradeUserHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		secret, err := a.GetApiKey(r.Header)
		if secret != a.polka_key {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		type dataStruct struct {
			UserId string `json:"user_id" validate:"required"`
		}

		type eventRequest struct {
			Event string     `json:"event" validate:"required"`
			Data  dataStruct `json:"data" validate:"required"`
		}

		body := &eventRequest{}
		decoder := json.NewDecoder(r.Body)
		err = decoder.Decode(body)
		if err != nil {
			http.Error(w, "error parsing body", http.StatusBadRequest)
			return
		}

		if body.Event != "user.upgraded" {
			log.Println(body.Event)
			log.Println(body.Data.UserId)

			w.WriteHeader(http.StatusNoContent)
			return
		}

		err = a.db.UpgradeUserToChirpy(r.Context(), body.Data.UserId)
		if err != nil {
			if err == sql.ErrNoRows {
				http.Error(w, "no user found: "+err.Error(), http.StatusNotFound)
				return
			}

			http.Error(w, "failed to upgrade: "+err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

func (a *apiConfig) GetApiKey(headers http.Header) (string, error) {
	value := headers.Get("Authorization")
	if value == "" {
		return "", fmt.Errorf("No Authorization")
	}

	header_val := strings.Split(value, " ")
	if len(header_val) < 2 {
		return "", fmt.Errorf("Invalid header value")
	}

	key := header_val[1]
	if key == "" {
		return "", fmt.Errorf("Empty secret value")
	}

	return key, nil
}

func main() {
	platform := os.Getenv("PLATFORM")
	if platform == "" {
		panic("PLATFORM environment variable is not set")
	}

	dbURL := os.Getenv("DB_URL")
	if dbURL == "" {
		panic("DB_URL environment variable is not set")
	}

	secret := os.Getenv("SECRET_KEY")
	if secret == "" {
		panic("SECRET environment variable is not set")
	}

	polka_key := os.Getenv("POLKA_KEY")
	if secret == "" {
		panic("POLKA environment variable is not set")
	}

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		panic(fmt.Sprintf("Failed to connect to database: %v", err))
	}

	defer db.Close()

	dbqueries := database.New(db)

	ServeMux := http.NewServeMux()

	port := ":8080"
	server := http.Server{
		Handler: ServeMux,
		Addr:    port,
	}

	refresh_token_cache, err := cache.NewRefreshTokenCache()
	if err != nil {
		panic(fmt.Sprintf("Failed to initialize refresh token cache: %v", err))
	}

	defer refresh_token_cache.Close()

	auth := auth.NewAuthAdapter(secret, refresh_token_cache)
	api := &apiConfig{
		db:        dbqueries,
		platform:  platform,
		auth:      auth,
		polka_key: polka_key,
	}

	fileHandler := http.FileServer(
		http.Dir("./"),
	)

	ServeMux.Handle("/app/", http.StripPrefix("/app/", api.middlewareMetricsInc(fileHandler)))

	ServeMux.Handle("/swagger/", httpSwagger.WrapHandler)

	// @Summary      Ping
	// @Description  Responds with pong
	// @Tags         health
	// @Accept       json
	// @Produce      json
	// @Success      200 {string} string "pong"
	// @Router       /ping [get]
	ServeMux.HandleFunc("GET /api/healthz", healthCheckHandler())

	ServeMux.HandleFunc("GET /admin/metrics", api.getFileServerHitsHandler())

	ServeMux.HandleFunc("POST /admin/reset", api.resetHitsHandler())

	ServeMux.HandleFunc("POST /api/users", api.createUserHandler())

	ServeMux.HandleFunc("GET /api/user", api.getUserFromEmailHandler())

	ServeMux.HandleFunc("POST /api/chirps", api.autenticateUser(api.addChirpHandler()))

	ServeMux.HandleFunc("GET /api/chirps", api.getAllChirpsHandler())

	ServeMux.HandleFunc("GET /api/chirps/{chirpID}", api.getChirpHandler())

	ServeMux.HandleFunc("DELETE /api/chirps/{chirpID}", api.autenticateUser(api.deleteChirpHandler()))

	ServeMux.HandleFunc("POST /api/login", api.loginHandler())

	ServeMux.HandleFunc("POST /api/refresh", api.getRefreshTokenHandler())

	ServeMux.HandleFunc("POST /api/revoke", api.revokeTokenHandler())

	ServeMux.HandleFunc("PUT /api/users", api.autenticateUser(api.updatePasswordHandler()))

	ServeMux.HandleFunc("POST /api/polka/webhooks", api.upgradeUserHandler())

	log.Println("Starting server on", port)
	err = server.ListenAndServe()
	if err != nil {
		log.Fatalln(err.Error())
	}
}
