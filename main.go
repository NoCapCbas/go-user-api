package main

import (
  "encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"
	"sync"
	"strings"
	"math/rand"
  "context"
)

var jwtSecretKey = []byte("secret_key") // Change this to a more secure key

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Claims struct {
	Username string `json:"username"`
	Expires  int64  `json:"expires"`
}

var userStore = map[string]string{} // In-memory user store (username: password)
var mu sync.Mutex // Ensure thread-safe access to the userStore

func main() {
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/protected", authMiddleware(protectedHandler))

	fmt.Println("Server is running on port 8079")
	log.Fatal(http.ListenAndServe(":8079", nil))
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	mu.Lock()
	defer mu.Unlock()

	if _, exists := userStore[user.Username]; exists {
		http.Error(w, "User already exists", http.StatusBadRequest)
		return
	}

	userStore[user.Username] = user.Password
	w.WriteHeader(http.StatusCreated)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	mu.Lock()
	defer mu.Unlock()

	storedPassword, exists := userStore[user.Username]
	if !exists || storedPassword != user.Password {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	token, err := generateJWT(user.Username)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": token})
}

func protectedHandler(w http.ResponseWriter, r *http.Request) {
	username := r.Context().Value("username").(string)
	w.Write([]byte(fmt.Sprintf("Hello, %s! You have accessed a protected route.", username)))
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Missing token", http.StatusUnauthorized)
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")
		claims, err := parseJWT(token)
		if err != nil {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		if time.Now().Unix() > claims.Expires {
			http.Error(w, "Token expired", http.StatusUnauthorized)
			return
		}

		ctx := r.Context()
		ctx = context.WithValue(ctx, "username", claims.Username)
		r = r.WithContext(ctx)

		next(w, r)
	}
}

func generateJWT(username string) (string, error) {
	expires := time.Now().Add(1 * time.Hour).Unix()
	claims := Claims{
		Username: username,
		Expires:  expires,
	}

	// Encode the claims as JSON
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	// Generate a random signature for simplicity
	signature := make([]byte, 16)
	rand.Read(signature)

	// Create the token as "header.payload.signature"
	token := fmt.Sprintf("%s.%s.%x", base64Encode([]byte(`{"alg":"none"}`)), base64Encode(claimsJSON), signature)

	return token, nil
}

func parseJWT(token string) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid token format")
	}

	claimsJSON, err := base64Decode(parts[1])
	if err != nil {
		return nil, err
	}

	var claims Claims
	err = json.Unmarshal(claimsJSON, &claims)
	if err != nil {
		return nil, err
	}

	return &claims, nil
}

func base64Encode(data []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(data), "=")
}

func base64Decode(data string) ([]byte, error) {
	return base64.URLEncoding.DecodeString(data + strings.Repeat("=", (4-len(data)%4)%4))
}

