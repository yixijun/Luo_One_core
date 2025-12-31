package middleware

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

var (
	// ErrInvalidAPIKey indicates the API key is invalid
	ErrInvalidAPIKey = errors.New("invalid API key")
	// ErrAPIKeyNotFound indicates no API key was provided
	ErrAPIKeyNotFound = errors.New("API key not found")
	// ErrInvalidToken indicates the JWT token is invalid
	ErrInvalidToken = errors.New("invalid token")
	// ErrTokenExpired indicates the JWT token has expired
	ErrTokenExpired = errors.New("token expired")
	// ErrTokenNotFound indicates no token was provided
	ErrTokenNotFound = errors.New("token not found")
)

const (
	// APIKeyHeader is the header name for API key
	APIKeyHeader = "X-API-Key"
	// AuthorizationHeader is the header name for JWT token
	AuthorizationHeader = "Authorization"
	// BearerPrefix is the prefix for Bearer token
	BearerPrefix = "Bearer "
	// APIKeyLength is the length of generated API keys (32 bytes = 64 hex chars)
	APIKeyLength = 32
	// DefaultTokenExpiry is the default JWT token expiry duration
	DefaultTokenExpiry = 24 * time.Hour
)

// APIKeyManager handles API key generation, storage, and validation
type APIKeyManager struct {
	keyFilePath string
	currentKey  string
	mu          sync.RWMutex
}

// NewAPIKeyManager creates a new APIKeyManager instance
func NewAPIKeyManager(dataDir string) (*APIKeyManager, error) {
	manager := &APIKeyManager{
		keyFilePath: filepath.Join(dataDir, "api_key.txt"),
	}

	// Load or generate API key
	if err := manager.loadOrGenerateKey(); err != nil {
		return nil, err
	}

	return manager, nil
}

// loadOrGenerateKey loads existing API key or generates a new one
func (m *APIKeyManager) loadOrGenerateKey() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Try to load existing key
	data, err := os.ReadFile(m.keyFilePath)
	if err == nil && len(data) > 0 {
		m.currentKey = strings.TrimSpace(string(data))
		return nil
	}

	// Generate new key if not exists
	return m.generateAndSaveKey()
}

// generateAndSaveKey generates a new API key and saves it to file
func (m *APIKeyManager) generateAndSaveKey() error {
	key, err := generateRandomKey(APIKeyLength)
	if err != nil {
		return err
	}

	// Ensure directory exists
	dir := filepath.Dir(m.keyFilePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// Save key to file with restricted permissions
	if err := os.WriteFile(m.keyFilePath, []byte(key), 0600); err != nil {
		return err
	}

	m.currentKey = key
	return nil
}

// generateRandomKey generates a cryptographically secure random key
func generateRandomKey(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// GetCurrentKey returns the current API key
func (m *APIKeyManager) GetCurrentKey() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.currentKey
}

// ValidateKey validates the provided API key
func (m *APIKeyManager) ValidateKey(key string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.currentKey == "" || key == "" {
		return false
	}

	// Use constant-time comparison to prevent timing attacks
	return subtle.ConstantTimeCompare([]byte(m.currentKey), []byte(key)) == 1
}

// ResetKey generates a new API key and invalidates the old one
func (m *APIKeyManager) ResetKey() (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.generateAndSaveKey(); err != nil {
		return "", err
	}

	return m.currentKey, nil
}

// JWTClaims represents the claims in a JWT token
type JWTClaims struct {
	UserID   uint   `json:"user_id"`
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// JWTManager handles JWT token generation and validation
type JWTManager struct {
	secretKey   []byte
	tokenExpiry time.Duration
}

// NewJWTManager creates a new JWTManager instance
func NewJWTManager(secretKey string, tokenExpiry time.Duration) *JWTManager {
	if tokenExpiry == 0 {
		tokenExpiry = DefaultTokenExpiry
	}
	return &JWTManager{
		secretKey:   []byte(secretKey),
		tokenExpiry: tokenExpiry,
	}
}

// GenerateToken generates a new JWT token for a user
func (m *JWTManager) GenerateToken(userID uint, username string) (string, int64, error) {
	expiresAt := time.Now().Add(m.tokenExpiry)

	claims := &JWTClaims{
		UserID:   userID,
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "luo-one",
			Subject:   username,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(m.secretKey)
	if err != nil {
		return "", 0, err
	}

	return tokenString, expiresAt.Unix(), nil
}

// ValidateToken validates a JWT token and returns the claims
func (m *JWTManager) ValidateToken(tokenString string) (*JWTClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrInvalidToken
		}
		return m.secretKey, nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrTokenExpired
		}
		return nil, ErrInvalidToken
	}

	claims, ok := token.Claims.(*JWTClaims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	return claims, nil
}

// AuthManager combines API key and JWT management
type AuthManager struct {
	APIKeyManager *APIKeyManager
	JWTManager    *JWTManager
}

// NewAuthManager creates a new AuthManager instance
func NewAuthManager(dataDir, jwtSecret string, tokenExpiry time.Duration) (*AuthManager, error) {
	apiKeyManager, err := NewAPIKeyManager(dataDir)
	if err != nil {
		return nil, err
	}

	jwtManager := NewJWTManager(jwtSecret, tokenExpiry)

	return &AuthManager{
		APIKeyManager: apiKeyManager,
		JWTManager:    jwtManager,
	}, nil
}

// APIKeyMiddleware validates API key for all requests
func APIKeyMiddleware(apiKeyManager *APIKeyManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		apiKey := c.GetHeader(APIKeyHeader)
		if apiKey == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"success": false,
				"error": gin.H{
					"code":    "AUTH_FAILED",
					"message": "API key is required",
				},
			})
			return
		}

		if !apiKeyManager.ValidateKey(apiKey) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"success": false,
				"error": gin.H{
					"code":    "AUTH_FAILED",
					"message": "Invalid API key",
				},
			})
			return
		}

		c.Next()
	}
}

// JWTMiddleware validates JWT token for protected routes
func JWTMiddleware(jwtManager *JWTManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader(AuthorizationHeader)
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"success": false,
				"error": gin.H{
					"code":    "AUTH_FAILED",
					"message": "Authorization header is required",
				},
			})
			return
		}

		if !strings.HasPrefix(authHeader, BearerPrefix) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"success": false,
				"error": gin.H{
					"code":    "AUTH_FAILED",
					"message": "Invalid authorization header format",
				},
			})
			return
		}

		tokenString := strings.TrimPrefix(authHeader, BearerPrefix)
		claims, err := jwtManager.ValidateToken(tokenString)
		if err != nil {
			message := "Invalid token"
			if errors.Is(err, ErrTokenExpired) {
				message = "Token has expired"
			}
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"success": false,
				"error": gin.H{
					"code":    "AUTH_FAILED",
					"message": message,
				},
			})
			return
		}

		// Set user info in context for downstream handlers
		c.Set("user_id", claims.UserID)
		c.Set("username", claims.Username)

		c.Next()
	}
}

// CombinedAuthMiddleware validates both API key and JWT token
func CombinedAuthMiddleware(apiKeyManager *APIKeyManager, jwtManager *JWTManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		// First validate API key
		apiKey := c.GetHeader(APIKeyHeader)
		if apiKey == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"success": false,
				"error": gin.H{
					"code":    "AUTH_FAILED",
					"message": "API key is required",
				},
			})
			return
		}

		if !apiKeyManager.ValidateKey(apiKey) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"success": false,
				"error": gin.H{
					"code":    "AUTH_FAILED",
					"message": "Invalid API key",
				},
			})
			return
		}

		// Then validate JWT token
		authHeader := c.GetHeader(AuthorizationHeader)
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"success": false,
				"error": gin.H{
					"code":    "AUTH_FAILED",
					"message": "Authorization header is required",
				},
			})
			return
		}

		if !strings.HasPrefix(authHeader, BearerPrefix) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"success": false,
				"error": gin.H{
					"code":    "AUTH_FAILED",
					"message": "Invalid authorization header format",
				},
			})
			return
		}

		tokenString := strings.TrimPrefix(authHeader, BearerPrefix)
		claims, err := jwtManager.ValidateToken(tokenString)
		if err != nil {
			message := "Invalid token"
			if errors.Is(err, ErrTokenExpired) {
				message = "Token has expired"
			}
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"success": false,
				"error": gin.H{
					"code":    "AUTH_FAILED",
					"message": message,
				},
			})
			return
		}

		// Set user info in context
		c.Set("user_id", claims.UserID)
		c.Set("username", claims.Username)

		c.Next()
	}
}

// GetUserIDFromContext retrieves the user ID from the Gin context
func GetUserIDFromContext(c *gin.Context) (uint, bool) {
	userID, exists := c.Get("user_id")
	if !exists {
		return 0, false
	}
	id, ok := userID.(uint)
	return id, ok
}

// GetUsernameFromContext retrieves the username from the Gin context
func GetUsernameFromContext(c *gin.Context) (string, bool) {
	username, exists := c.Get("username")
	if !exists {
		return "", false
	}
	name, ok := username.(string)
	return name, ok
}
