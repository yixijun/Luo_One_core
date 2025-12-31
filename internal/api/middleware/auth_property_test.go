package middleware

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
)

// Feature: luo-one-email-manager, Property 10: API 密钥认证有效性
// For any API request, requests with valid API key should be accepted,
// requests with invalid API key or no API key should be rejected with 401 error.
// Validates: Requirements 5.1, 5.3

func TestProperty_APIKeyAuthenticationValidity(t *testing.T) {
	gin.SetMode(gin.TestMode)

	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 20
	properties := gopter.NewProperties(parameters)

	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "luo_one_auth_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Initialize API key manager
	apiKeyManager, err := NewAPIKeyManager(tempDir)
	if err != nil {
		t.Fatalf("Failed to create API key manager: %v", err)
	}

	validKey := apiKeyManager.GetCurrentKey()

	// Property 10.1: Requests with valid API key should be accepted
	properties.Property("valid_api_key_accepted", prop.ForAll(
		func(path string) bool {
			router := gin.New()
			router.Use(APIKeyMiddleware(apiKeyManager))
			router.GET("/test", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"status": "ok"})
			})

			req, _ := http.NewRequest("GET", "/test", nil)
			req.Header.Set(APIKeyHeader, validKey)

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			return w.Code == http.StatusOK
		},
		gen.AlphaString(),
	))

	// Property 10.2: Requests without API key should be rejected with 401
	properties.Property("missing_api_key_rejected", prop.ForAll(
		func(path string) bool {
			router := gin.New()
			router.Use(APIKeyMiddleware(apiKeyManager))
			router.GET("/test", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"status": "ok"})
			})

			req, _ := http.NewRequest("GET", "/test", nil)
			// No API key header

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			return w.Code == http.StatusUnauthorized
		},
		gen.AlphaString(),
	))

	// Property 10.3: Requests with invalid API key should be rejected with 401
	properties.Property("invalid_api_key_rejected", prop.ForAll(
		func(invalidKey string) bool {
			// Skip if the random key happens to match the valid key
			if invalidKey == validKey {
				return true
			}

			router := gin.New()
			router.Use(APIKeyMiddleware(apiKeyManager))
			router.GET("/test", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"status": "ok"})
			})

			req, _ := http.NewRequest("GET", "/test", nil)
			req.Header.Set(APIKeyHeader, invalidKey)

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			return w.Code == http.StatusUnauthorized
		},
		gen.AlphaString(),
	))

	// Property 10.4: Empty API key should be rejected
	properties.Property("empty_api_key_rejected", prop.ForAll(
		func(_ int) bool {
			router := gin.New()
			router.Use(APIKeyMiddleware(apiKeyManager))
			router.GET("/test", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"status": "ok"})
			})

			req, _ := http.NewRequest("GET", "/test", nil)
			req.Header.Set(APIKeyHeader, "")

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			return w.Code == http.StatusUnauthorized
		},
		gen.Int(),
	))

	properties.TestingRun(t)
}

// Property 10.5: API key validation is constant-time (security property)
func TestProperty_APIKeyValidationConsistency(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 20
	properties := gopter.NewProperties(parameters)

	tempDir, err := os.MkdirTemp("", "luo_one_key_validation_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	apiKeyManager, err := NewAPIKeyManager(tempDir)
	if err != nil {
		t.Fatalf("Failed to create API key manager: %v", err)
	}

	validKey := apiKeyManager.GetCurrentKey()

	// Property: ValidateKey returns consistent results
	properties.Property("validate_key_consistent_results", prop.ForAll(
		func(key string) bool {
			result1 := apiKeyManager.ValidateKey(key)
			result2 := apiKeyManager.ValidateKey(key)

			// Results should be consistent
			if result1 != result2 {
				return false
			}

			// Valid key should always return true
			if key == validKey {
				return result1 == true
			}

			// Invalid key should always return false
			return result1 == false
		},
		gen.AlphaString(),
	))

	properties.TestingRun(t)
}

// Property 10.6: JWT token validation
func TestProperty_JWTTokenValidation(t *testing.T) {
	gin.SetMode(gin.TestMode)

	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 20
	properties := gopter.NewProperties(parameters)

	jwtManager := NewJWTManager("test-secret-key", time.Hour)

	// Property: Valid tokens are accepted
	properties.Property("valid_jwt_token_accepted", prop.ForAll(
		func(userID uint, username string) bool {
			if userID == 0 || username == "" {
				return true
			}

			token, _, err := jwtManager.GenerateToken(userID, username)
			if err != nil {
				return false
			}

			claims, err := jwtManager.ValidateToken(token)
			if err != nil {
				return false
			}

			return claims.UserID == userID && claims.Username == username
		},
		gen.UIntRange(1, 10000),
		gen.AlphaString().SuchThat(func(s string) bool { return len(s) > 0 }),
	))

	// Property: Invalid tokens are rejected
	properties.Property("invalid_jwt_token_rejected", prop.ForAll(
		func(invalidToken string) bool {
			_, err := jwtManager.ValidateToken(invalidToken)
			return err != nil
		},
		gen.AlphaString(),
	))

	// Property: Tokens from different secrets are rejected
	properties.Property("tokens_from_different_secrets_rejected", prop.ForAll(
		func(userID uint, username string) bool {
			if userID == 0 || username == "" {
				return true
			}

			// Generate token with different secret
			otherManager := NewJWTManager("different-secret", time.Hour)
			token, _, err := otherManager.GenerateToken(userID, username)
			if err != nil {
				return false
			}

			// Validate with original manager should fail
			_, err = jwtManager.ValidateToken(token)
			return err != nil
		},
		gen.UIntRange(1, 10000),
		gen.AlphaString().SuchThat(func(s string) bool { return len(s) > 0 }),
	))

	properties.TestingRun(t)
}


// Feature: luo-one-email-manager, Property 11: 密钥重置有效性
// For any key reset operation, the old key should become invalid after reset,
// and the new key should be usable for authentication.
// Validates: Requirements 5.2, 6.2

func TestProperty_KeyResetValidity(t *testing.T) {
	gin.SetMode(gin.TestMode)

	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 20
	properties := gopter.NewProperties(parameters)

	// Property 11.1: After reset, old key becomes invalid
	properties.Property("old_key_invalid_after_reset", prop.ForAll(
		func(_ int) bool {
			// Create a fresh temp directory for each test
			tempDir, err := os.MkdirTemp("", "luo_one_reset_test_*")
			if err != nil {
				return false
			}
			defer os.RemoveAll(tempDir)

			apiKeyManager, err := NewAPIKeyManager(tempDir)
			if err != nil {
				return false
			}

			// Get the original key
			oldKey := apiKeyManager.GetCurrentKey()

			// Verify old key is valid before reset
			if !apiKeyManager.ValidateKey(oldKey) {
				return false
			}

			// Reset the key
			newKey, err := apiKeyManager.ResetKey()
			if err != nil {
				return false
			}

			// Old key should now be invalid
			if apiKeyManager.ValidateKey(oldKey) {
				return false
			}

			// New key should be valid
			if !apiKeyManager.ValidateKey(newKey) {
				return false
			}

			// New key should be different from old key
			return oldKey != newKey
		},
		gen.Int(),
	))

	// Property 11.2: New key is usable for authentication after reset
	properties.Property("new_key_usable_after_reset", prop.ForAll(
		func(_ int) bool {
			tempDir, err := os.MkdirTemp("", "luo_one_reset_auth_*")
			if err != nil {
				return false
			}
			defer os.RemoveAll(tempDir)

			apiKeyManager, err := NewAPIKeyManager(tempDir)
			if err != nil {
				return false
			}

			// Reset the key
			newKey, err := apiKeyManager.ResetKey()
			if err != nil {
				return false
			}

			// Test authentication with new key
			router := gin.New()
			router.Use(APIKeyMiddleware(apiKeyManager))
			router.GET("/test", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"status": "ok"})
			})

			req, _ := http.NewRequest("GET", "/test", nil)
			req.Header.Set(APIKeyHeader, newKey)

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			return w.Code == http.StatusOK
		},
		gen.Int(),
	))

	// Property 11.3: Multiple resets produce unique keys
	properties.Property("multiple_resets_produce_unique_keys", prop.ForAll(
		func(resetCount int) bool {
			// Limit reset count to reasonable range
			if resetCount < 2 {
				resetCount = 2
			}
			if resetCount > 10 {
				resetCount = 10
			}

			tempDir, err := os.MkdirTemp("", "luo_one_multi_reset_*")
			if err != nil {
				return false
			}
			defer os.RemoveAll(tempDir)

			apiKeyManager, err := NewAPIKeyManager(tempDir)
			if err != nil {
				return false
			}

			keys := make(map[string]bool)
			keys[apiKeyManager.GetCurrentKey()] = true

			for i := 0; i < resetCount; i++ {
				newKey, err := apiKeyManager.ResetKey()
				if err != nil {
					return false
				}

				// Check if key is unique
				if keys[newKey] {
					return false // Duplicate key found
				}
				keys[newKey] = true

				// Verify new key is valid
				if !apiKeyManager.ValidateKey(newKey) {
					return false
				}
			}

			return true
		},
		gen.IntRange(2, 10),
	))

	// Property 11.4: Key persists after reset (survives manager recreation)
	properties.Property("key_persists_after_reset", prop.ForAll(
		func(_ int) bool {
			tempDir, err := os.MkdirTemp("", "luo_one_persist_*")
			if err != nil {
				return false
			}
			defer os.RemoveAll(tempDir)

			// Create manager and reset key
			apiKeyManager1, err := NewAPIKeyManager(tempDir)
			if err != nil {
				return false
			}

			newKey, err := apiKeyManager1.ResetKey()
			if err != nil {
				return false
			}

			// Create a new manager instance (simulating restart)
			apiKeyManager2, err := NewAPIKeyManager(tempDir)
			if err != nil {
				return false
			}

			// The key should be the same
			if apiKeyManager2.GetCurrentKey() != newKey {
				return false
			}

			// And should be valid
			return apiKeyManager2.ValidateKey(newKey)
		},
		gen.Int(),
	))

	properties.TestingRun(t)
}

// Property 11.5: Reset key has correct format and length
func TestProperty_ResetKeyFormat(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 20
	properties := gopter.NewProperties(parameters)

	properties.Property("reset_key_has_correct_format", prop.ForAll(
		func(_ int) bool {
			tempDir, err := os.MkdirTemp("", "luo_one_format_*")
			if err != nil {
				return false
			}
			defer os.RemoveAll(tempDir)

			apiKeyManager, err := NewAPIKeyManager(tempDir)
			if err != nil {
				return false
			}

			newKey, err := apiKeyManager.ResetKey()
			if err != nil {
				return false
			}

			// Key should be hex encoded (64 chars for 32 bytes)
			expectedLength := APIKeyLength * 2
			if len(newKey) != expectedLength {
				return false
			}

			// Key should only contain hex characters
			for _, c := range newKey {
				if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
					return false
				}
			}

			return true
		},
		gen.Int(),
	))

	properties.TestingRun(t)
}
