package handlers

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/luo-one/core/internal/api/middleware"
	"github.com/luo-one/core/internal/database/models"
	"github.com/luo-one/core/internal/services"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// OAuthHandler handles OAuth authentication
type OAuthHandler struct {
	accountService *services.AccountService
	stateStore     *StateStore
}

// StateStore stores OAuth state tokens temporarily
type StateStore struct {
	mu     sync.RWMutex
	states map[string]*OAuthState
}

// OAuthState represents the state of an OAuth flow
type OAuthState struct {
	UserID    uint
	Provider  string
	CreatedAt time.Time
}

// NewOAuthHandler creates a new OAuthHandler
func NewOAuthHandler(accountService *services.AccountService) *OAuthHandler {
	return &OAuthHandler{
		accountService: accountService,
		stateStore: &StateStore{
			states: make(map[string]*OAuthState),
		},
	}
}

// getGoogleOAuthConfig returns the Google OAuth2 config
func getGoogleOAuthConfig() *oauth2.Config {
	clientID := os.Getenv("GOOGLE_CLIENT_ID")
	clientSecret := os.Getenv("GOOGLE_CLIENT_SECRET")
	redirectURL := os.Getenv("GOOGLE_REDIRECT_URL")
	
	if redirectURL == "" {
		redirectURL = "http://localhost:8080/api/oauth/google/callback"
	}

	return &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Scopes: []string{
			"https://mail.google.com/",
			"https://www.googleapis.com/auth/userinfo.email",
		},
		Endpoint: google.Endpoint,
	}
}

// generateState generates a random state token
func generateState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// GetGoogleAuthURL returns the Google OAuth authorization URL
// GET /api/oauth/google/auth
func (h *OAuthHandler) GetGoogleAuthURL(c *gin.Context) {
	userID, exists := middleware.GetUserIDFromContext(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"success": false,
			"error": gin.H{
				"code":    "AUTH_FAILED",
				"message": "User not authenticated",
			},
		})
		return
	}

	config := getGoogleOAuthConfig()
	if config.ClientID == "" || config.ClientSecret == "" {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error": gin.H{
				"code":    "OAUTH_NOT_CONFIGURED",
				"message": "Google OAuth is not configured. Please set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET environment variables.",
			},
		})
		return
	}

	// Generate state token
	state, err := generateState()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error": gin.H{
				"code":    "STATE_GENERATION_FAILED",
				"message": "Failed to generate state token",
			},
		})
		return
	}

	// Store state
	h.stateStore.mu.Lock()
	h.stateStore.states[state] = &OAuthState{
		UserID:    userID,
		Provider:  "google",
		CreatedAt: time.Now(),
	}
	h.stateStore.mu.Unlock()

	// Clean up old states (older than 10 minutes)
	go h.cleanupOldStates()

	// Generate auth URL with offline access for refresh token
	url := config.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.ApprovalForce)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"auth_url": url,
		},
	})
}

// GoogleCallback handles the Google OAuth callback
// GET /api/oauth/google/callback
func (h *OAuthHandler) GoogleCallback(c *gin.Context) {
	code := c.Query("code")
	state := c.Query("state")
	errorParam := c.Query("error")

	if errorParam != "" {
		// User denied access or other error
		c.Redirect(http.StatusFound, "/?oauth_error="+errorParam)
		return
	}

	if code == "" || state == "" {
		c.Redirect(http.StatusFound, "/?oauth_error=missing_params")
		return
	}

	// Verify state
	h.stateStore.mu.RLock()
	oauthState, exists := h.stateStore.states[state]
	h.stateStore.mu.RUnlock()

	if !exists {
		c.Redirect(http.StatusFound, "/?oauth_error=invalid_state")
		return
	}

	// Remove used state
	h.stateStore.mu.Lock()
	delete(h.stateStore.states, state)
	h.stateStore.mu.Unlock()

	// Check if state is expired (10 minutes)
	if time.Since(oauthState.CreatedAt) > 10*time.Minute {
		c.Redirect(http.StatusFound, "/?oauth_error=state_expired")
		return
	}

	// Exchange code for token
	config := getGoogleOAuthConfig()
	token, err := config.Exchange(context.Background(), code)
	if err != nil {
		c.Redirect(http.StatusFound, "/?oauth_error=token_exchange_failed")
		return
	}

	// Get user email from Google
	email, err := getGoogleUserEmail(token.AccessToken)
	if err != nil {
		c.Redirect(http.StatusFound, "/?oauth_error=get_email_failed")
		return
	}

	// Create or update account
	account := &models.EmailAccount{
		UserID:           oauthState.UserID,
		Email:            email,
		DisplayName:      email,
		IMAPHost:         "imap.gmail.com",
		IMAPPort:         993,
		SMTPHost:         "smtp.gmail.com",
		SMTPPort:         587,
		Username:         email,
		UseSSL:           true,
		Enabled:          true,
		SyncDays:         0, // Incremental sync by default
		AuthType:         models.AuthTypeOAuth2,
		OAuthProvider:    "google",
		OAuthTokenExpiry: token.Expiry,
	}

	// Save account with OAuth tokens
	err = h.accountService.CreateAccountWithOAuth(account, token.AccessToken, token.RefreshToken)
	if err != nil {
		c.Redirect(http.StatusFound, "/?oauth_error=save_account_failed")
		return
	}

	// Redirect to success page
	c.Redirect(http.StatusFound, "/?oauth_success=google&email="+email)
}

// getGoogleUserEmail gets the user's email from Google API
func getGoogleUserEmail(accessToken string) (string, error) {
	resp, err := http.Get("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + accessToken)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to get user info: status %d", resp.StatusCode)
	}

	var userInfo struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return "", err
	}

	return userInfo.Email, nil
}

// cleanupOldStates removes states older than 10 minutes
func (h *OAuthHandler) cleanupOldStates() {
	h.stateStore.mu.Lock()
	defer h.stateStore.mu.Unlock()

	for state, oauthState := range h.stateStore.states {
		if time.Since(oauthState.CreatedAt) > 10*time.Minute {
			delete(h.stateStore.states, state)
		}
	}
}

// GetOAuthConfig returns the OAuth configuration status
// GET /api/oauth/config
func (h *OAuthHandler) GetOAuthConfig(c *gin.Context) {
	googleClientID := os.Getenv("GOOGLE_CLIENT_ID")
	
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"google_enabled": googleClientID != "",
		},
	})
}
