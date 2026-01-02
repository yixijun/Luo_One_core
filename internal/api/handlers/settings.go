package handlers

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/luo-one/core/internal/api/middleware"
	"github.com/luo-one/core/internal/database/models"
	"github.com/luo-one/core/internal/functions/ai"
	"github.com/luo-one/core/internal/services"
)

// SettingsHandler handles user settings related requests
type SettingsHandler struct {
	userService *services.UserService
	logService  *services.LogService
}

// NewSettingsHandler creates a new SettingsHandler instance
func NewSettingsHandler(userService *services.UserService, logService *services.LogService) *SettingsHandler {
	return &SettingsHandler{
		userService: userService,
		logService:  logService,
	}
}

// UserSettingsResponse represents the response for user settings
type UserSettingsResponse struct {
	AIEnabled       bool   `json:"ai_enabled"`
	AIProvider      string `json:"ai_provider"`
	AIAPIKey        string `json:"ai_api_key"`
	AIModel         string `json:"ai_model"`
	ExtractCode     bool   `json:"extract_code"`
	DetectAd        bool   `json:"detect_ad"`
	Summarize       bool   `json:"summarize"`
	JudgeImportance bool   `json:"judge_importance"`

	// Google OAuth 配置
	GoogleClientID     string `json:"google_client_id"`
	GoogleClientSecret string `json:"google_client_secret"`
	GoogleRedirectURL  string `json:"google_redirect_url"`

	// 主题和字体配置
	Theme string `json:"theme"`
	Font  string `json:"font"`
}

// UpdateSettingsRequest represents the request to update user settings
type UpdateSettingsRequest struct {
	AIEnabled       *bool   `json:"ai_enabled"`
	AIProvider      *string `json:"ai_provider"`
	AIAPIKey        *string `json:"ai_api_key"`
	AIModel         *string `json:"ai_model"`
	ExtractCode     *bool   `json:"extract_code"`
	DetectAd        *bool   `json:"detect_ad"`
	Summarize       *bool   `json:"summarize"`
	JudgeImportance *bool   `json:"judge_importance"`

	// Google OAuth 配置
	GoogleClientID     *string `json:"google_client_id"`
	GoogleClientSecret *string `json:"google_client_secret"`
	GoogleRedirectURL  *string `json:"google_redirect_url"`

	// 主题和字体配置
	Theme *string `json:"theme"`
	Font  *string `json:"font"`
}

// toSettingsResponse converts UserSettings model to UserSettingsResponse
func toSettingsResponse(settings *models.UserSettings) UserSettingsResponse {
	theme := settings.Theme
	if theme == "" {
		theme = "dark"
	}
	font := settings.Font
	if font == "" {
		font = "system"
	}
	return UserSettingsResponse{
		AIEnabled:          settings.AIEnabled,
		AIProvider:         settings.AIProvider,
		AIAPIKey:           settings.AIAPIKey,
		AIModel:            settings.AIModel,
		ExtractCode:        settings.ExtractCode,
		DetectAd:           settings.DetectAd,
		Summarize:          settings.Summarize,
		JudgeImportance:    settings.JudgeImportance,
		GoogleClientID:     settings.GoogleClientID,
		GoogleClientSecret: settings.GoogleClientSecret,
		GoogleRedirectURL:  settings.GoogleRedirectURL,
		Theme:              theme,
		Font:               font,
	}
}


// GetSettings returns the current user's settings
// GET /api/settings
func (h *SettingsHandler) GetSettings(c *gin.Context) {
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

	settings, err := h.userService.GetUserSettings(userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error": gin.H{
				"code":    "INTERNAL_ERROR",
				"message": "Failed to retrieve settings",
			},
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    toSettingsResponse(settings),
	})
}

// UpdateSettings updates the current user's settings
// PUT /api/settings
func (h *SettingsHandler) UpdateSettings(c *gin.Context) {
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

	log.Printf("[Settings] UpdateSettings called for userID: %d", userID)

	var req UpdateSettingsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("[Settings] UpdateSettings: Invalid request body: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error": gin.H{
				"code":    "VALIDATION_ERROR",
				"message": "Invalid request body",
				"details": err.Error(),
			},
		})
		return
	}

	// Log incoming Google OAuth fields
	if req.GoogleClientID != nil {
		log.Printf("[Settings] UpdateSettings: GoogleClientID provided (len=%d)", len(*req.GoogleClientID))
	}
	if req.GoogleClientSecret != nil {
		log.Printf("[Settings] UpdateSettings: GoogleClientSecret provided (len=%d)", len(*req.GoogleClientSecret))
	}
	if req.GoogleRedirectURL != nil {
		log.Printf("[Settings] UpdateSettings: GoogleRedirectURL provided: %s", *req.GoogleRedirectURL)
	}

	// Get current settings
	settings, err := h.userService.GetUserSettings(userID)
	if err != nil {
		log.Printf("[Settings] UpdateSettings: Failed to get current settings: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error": gin.H{
				"code":    "INTERNAL_ERROR",
				"message": "Failed to retrieve settings",
			},
		})
		return
	}

	log.Printf("[Settings] UpdateSettings: Current settings - GoogleClientID len=%d, GoogleClientSecret len=%d",
		len(settings.GoogleClientID), len(settings.GoogleClientSecret))

	// Update only provided fields
	if req.AIEnabled != nil {
		settings.AIEnabled = *req.AIEnabled
	}
	if req.AIProvider != nil {
		settings.AIProvider = *req.AIProvider
	}
	if req.AIAPIKey != nil {
		settings.AIAPIKey = *req.AIAPIKey
	}
	if req.AIModel != nil {
		settings.AIModel = *req.AIModel
	}
	if req.ExtractCode != nil {
		settings.ExtractCode = *req.ExtractCode
	}
	if req.DetectAd != nil {
		settings.DetectAd = *req.DetectAd
	}
	if req.Summarize != nil {
		settings.Summarize = *req.Summarize
	}
	if req.JudgeImportance != nil {
		settings.JudgeImportance = *req.JudgeImportance
	}
	if req.GoogleClientID != nil {
		settings.GoogleClientID = *req.GoogleClientID
		log.Printf("[Settings] UpdateSettings: Setting GoogleClientID to len=%d", len(settings.GoogleClientID))
	}
	if req.GoogleClientSecret != nil {
		settings.GoogleClientSecret = *req.GoogleClientSecret
		log.Printf("[Settings] UpdateSettings: Setting GoogleClientSecret to len=%d", len(settings.GoogleClientSecret))
	}
	if req.GoogleRedirectURL != nil {
		settings.GoogleRedirectURL = *req.GoogleRedirectURL
		log.Printf("[Settings] UpdateSettings: Setting GoogleRedirectURL to %s", settings.GoogleRedirectURL)
	}
	if req.Theme != nil {
		settings.Theme = *req.Theme
	}
	if req.Font != nil {
		settings.Font = *req.Font
	}

	// Save updated settings
	err = h.userService.UpdateUserSettings(userID, settings)
	if err != nil {
		log.Printf("[Settings] UpdateSettings: Failed to save settings: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error": gin.H{
				"code":    "INTERNAL_ERROR",
				"message": "Failed to update settings",
			},
		})
		return
	}

	log.Printf("[Settings] UpdateSettings: Settings saved successfully for userID %d", userID)

	// Log settings update
	h.logService.LogInfo(userID, models.LogModuleAuth, "settings_update", "User settings updated", map[string]interface{}{
		"ai_enabled":       settings.AIEnabled,
		"extract_code":     settings.ExtractCode,
		"detect_ad":        settings.DetectAd,
		"summarize":        settings.Summarize,
		"judge_importance": settings.JudgeImportance,
	})

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    toSettingsResponse(settings),
	})
}

// TestAIRequest represents the request to test AI connection
type TestAIRequest struct {
	Provider string `json:"provider"`
	BaseURL  string `json:"base_url"`
	APIKey   string `json:"api_key"`
	Model    string `json:"model"`
}

// TestAI tests the AI API connection
// POST /api/settings/test-ai
func (h *SettingsHandler) TestAI(c *gin.Context) {
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

	var req TestAIRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error": gin.H{
				"code":    "VALIDATION_ERROR",
				"message": "Invalid request body",
			},
		})
		return
	}

	if req.APIKey == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error": gin.H{
				"code":    "VALIDATION_ERROR",
				"message": "API Key is required",
			},
		})
		return
	}

	// Create AI client and test connection
	aiClient := ai.NewClient()
	aiClient.ConfigureWithBaseURL(req.Provider, req.APIKey, req.Model, req.BaseURL)

	response, err := aiClient.TestConnection()
	if err != nil {
		h.logService.LogWarn(userID, models.LogModuleAuth, "test_ai", "AI connection test failed", map[string]interface{}{
			"provider": req.Provider,
			"error":    err.Error(),
		})
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"error": gin.H{
				"code":    "AI_TEST_FAILED",
				"message": err.Error(),
			},
		})
		return
	}

	h.logService.LogInfo(userID, models.LogModuleAuth, "test_ai", "AI connection test successful", map[string]interface{}{
		"provider": req.Provider,
		"response": response,
	})

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"response": response,
		},
		"message": "AI connection test successful",
	})
}
