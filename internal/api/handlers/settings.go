package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/luo-one/core/internal/api/middleware"
	"github.com/luo-one/core/internal/database/models"
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
}

// toSettingsResponse converts UserSettings model to UserSettingsResponse
func toSettingsResponse(settings *models.UserSettings) UserSettingsResponse {
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

	var req UpdateSettingsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
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

	// Get current settings
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
	}
	if req.GoogleClientSecret != nil {
		settings.GoogleClientSecret = *req.GoogleClientSecret
	}
	if req.GoogleRedirectURL != nil {
		settings.GoogleRedirectURL = *req.GoogleRedirectURL
	}

	// Save updated settings
	err = h.userService.UpdateUserSettings(userID, settings)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error": gin.H{
				"code":    "INTERNAL_ERROR",
				"message": "Failed to update settings",
			},
		})
		return
	}

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
