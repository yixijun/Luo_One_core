package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/luo-one/core/internal/api/middleware"
	"github.com/luo-one/core/internal/database/models"
	"github.com/luo-one/core/internal/services"
)

// LoginRequest represents the login request body
type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// LoginResponse represents the login response
type LoginResponse struct {
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expires_at"`
}

// AuthHandler handles authentication related requests
type AuthHandler struct {
	userService *services.UserService
	jwtManager  *middleware.JWTManager
	logService  *services.LogService
}

// NewAuthHandler creates a new AuthHandler instance
func NewAuthHandler(userService *services.UserService, jwtManager *middleware.JWTManager, logService *services.LogService) *AuthHandler {
	return &AuthHandler{
		userService: userService,
		jwtManager:  jwtManager,
		logService:  logService,
	}
}

// Login handles user login requests
// POST /api/auth/login
func (h *AuthHandler) Login(c *gin.Context) {
	var req LoginRequest
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

	// Verify credentials
	user, err := h.userService.VerifyPassword(req.Username, req.Password)
	if err != nil {
		// Log failed login attempt
		h.logService.LogLogin(0, req.Username, c.ClientIP(), false, err)
		c.JSON(http.StatusUnauthorized, gin.H{
			"success": false,
			"error": gin.H{
				"code":    "AUTH_FAILED",
				"message": "Invalid username or password",
			},
		})
		return
	}

	// Generate JWT token
	token, expiresAt, err := h.jwtManager.GenerateToken(user.ID, user.Username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error": gin.H{
				"code":    "INTERNAL_ERROR",
				"message": "Failed to generate token",
			},
		})
		return
	}

	// Log successful login
	h.logService.LogLogin(user.ID, req.Username, c.ClientIP(), true, nil)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": LoginResponse{
			Token:     token,
			ExpiresAt: expiresAt,
		},
	})
}

// RefreshToken handles token refresh requests
// POST /api/auth/refresh
func (h *AuthHandler) RefreshToken(c *gin.Context) {
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

	username, _ := middleware.GetUsernameFromContext(c)

	// Generate new token
	token, expiresAt, err := h.jwtManager.GenerateToken(userID, username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error": gin.H{
				"code":    "INTERNAL_ERROR",
				"message": "Failed to generate token",
			},
		})
		return
	}

	// Log token refresh
	h.logService.LogTokenGenerated(userID, "refresh")

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": LoginResponse{
			Token:     token,
			ExpiresAt: expiresAt,
		},
	})
}

// Logout handles user logout requests
// POST /api/auth/logout
func (h *AuthHandler) Logout(c *gin.Context) {
	userID, exists := middleware.GetUserIDFromContext(c)
	if exists {
		// Log logout
		h.logService.LogLogout(userID)
	}

	// In a stateless JWT system, logout is handled client-side by removing the token
	// For enhanced security, you could implement a token blacklist here
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Logged out successfully",
	})
}

// GetCurrentUser returns the current authenticated user info
// GET /api/auth/me
func (h *AuthHandler) GetCurrentUser(c *gin.Context) {
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

	user, err := h.userService.GetUserByID(userID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"error": gin.H{
				"code":    "NOT_FOUND",
				"message": "User not found",
			},
		})
		return
	}

	// Log API request
	h.logService.LogAPIRequest(userID, c.Request.Method, c.Request.URL.Path, http.StatusOK, 0, c.ClientIP(), c.GetHeader("User-Agent"))

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"id":         user.ID,
			"username":   user.Username,
			"nickname":   user.Nickname,
			"avatar":     user.Avatar,
			"created_at": user.CreatedAt.Unix(),
		},
	})
}

// UserProfileResponse represents the user profile response
type UserProfileResponse struct {
	ID        uint   `json:"id"`
	Username  string `json:"username"`
	Nickname  string `json:"nickname"`
	Avatar    string `json:"avatar"`
	CreatedAt int64  `json:"created_at"`
}

// ToProfileResponse converts a User model to UserProfileResponse
func ToProfileResponse(user *models.User) UserProfileResponse {
	return UserProfileResponse{
		ID:        user.ID,
		Username:  user.Username,
		Nickname:  user.Nickname,
		Avatar:    user.Avatar,
		CreatedAt: user.CreatedAt.Unix(),
	}
}
