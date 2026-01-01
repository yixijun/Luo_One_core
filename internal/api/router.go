package api

import (
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/luo-one/core/internal/api/handlers"
	"github.com/luo-one/core/internal/api/middleware"
	"github.com/luo-one/core/internal/config"
	"github.com/luo-one/core/internal/services"
	"github.com/luo-one/core/internal/user"
	"gorm.io/gorm"
)

// SetupRouter initializes and returns the Gin router with all routes configured
func SetupRouter(db *gorm.DB, cfg *config.Config) (*gin.Engine, *middleware.AuthManager, error) {
	router := gin.Default()

	// 配置 CORS - 允许跨域请求
	router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization", "X-API-Key"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	// Initialize auth manager
	authManager, err := middleware.NewAuthManager(cfg.DataDir, cfg.JWTSecret, middleware.DefaultTokenExpiry)
	if err != nil {
		return nil, nil, err
	}

	// Initialize user manager
	userManager := user.NewManager(cfg.DataDir)

	// Initialize services
	userService := services.NewUserService(db, userManager)
	logService := services.NewLogServiceWithLevel(db, cfg.LogLevel)

	// Create encryption key from JWT secret for account service
	encryptionKey := []byte(cfg.JWTSecret)
	accountService := services.NewAccountService(db, encryptionKey)
	emailService := services.NewEmailService(db, accountService, userManager)

	// Start sync scheduler (auto sync every 2 minutes)
	syncScheduler := services.NewSyncScheduler(db, emailService, logService, 2*time.Minute)
	syncScheduler.Start()

	// Initialize handlers
	authHandler := handlers.NewAuthHandler(userService, authManager.JWTManager, logService)
	userHandler := handlers.NewUserHandler(userService, logService)
	accountHandler := handlers.NewAccountHandler(accountService, logService)
	emailHandler := handlers.NewEmailHandler(emailService, logService)
	settingsHandler := handlers.NewSettingsHandler(userService, logService)
	oauthHandler := handlers.NewOAuthHandler(accountService)

	// Health check endpoint (no auth required)
	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	// API routes
	api := router.Group("/api")
	{
		// Apply API key middleware to all API routes
		api.Use(middleware.APIKeyMiddleware(authManager.APIKeyManager))

		// Auth routes (API key required, but no JWT required)
		auth := api.Group("/auth")
		{
			auth.POST("/login", authHandler.Login)
		}

		// OAuth routes (some require JWT, callback doesn't)
		oauth := api.Group("/oauth")
		{
			oauth.GET("/config", oauthHandler.GetOAuthConfig) // Check if OAuth is configured
			oauth.GET("/google/callback", oauthHandler.GoogleCallback) // OAuth callback (no JWT needed)
		}

		// Protected routes (API key + JWT required)
		protected := api.Group("")
		protected.Use(middleware.JWTMiddleware(authManager.JWTManager))
		{
			// Auth routes that require authentication
			protected.POST("/auth/refresh", authHandler.RefreshToken)
			protected.POST("/auth/logout", authHandler.Logout)
			protected.GET("/auth/me", authHandler.GetCurrentUser)

			// User routes
			userGroup := protected.Group("/user")
			{
				userGroup.GET("/profile", userHandler.GetProfile)
				userGroup.PUT("/profile", userHandler.UpdateProfile)
				userGroup.PUT("/password", userHandler.ChangePassword)
			}

			// Email account routes
			accounts := protected.Group("/accounts")
			{
				accounts.GET("", accountHandler.ListAccounts)
				accounts.POST("", accountHandler.CreateAccount)
				accounts.POST("/test", accountHandler.TestConnectionDirect) // Test without saving (must be before /:id routes)
				accounts.GET("/:id", accountHandler.GetAccount)
				accounts.PUT("/:id", accountHandler.UpdateAccount)
				accounts.DELETE("/:id", accountHandler.DeleteAccount)
				accounts.POST("/:id/test", accountHandler.TestConnection)
				accounts.PUT("/:id/enable", accountHandler.EnableAccount)
				accounts.PUT("/:id/disable", accountHandler.DisableAccount)
			}

			// Email routes
			emails := protected.Group("/emails")
			{
				emails.GET("", emailHandler.ListEmails)
				emails.GET("/count", emailHandler.GetEmailCount) // 检查邮件数量
				emails.PUT("/read-all", emailHandler.MarkAllAsRead) // 全部已读
				emails.GET("/:id", emailHandler.GetEmail)
				emails.DELETE("/:id", emailHandler.DeleteEmail)
				emails.PUT("/:id/read", emailHandler.MarkAsRead)
				emails.POST("/send", emailHandler.SendEmail)
				emails.POST("/sync", emailHandler.SyncEmails)
				// Attachment routes
				emails.GET("/:id/attachments", emailHandler.ListAttachments)
				emails.GET("/:id/attachments/:filename", emailHandler.DownloadAttachment)
				emails.POST("/:id/attachments", emailHandler.UploadAttachment)
				emails.DELETE("/:id/attachments/:filename", emailHandler.DeleteAttachment)
			}

			// Settings routes
			settings := protected.Group("/settings")
			{
				settings.GET("", settingsHandler.GetSettings)
				settings.PUT("", settingsHandler.UpdateSettings)
			}

			// OAuth routes (protected - need JWT to initiate)
			oauthProtected := protected.Group("/oauth")
			{
				oauthProtected.GET("/google/auth", oauthHandler.GetGoogleAuthURL)
			}
		}
	}

	return router, authManager, nil
}

// SetupRouterSimple is a simplified version for backward compatibility
func SetupRouterSimple(db *gorm.DB, cfg *config.Config) *gin.Engine {
	router, _, _ := SetupRouter(db, cfg)
	return router
}
