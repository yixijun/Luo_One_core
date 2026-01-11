package handlers

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/luo-one/core/internal/api/middleware"
	"github.com/luo-one/core/internal/database/models"
	"github.com/luo-one/core/internal/services"
	"gorm.io/gorm"
)

// AccountHandler handles email account related requests
type AccountHandler struct {
	accountService *services.AccountService
	logService     *services.LogService
	db             *gorm.DB
}

// NewAccountHandler creates a new AccountHandler instance
func NewAccountHandler(accountService *services.AccountService, logService *services.LogService, db *gorm.DB) *AccountHandler {
	return &AccountHandler{
		accountService: accountService,
		logService:     logService,
		db:             db,
	}
}

// CreateAccountRequest represents the request to create an email account
type CreateAccountRequest struct {
	Email       string `json:"email" binding:"required,email"`
	DisplayName string `json:"display_name"`
	IMAPHost    string `json:"imap_host" binding:"required"`
	IMAPPort    int    `json:"imap_port" binding:"required"`
	SMTPHost    string `json:"smtp_host" binding:"required"`
	SMTPPort    int    `json:"smtp_port" binding:"required"`
	Username    string `json:"username" binding:"required"`
	Password    string `json:"password" binding:"required"`
	UseSSL      bool   `json:"use_ssl"`
	SyncDays    int    `json:"sync_days"` // 默认 -1 全部
}

// UpdateAccountRequest represents the request to update an email account
type UpdateAccountRequest struct {
	DisplayName string `json:"display_name"`
	IMAPHost    string `json:"imap_host"`
	IMAPPort    int    `json:"imap_port"`
	SMTPHost    string `json:"smtp_host"`
	SMTPPort    int    `json:"smtp_port"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	UseSSL      bool   `json:"use_ssl"`
	SyncDays    *int   `json:"sync_days"` // 使用指针区分 0 和未设置
}

// AccountResponse represents the response for an email account
type AccountResponse struct {
	ID            uint   `json:"id"`
	Email         string `json:"email"`
	DisplayName   string `json:"display_name"`
	IMAPHost      string `json:"imap_host"`
	IMAPPort      int    `json:"imap_port"`
	SMTPHost      string `json:"smtp_host"`
	SMTPPort      int    `json:"smtp_port"`
	Username      string `json:"username"`
	UseSSL        bool   `json:"use_ssl"`
	Enabled       bool   `json:"enabled"`
	SyncDays      int    `json:"sync_days"`
	SortOrder     int    `json:"sort_order"`
	LastSyncAt    int64  `json:"last_sync_at"`
	CreatedAt     int64  `json:"created_at"`
	EmailCount    int64  `json:"email_count"`
	AuthType      string `json:"auth_type"`
	OAuthProvider string `json:"oauth_provider"`
}


// toAccountResponse converts an EmailAccount model to AccountResponse
func toAccountResponse(account *models.EmailAccount, emailCount int64) AccountResponse {
	return AccountResponse{
		ID:            account.ID,
		Email:         account.Email,
		DisplayName:   account.DisplayName,
		IMAPHost:      account.IMAPHost,
		IMAPPort:      account.IMAPPort,
		SMTPHost:      account.SMTPHost,
		SMTPPort:      account.SMTPPort,
		Username:      account.Username,
		UseSSL:        account.UseSSL,
		Enabled:       account.Enabled,
		SyncDays:      account.SyncDays,
		SortOrder:     account.SortOrder,
		LastSyncAt:    account.LastSyncAt.Unix(),
		CreatedAt:     account.CreatedAt.Unix(),
		EmailCount:    emailCount,
		AuthType:      string(account.AuthType),
		OAuthProvider: account.OAuthProvider,
	}
}

// ListAccounts returns all email accounts for the current user
// GET /api/accounts
func (h *AccountHandler) ListAccounts(c *gin.Context) {
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

	accounts, err := h.accountService.GetAccountsByUserID(userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error": gin.H{
				"code":    "INTERNAL_ERROR",
				"message": "Failed to retrieve accounts",
			},
		})
		return
	}

	// 获取每个账户的邮件数量
	emailCounts := h.accountService.GetEmailCountsByAccountIDs(accounts)

	var response []AccountResponse
	for _, account := range accounts {
		emailCount := emailCounts[account.ID]
		response = append(response, toAccountResponse(&account, emailCount))
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    response,
	})
}

// CreateAccount creates a new email account
// POST /api/accounts
func (h *AccountHandler) CreateAccount(c *gin.Context) {
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

	var req CreateAccountRequest
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

	input := services.CreateAccountInput{
		UserID:      userID,
		Email:       req.Email,
		DisplayName: req.DisplayName,
		IMAPHost:    req.IMAPHost,
		IMAPPort:    req.IMAPPort,
		SMTPHost:    req.SMTPHost,
		SMTPPort:    req.SMTPPort,
		Username:    req.Username,
		Password:    req.Password,
		UseSSL:      req.UseSSL,
		SyncDays:    req.SyncDays,
	}

	account, err := h.accountService.CreateAccount(input)
	if err != nil {
		if err == services.ErrAccountAlreadyExists {
			c.JSON(http.StatusConflict, gin.H{
				"success": false,
				"error": gin.H{
					"code":    "CONFLICT",
					"message": "Email account already exists",
				},
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error": gin.H{
				"code":    "INTERNAL_ERROR",
				"message": "Failed to create account",
			},
		})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"success": true,
		"data":    toAccountResponse(account, 0),
	})
}


// GetAccount returns a specific email account
// GET /api/accounts/:id
func (h *AccountHandler) GetAccount(c *gin.Context) {
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

	accountID, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error": gin.H{
				"code":    "VALIDATION_ERROR",
				"message": "Invalid account ID",
			},
		})
		return
	}

	account, err := h.accountService.GetAccountByIDAndUserID(uint(accountID), userID)
	if err != nil {
		if err == services.ErrAccountNotFound {
			c.JSON(http.StatusNotFound, gin.H{
				"success": false,
				"error": gin.H{
					"code":    "NOT_FOUND",
					"message": "Account not found",
				},
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error": gin.H{
				"code":    "INTERNAL_ERROR",
				"message": "Failed to retrieve account",
			},
		})
		return
	}

	// 获取该账户的邮件数量
	var emailCount int64
	h.db.Model(&models.Email{}).Where("account_id = ?", account.ID).Count(&emailCount)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    toAccountResponse(account, emailCount),
	})
}

// UpdateAccount updates an email account
// PUT /api/accounts/:id
func (h *AccountHandler) UpdateAccount(c *gin.Context) {
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

	accountID, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error": gin.H{
				"code":    "VALIDATION_ERROR",
				"message": "Invalid account ID",
			},
		})
		return
	}

	var req UpdateAccountRequest
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

	input := services.UpdateAccountInput{
		DisplayName: req.DisplayName,
		IMAPHost:    req.IMAPHost,
		IMAPPort:    req.IMAPPort,
		SMTPHost:    req.SMTPHost,
		SMTPPort:    req.SMTPPort,
		Username:    req.Username,
		Password:    req.Password,
		UseSSL:      req.UseSSL,
		SyncDays:    req.SyncDays,
	}

	account, err := h.accountService.UpdateAccount(uint(accountID), userID, input)
	if err != nil {
		if err == services.ErrAccountNotFound {
			c.JSON(http.StatusNotFound, gin.H{
				"success": false,
				"error": gin.H{
					"code":    "NOT_FOUND",
					"message": "Account not found",
				},
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error": gin.H{
				"code":    "INTERNAL_ERROR",
				"message": "Failed to update account",
			},
		})
		return
	}

	// 获取该账户的邮件数量
	var emailCount int64
	h.db.Model(&models.Email{}).Where("account_id = ?", account.ID).Count(&emailCount)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    toAccountResponse(account, emailCount),
	})
}


// DeleteAccount deletes an email account
// DELETE /api/accounts/:id
func (h *AccountHandler) DeleteAccount(c *gin.Context) {
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

	accountID, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error": gin.H{
				"code":    "VALIDATION_ERROR",
				"message": "Invalid account ID",
			},
		})
		return
	}

	err = h.accountService.DeleteAccount(uint(accountID), userID)
	if err != nil {
		if err == services.ErrAccountNotFound {
			c.JSON(http.StatusNotFound, gin.H{
				"success": false,
				"error": gin.H{
					"code":    "NOT_FOUND",
					"message": "Account not found",
				},
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error": gin.H{
				"code":    "INTERNAL_ERROR",
				"message": "Failed to delete account",
			},
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Account deleted successfully",
	})
}

// TestConnection tests the connection for an email account
// POST /api/accounts/:id/test
func (h *AccountHandler) TestConnection(c *gin.Context) {
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

	accountID, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error": gin.H{
				"code":    "VALIDATION_ERROR",
				"message": "Invalid account ID",
			},
		})
		return
	}

	result, err := h.accountService.TestConnectionByID(uint(accountID), userID)
	if err != nil {
		if err == services.ErrAccountNotFound {
			c.JSON(http.StatusNotFound, gin.H{
				"success": false,
				"error": gin.H{
					"code":    "NOT_FOUND",
					"message": "Account not found",
				},
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error": gin.H{
				"code":    "INTERNAL_ERROR",
				"message": "Failed to test connection",
			},
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    result,
	})
}

// TestConnectionDirectRequest represents the request to test connection without saving
type TestConnectionDirectRequest struct {
	IMAPHost string `json:"imap_host" binding:"required"`
	IMAPPort int    `json:"imap_port" binding:"required"`
	SMTPHost string `json:"smtp_host" binding:"required"`
	SMTPPort int    `json:"smtp_port" binding:"required"`
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
	UseSSL   bool   `json:"use_ssl"`
}

// TestConnectionDirect tests the connection without saving the account
// POST /api/accounts/test
func (h *AccountHandler) TestConnectionDirect(c *gin.Context) {
	_, exists := middleware.GetUserIDFromContext(c)
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

	var req TestConnectionDirectRequest
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

	input := services.TestConnectionInput{
		IMAPHost: req.IMAPHost,
		IMAPPort: req.IMAPPort,
		SMTPHost: req.SMTPHost,
		SMTPPort: req.SMTPPort,
		Username: req.Username,
		Password: req.Password,
		UseSSL:   req.UseSSL,
	}

	result := h.accountService.TestConnectionDirect(input)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    result,
	})
}

// EnableAccount enables an email account
// PUT /api/accounts/:id/enable
func (h *AccountHandler) EnableAccount(c *gin.Context) {
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

	accountID, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error": gin.H{
				"code":    "VALIDATION_ERROR",
				"message": "Invalid account ID",
			},
		})
		return
	}

	account, err := h.accountService.EnableAccount(uint(accountID), userID)
	if err != nil {
		if err == services.ErrAccountNotFound {
			c.JSON(http.StatusNotFound, gin.H{
				"success": false,
				"error": gin.H{
					"code":    "NOT_FOUND",
					"message": "Account not found",
				},
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error": gin.H{
				"code":    "INTERNAL_ERROR",
				"message": "Failed to enable account",
			},
		})
		return
	}

	// 获取该账户的邮件数量
	var emailCount int64
	h.db.Model(&models.Email{}).Where("account_id = ?", account.ID).Count(&emailCount)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    toAccountResponse(account, emailCount),
	})
}

// DisableAccount disables an email account
// PUT /api/accounts/:id/disable
func (h *AccountHandler) DisableAccount(c *gin.Context) {
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

	accountID, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error": gin.H{
				"code":    "VALIDATION_ERROR",
				"message": "Invalid account ID",
			},
		})
		return
	}

	account, err := h.accountService.DisableAccount(uint(accountID), userID)
	if err != nil {
		if err == services.ErrAccountNotFound {
			c.JSON(http.StatusNotFound, gin.H{
				"success": false,
				"error": gin.H{
					"code":    "NOT_FOUND",
					"message": "Account not found",
				},
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error": gin.H{
				"code":    "INTERNAL_ERROR",
				"message": "Failed to disable account",
			},
		})
		return
	}

	// 获取该账户的邮件数量
	var emailCount int64
	h.db.Model(&models.Email{}).Where("account_id = ?", account.ID).Count(&emailCount)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    toAccountResponse(account, emailCount),
	})
}


// ReorderAccountsRequest represents the request to reorder accounts
type ReorderAccountsRequest struct {
	AccountIDs []uint `json:"account_ids" binding:"required"`
}

// ReorderAccounts updates the sort order of accounts
// PUT /api/accounts/reorder
func (h *AccountHandler) ReorderAccounts(c *gin.Context) {
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

	var req ReorderAccountsRequest
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

	// 更新每个账户的排序顺序
	for i, accountID := range req.AccountIDs {
		if err := h.db.Model(&models.EmailAccount{}).
			Where("id = ? AND user_id = ?", accountID, userID).
			Update("sort_order", i).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"success": false,
				"error": gin.H{
					"code":    "INTERNAL_ERROR",
					"message": "Failed to update account order",
				},
			})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Account order updated successfully",
	})
}
