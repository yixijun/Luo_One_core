package handlers

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/luo-one/core/internal/api/middleware"
	"github.com/luo-one/core/internal/database/models"
	"github.com/luo-one/core/internal/services"
)

// AccountHandler handles email account related requests
type AccountHandler struct {
	accountService *services.AccountService
	logService     *services.LogService
}

// NewAccountHandler creates a new AccountHandler instance
func NewAccountHandler(accountService *services.AccountService, logService *services.LogService) *AccountHandler {
	return &AccountHandler{
		accountService: accountService,
		logService:     logService,
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
}

// AccountResponse represents the response for an email account
type AccountResponse struct {
	ID          uint   `json:"id"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	IMAPHost    string `json:"imap_host"`
	IMAPPort    int    `json:"imap_port"`
	SMTPHost    string `json:"smtp_host"`
	SMTPPort    int    `json:"smtp_port"`
	Username    string `json:"username"`
	UseSSL      bool   `json:"use_ssl"`
	Enabled     bool   `json:"enabled"`
	LastSyncAt  int64  `json:"last_sync_at"`
	CreatedAt   int64  `json:"created_at"`
}


// toAccountResponse converts an EmailAccount model to AccountResponse
func toAccountResponse(account *models.EmailAccount) AccountResponse {
	return AccountResponse{
		ID:          account.ID,
		Email:       account.Email,
		DisplayName: account.DisplayName,
		IMAPHost:    account.IMAPHost,
		IMAPPort:    account.IMAPPort,
		SMTPHost:    account.SMTPHost,
		SMTPPort:    account.SMTPPort,
		Username:    account.Username,
		UseSSL:      account.UseSSL,
		Enabled:     account.Enabled,
		LastSyncAt:  account.LastSyncAt.Unix(),
		CreatedAt:   account.CreatedAt.Unix(),
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

	var response []AccountResponse
	for _, account := range accounts {
		response = append(response, toAccountResponse(&account))
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
		"data":    toAccountResponse(account),
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

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    toAccountResponse(account),
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

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    toAccountResponse(account),
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

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    toAccountResponse(account),
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

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    toAccountResponse(account),
	})
}
