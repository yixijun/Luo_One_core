package handlers

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/luo-one/core/internal/api/middleware"
	"github.com/luo-one/core/internal/database/models"
	"github.com/luo-one/core/internal/services"
)

// EmailHandler handles email related requests
type EmailHandler struct {
	emailService *services.EmailService
	logService   *services.LogService
}

// NewEmailHandler creates a new EmailHandler instance
func NewEmailHandler(emailService *services.EmailService, logService *services.LogService) *EmailHandler {
	return &EmailHandler{
		emailService: emailService,
		logService:   logService,
	}
}

// SendEmailRequest represents the request to send an email
type SendEmailRequest struct {
	AccountID   uint     `json:"account_id" binding:"required"`
	To          []string `json:"to" binding:"required"`
	Cc          []string `json:"cc"`
	Bcc         []string `json:"bcc"`
	Subject     string   `json:"subject" binding:"required"`
	Body        string   `json:"body"`
	HTMLBody    string   `json:"html_body"`
	Attachments []string `json:"attachments"`
}

// SyncRequest represents the request to sync emails
type SyncRequest struct {
	AccountID uint `json:"account_id" binding:"required"`
}

// EmailResponse represents the response for an email
type EmailResponse struct {
	ID              uint                     `json:"id"`
	AccountID       uint                     `json:"account_id"`
	MessageID       string                   `json:"message_id"`
	Subject         string                   `json:"subject"`
	From            string                   `json:"from"`
	To              []string                 `json:"to"`
	Date            int64                    `json:"date"`
	Body            string                   `json:"body"`
	HTMLBody        string                   `json:"html_body"`
	HasAttachments  bool                     `json:"has_attachments"`
	IsRead          bool                     `json:"is_read"`
	ProcessedResult *ProcessedResultResponse `json:"processed_result,omitempty"`
}


// ProcessedResultResponse represents the processed result in response
type ProcessedResultResponse struct {
	VerificationCode string `json:"verification_code,omitempty"`
	IsAd             bool   `json:"is_ad"`
	Summary          string `json:"summary,omitempty"`
	Importance       string `json:"importance"`
	ProcessedBy      string `json:"processed_by"`
	ProcessedAt      int64  `json:"processed_at"`
}

// toEmailResponse converts an Email model to EmailResponse
func toEmailResponse(email *models.Email) EmailResponse {
	var toAddrs []string
	if email.ToAddrs != "" {
		json.Unmarshal([]byte(email.ToAddrs), &toAddrs)
	}

	response := EmailResponse{
		ID:             email.ID,
		AccountID:      email.AccountID,
		MessageID:      email.MessageID,
		Subject:        email.Subject,
		From:           email.FromAddr,
		To:             toAddrs,
		Date:           email.Date.Unix(),
		Body:           email.Body,
		HTMLBody:       email.HTMLBody,
		HasAttachments: email.HasAttachments,
		IsRead:         email.IsRead,
	}

	if email.ProcessedResult != nil {
		response.ProcessedResult = &ProcessedResultResponse{
			VerificationCode: email.ProcessedResult.VerificationCode,
			IsAd:             email.ProcessedResult.IsAd,
			Summary:          email.ProcessedResult.Summary,
			Importance:       email.ProcessedResult.Importance,
			ProcessedBy:      email.ProcessedResult.ProcessedBy,
			ProcessedAt:      email.ProcessedResult.ProcessedAt.Unix(),
		}
	}

	return response
}

// ListEmails returns a list of emails with pagination
// GET /api/emails
func (h *EmailHandler) ListEmails(c *gin.Context) {
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

	// Parse query parameters
	accountID, _ := strconv.ParseUint(c.Query("account_id"), 10, 32)
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
	sortBy := c.DefaultQuery("sort", "date")
	sortOrder := c.DefaultQuery("order", "desc")
	search := c.Query("search")

	opts := services.EmailListOptions{
		AccountID: uint(accountID),
		Page:      page,
		Limit:     limit,
		SortBy:    sortBy,
		SortOrder: sortOrder,
		Search:    search,
	}

	result, err := h.emailService.ListEmails(userID, opts)
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
				"message": "Failed to retrieve emails",
			},
		})
		return
	}

	var emails []EmailResponse
	for _, email := range result.Emails {
		emails = append(emails, toEmailResponse(&email))
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"total":  result.Total,
			"page":   result.Page,
			"limit":  result.Limit,
			"emails": emails,
		},
	})
}


// GetEmail returns a specific email
// GET /api/emails/:id
func (h *EmailHandler) GetEmail(c *gin.Context) {
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

	emailID, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error": gin.H{
				"code":    "VALIDATION_ERROR",
				"message": "Invalid email ID",
			},
		})
		return
	}

	email, err := h.emailService.GetEmailByIDAndUserID(uint(emailID), userID)
	if err != nil {
		if err == services.ErrEmailNotFound {
			c.JSON(http.StatusNotFound, gin.H{
				"success": false,
				"error": gin.H{
					"code":    "NOT_FOUND",
					"message": "Email not found",
				},
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error": gin.H{
				"code":    "INTERNAL_ERROR",
				"message": "Failed to retrieve email",
			},
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    toEmailResponse(email),
	})
}

// DeleteEmail deletes an email
// DELETE /api/emails/:id
func (h *EmailHandler) DeleteEmail(c *gin.Context) {
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

	emailID, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error": gin.H{
				"code":    "VALIDATION_ERROR",
				"message": "Invalid email ID",
			},
		})
		return
	}

	// Get email first for logging
	email, _ := h.emailService.GetEmailByIDAndUserID(uint(emailID), userID)

	err = h.emailService.DeleteEmail(uint(emailID), userID)
	if err != nil {
		if err == services.ErrEmailNotFound {
			c.JSON(http.StatusNotFound, gin.H{
				"success": false,
				"error": gin.H{
					"code":    "NOT_FOUND",
					"message": "Email not found",
				},
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error": gin.H{
				"code":    "INTERNAL_ERROR",
				"message": "Failed to delete email",
			},
		})
		return
	}

	// Log email deletion
	if email != nil {
		h.logService.LogEmailDelete(userID, uint(emailID), email.Subject)
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Email deleted successfully",
	})
}

// MarkAsRead marks an email as read
// PUT /api/emails/:id/read
func (h *EmailHandler) MarkAsRead(c *gin.Context) {
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

	emailID, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error": gin.H{
				"code":    "VALIDATION_ERROR",
				"message": "Invalid email ID",
			},
		})
		return
	}

	err = h.emailService.MarkEmailAsRead(uint(emailID), userID)
	if err != nil {
		if err == services.ErrEmailNotFound {
			c.JSON(http.StatusNotFound, gin.H{
				"success": false,
				"error": gin.H{
					"code":    "NOT_FOUND",
					"message": "Email not found",
				},
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error": gin.H{
				"code":    "INTERNAL_ERROR",
				"message": "Failed to mark email as read",
			},
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Email marked as read",
	})
}


// SendEmail sends an email
// POST /api/emails/send
func (h *EmailHandler) SendEmail(c *gin.Context) {
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

	var req SendEmailRequest
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

	// Validate that at least body or html_body is provided
	if req.Body == "" && req.HTMLBody == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error": gin.H{
				"code":    "VALIDATION_ERROR",
				"message": "Either body or html_body is required",
			},
		})
		return
	}

	sendReq := services.SendEmailRequest{
		AccountID:   req.AccountID,
		To:          req.To,
		Cc:          req.Cc,
		Bcc:         req.Bcc,
		Subject:     req.Subject,
		Body:        req.Body,
		HTMLBody:    req.HTMLBody,
		Attachments: req.Attachments,
	}

	result, err := h.emailService.SendEmail(userID, sendReq)
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
				"message": err.Error(),
			},
		})
		return
	}

	if !result.Success {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error": gin.H{
				"code":    "EMAIL_SEND_FAILED",
				"message": result.Error,
			},
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"message_id": result.MessageID,
		},
	})
}

// SyncEmails syncs emails from an account
// POST /api/emails/sync
func (h *EmailHandler) SyncEmails(c *gin.Context) {
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

	var req SyncRequest
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

	savedCount, err := h.emailService.SyncAndSaveEmails(userID, req.AccountID)
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
				"code":    "SYNC_FAILED",
				"message": err.Error(),
			},
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"synced_count": savedCount,
		},
	})
}


// ListAttachments lists all attachments for an email
// GET /api/emails/:id/attachments
func (h *EmailHandler) ListAttachments(c *gin.Context) {
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

	emailID, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error": gin.H{
				"code":    "VALIDATION_ERROR",
				"message": "Invalid email ID",
			},
		})
		return
	}

	attachments, err := h.emailService.ListAttachments(userID, uint(emailID))
	if err != nil {
		if err == services.ErrEmailNotFound {
			c.JSON(http.StatusNotFound, gin.H{
				"success": false,
				"error": gin.H{
					"code":    "NOT_FOUND",
					"message": "Email not found",
				},
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error": gin.H{
				"code":    "INTERNAL_ERROR",
				"message": "Failed to list attachments",
			},
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    attachments,
	})
}

// DownloadAttachment downloads an attachment
// GET /api/emails/:id/attachments/:filename
func (h *EmailHandler) DownloadAttachment(c *gin.Context) {
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

	emailID, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error": gin.H{
				"code":    "VALIDATION_ERROR",
				"message": "Invalid email ID",
			},
		})
		return
	}

	filename := c.Param("filename")
	if filename == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error": gin.H{
				"code":    "VALIDATION_ERROR",
				"message": "Filename is required",
			},
		})
		return
	}

	content, err := h.emailService.DownloadAttachment(userID, uint(emailID), filename)
	if err != nil {
		if err == services.ErrEmailNotFound {
			c.JSON(http.StatusNotFound, gin.H{
				"success": false,
				"error": gin.H{
					"code":    "NOT_FOUND",
					"message": "Email not found",
				},
			})
			return
		}
		if err == services.ErrAttachmentNotFound {
			c.JSON(http.StatusNotFound, gin.H{
				"success": false,
				"error": gin.H{
					"code":    "NOT_FOUND",
					"message": "Attachment not found",
				},
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error": gin.H{
				"code":    "INTERNAL_ERROR",
				"message": "Failed to download attachment",
			},
		})
		return
	}

	c.Header("Content-Disposition", "attachment; filename="+filename)
	c.Data(http.StatusOK, "application/octet-stream", content)
}

// UploadAttachment uploads an attachment for an email
// POST /api/emails/:id/attachments
func (h *EmailHandler) UploadAttachment(c *gin.Context) {
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

	emailID, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error": gin.H{
				"code":    "VALIDATION_ERROR",
				"message": "Invalid email ID",
			},
		})
		return
	}

	file, header, err := c.Request.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error": gin.H{
				"code":    "VALIDATION_ERROR",
				"message": "File is required",
			},
		})
		return
	}
	defer file.Close()

	content, err := io.ReadAll(file)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error": gin.H{
				"code":    "INTERNAL_ERROR",
				"message": "Failed to read file",
			},
		})
		return
	}

	info, err := h.emailService.UploadAttachment(userID, uint(emailID), header.Filename, content)
	if err != nil {
		if err == services.ErrEmailNotFound {
			c.JSON(http.StatusNotFound, gin.H{
				"success": false,
				"error": gin.H{
					"code":    "NOT_FOUND",
					"message": "Email not found",
				},
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error": gin.H{
				"code":    "INTERNAL_ERROR",
				"message": "Failed to upload attachment",
			},
		})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"success": true,
		"data":    info,
	})
}

// DeleteAttachment deletes an attachment
// DELETE /api/emails/:id/attachments/:filename
func (h *EmailHandler) DeleteAttachment(c *gin.Context) {
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

	emailID, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error": gin.H{
				"code":    "VALIDATION_ERROR",
				"message": "Invalid email ID",
			},
		})
		return
	}

	filename := c.Param("filename")
	if filename == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error": gin.H{
				"code":    "VALIDATION_ERROR",
				"message": "Filename is required",
			},
		})
		return
	}

	err = h.emailService.DeleteAttachment(userID, uint(emailID), filename)
	if err != nil {
		if err == services.ErrEmailNotFound {
			c.JSON(http.StatusNotFound, gin.H{
				"success": false,
				"error": gin.H{
					"code":    "NOT_FOUND",
					"message": "Email not found",
				},
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error": gin.H{
				"code":    "INTERNAL_ERROR",
				"message": "Failed to delete attachment",
			},
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Attachment deleted successfully",
	})
}
