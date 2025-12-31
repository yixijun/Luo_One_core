package services

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/luo-one/core/internal/database/models"
	"gorm.io/gorm"
)

// LogService handles logging operations
type LogService struct {
	db       *gorm.DB
	logLevel models.LogLevel
}

// NewLogService creates a new LogService instance
func NewLogService(db *gorm.DB) *LogService {
	return &LogService{
		db:       db,
		logLevel: models.LogLevelInfo, // Default log level
	}
}

// NewLogServiceWithLevel creates a new LogService instance with specified log level
func NewLogServiceWithLevel(db *gorm.DB, level string) *LogService {
	return &LogService{
		db:       db,
		logLevel: parseLogLevel(level),
	}
}

// parseLogLevel converts a string to LogLevel
func parseLogLevel(level string) models.LogLevel {
	switch strings.ToUpper(level) {
	case "DEBUG":
		return models.LogLevelDebug
	case "INFO":
		return models.LogLevelInfo
	case "WARN", "WARNING":
		return models.LogLevelWarn
	case "ERROR":
		return models.LogLevelError
	default:
		return models.LogLevelInfo
	}
}

// SetLogLevel sets the minimum log level
func (s *LogService) SetLogLevel(level string) {
	s.logLevel = parseLogLevel(level)
}

// GetLogLevel returns the current log level
func (s *LogService) GetLogLevel() models.LogLevel {
	return s.logLevel
}

// shouldLog checks if a log entry should be recorded based on log level
func (s *LogService) shouldLog(level models.LogLevel) bool {
	levelPriority := map[models.LogLevel]int{
		models.LogLevelDebug: 0,
		models.LogLevelInfo:  1,
		models.LogLevelWarn:  2,
		models.LogLevelError: 3,
	}

	return levelPriority[level] >= levelPriority[s.logLevel]
}

// LogEntry represents a log entry to be created
type LogEntry struct {
	UserID  uint
	Level   models.LogLevel
	Module  models.LogModule
	Action  string
	Message string
	Details interface{} // Will be serialized to JSON
}

// Log creates a new log entry
func (s *LogService) Log(entry LogEntry) error {
	// Check if this log level should be recorded
	if !s.shouldLog(entry.Level) {
		return nil
	}

	var detailsJSON string
	if entry.Details != nil {
		bytes, err := json.Marshal(entry.Details)
		if err != nil {
			detailsJSON = "{}"
		} else {
			detailsJSON = string(bytes)
		}
	}

	log := &models.Log{
		UserID:  entry.UserID,
		Level:   string(entry.Level),
		Module:  string(entry.Module),
		Action:  entry.Action,
		Message: entry.Message,
		Details: detailsJSON,
	}

	return s.db.Create(log).Error
}

// LogInfo creates an INFO level log entry
func (s *LogService) LogInfo(userID uint, module models.LogModule, action, message string, details interface{}) error {
	return s.Log(LogEntry{
		UserID:  userID,
		Level:   models.LogLevelInfo,
		Module:  module,
		Action:  action,
		Message: message,
		Details: details,
	})
}

// LogWarn creates a WARN level log entry
func (s *LogService) LogWarn(userID uint, module models.LogModule, action, message string, details interface{}) error {
	return s.Log(LogEntry{
		UserID:  userID,
		Level:   models.LogLevelWarn,
		Module:  module,
		Action:  action,
		Message: message,
		Details: details,
	})
}

// LogError creates an ERROR level log entry
func (s *LogService) LogError(userID uint, module models.LogModule, action, message string, details interface{}) error {
	return s.Log(LogEntry{
		UserID:  userID,
		Level:   models.LogLevelError,
		Module:  module,
		Action:  action,
		Message: message,
		Details: details,
	})
}

// LogDebug creates a DEBUG level log entry
func (s *LogService) LogDebug(userID uint, module models.LogModule, action, message string, details interface{}) error {
	return s.Log(LogEntry{
		UserID:  userID,
		Level:   models.LogLevelDebug,
		Module:  module,
		Action:  action,
		Message: message,
		Details: details,
	})
}

// AccountChangeDetails represents details for account configuration changes
type AccountChangeDetails struct {
	AccountID   uint   `json:"account_id"`
	AccountEmail string `json:"account_email"`
	Field       string `json:"field,omitempty"`
	OldValue    string `json:"old_value,omitempty"`
	NewValue    string `json:"new_value,omitempty"`
}

// LogAccountCreated logs an account creation event
func (s *LogService) LogAccountCreated(userID uint, accountID uint, email string) error {
	return s.LogInfo(userID, models.LogModuleAccount, "create", "Email account created", AccountChangeDetails{
		AccountID:    accountID,
		AccountEmail: email,
	})
}

// LogAccountUpdated logs an account update event
func (s *LogService) LogAccountUpdated(userID uint, accountID uint, email string) error {
	return s.LogInfo(userID, models.LogModuleAccount, "update", "Email account updated", AccountChangeDetails{
		AccountID:    accountID,
		AccountEmail: email,
	})
}

// LogAccountDeleted logs an account deletion event
func (s *LogService) LogAccountDeleted(userID uint, accountID uint, email string) error {
	return s.LogInfo(userID, models.LogModuleAccount, "delete", "Email account deleted", AccountChangeDetails{
		AccountID:    accountID,
		AccountEmail: email,
	})
}

// LogAccountStatusChanged logs an account status change event
func (s *LogService) LogAccountStatusChanged(userID uint, accountID uint, email string, enabled bool) error {
	status := "disabled"
	if enabled {
		status = "enabled"
	}
	return s.LogInfo(userID, models.LogModuleAccount, "status_change", "Email account "+status, AccountChangeDetails{
		AccountID:    accountID,
		AccountEmail: email,
		Field:        "enabled",
		NewValue:     status,
	})
}

// ===== API Request Logging (Requirements 7.1) =====

// APIRequestDetails represents details for API request logs
type APIRequestDetails struct {
	Method     string `json:"method"`
	Path       string `json:"path"`
	StatusCode int    `json:"status_code"`
	Duration   int64  `json:"duration_ms"`
	ClientIP   string `json:"client_ip"`
	UserAgent  string `json:"user_agent,omitempty"`
}

// LogAPIRequest logs an API request
func (s *LogService) LogAPIRequest(userID uint, method, path string, statusCode int, durationMs int64, clientIP, userAgent string) error {
	level := models.LogLevelInfo
	if statusCode >= 400 && statusCode < 500 {
		level = models.LogLevelWarn
	} else if statusCode >= 500 {
		level = models.LogLevelError
	}

	return s.Log(LogEntry{
		UserID:  userID,
		Level:   level,
		Module:  models.LogModuleAPI,
		Action:  "request",
		Message: method + " " + path,
		Details: APIRequestDetails{
			Method:     method,
			Path:       path,
			StatusCode: statusCode,
			Duration:   durationMs,
			ClientIP:   clientIP,
			UserAgent:  userAgent,
		},
	})
}

// ===== Email Operation Logging (Requirements 7.2) =====

// EmailOperationDetails represents details for email operation logs
type EmailOperationDetails struct {
	AccountID   uint   `json:"account_id"`
	EmailID     uint   `json:"email_id,omitempty"`
	MessageID   string `json:"message_id,omitempty"`
	Subject     string `json:"subject,omitempty"`
	From        string `json:"from,omitempty"`
	To          string `json:"to,omitempty"`
	Status      string `json:"status"`
	ErrorMsg    string `json:"error_msg,omitempty"`
	EmailCount  int    `json:"email_count,omitempty"`
}

// LogEmailFetch logs an email fetch operation
func (s *LogService) LogEmailFetch(userID uint, accountID uint, emailCount int, err error) error {
	details := EmailOperationDetails{
		AccountID:  accountID,
		EmailCount: emailCount,
		Status:     "success",
	}

	level := models.LogLevelInfo
	message := "Fetched emails successfully"

	if err != nil {
		level = models.LogLevelError
		details.Status = "failed"
		details.ErrorMsg = err.Error()
		message = "Failed to fetch emails"
	}

	return s.Log(LogEntry{
		UserID:  userID,
		Level:   level,
		Module:  models.LogModuleEmail,
		Action:  "fetch",
		Message: message,
		Details: details,
	})
}

// LogEmailReceived logs a received email
func (s *LogService) LogEmailReceived(userID uint, accountID uint, emailID uint, messageID, subject, from string) error {
	return s.LogInfo(userID, models.LogModuleEmail, "receive", "Email received", EmailOperationDetails{
		AccountID: accountID,
		EmailID:   emailID,
		MessageID: messageID,
		Subject:   subject,
		From:      from,
		Status:    "received",
	})
}

// LogEmailSend logs an email send operation
func (s *LogService) LogEmailSend(userID uint, accountID uint, to, subject string, err error) error {
	details := EmailOperationDetails{
		AccountID: accountID,
		Subject:   subject,
		To:        to,
		Status:    "sent",
	}

	level := models.LogLevelInfo
	message := "Email sent successfully"

	if err != nil {
		level = models.LogLevelError
		details.Status = "failed"
		details.ErrorMsg = err.Error()
		message = "Failed to send email"
	}

	return s.Log(LogEntry{
		UserID:  userID,
		Level:   level,
		Module:  models.LogModuleEmail,
		Action:  "send",
		Message: message,
		Details: details,
	})
}

// LogEmailDelete logs an email deletion
func (s *LogService) LogEmailDelete(userID uint, emailID uint, subject string) error {
	return s.LogInfo(userID, models.LogModuleEmail, "delete", "Email deleted", EmailOperationDetails{
		EmailID: emailID,
		Subject: subject,
		Status:  "deleted",
	})
}

// ===== Email Processing Logging (Requirements 7.3) =====

// ProcessingOperationDetails represents details for processing operation logs
type ProcessingOperationDetails struct {
	EmailID          uint   `json:"email_id"`
	ProcessedBy      string `json:"processed_by"` // "ai" or "local"
	VerificationCode string `json:"verification_code,omitempty"`
	IsAd             bool   `json:"is_ad"`
	Importance       string `json:"importance,omitempty"`
	HasSummary       bool   `json:"has_summary"`
	Status           string `json:"status"`
	ErrorMsg         string `json:"error_msg,omitempty"`
	DurationMs       int64  `json:"duration_ms,omitempty"`
}

// LogEmailProcessing logs an email processing operation
func (s *LogService) LogEmailProcessing(userID uint, emailID uint, processedBy string, result *ProcessingResult, durationMs int64, err error) error {
	details := ProcessingOperationDetails{
		EmailID:    emailID,
		ProcessedBy: processedBy,
		Status:     "success",
		DurationMs: durationMs,
	}

	level := models.LogLevelInfo
	message := "Email processed successfully"

	if err != nil {
		level = models.LogLevelError
		details.Status = "failed"
		details.ErrorMsg = err.Error()
		message = "Failed to process email"
	} else if result != nil {
		details.VerificationCode = result.VerificationCode
		details.IsAd = result.IsAd
		details.Importance = result.Importance
		details.HasSummary = result.Summary != ""
	}

	return s.Log(LogEntry{
		UserID:  userID,
		Level:   level,
		Module:  models.LogModuleProcess,
		Action:  "process",
		Message: message,
		Details: details,
	})
}

// ProcessingResult represents the result of email processing (for logging)
type ProcessingResult struct {
	VerificationCode string
	IsAd             bool
	Summary          string
	Importance       string
}

// ===== Authentication Logging (Requirements 7.4) =====

// AuthOperationDetails represents details for authentication operation logs
type AuthOperationDetails struct {
	Username  string `json:"username,omitempty"`
	ClientIP  string `json:"client_ip,omitempty"`
	Status    string `json:"status"`
	ErrorMsg  string `json:"error_msg,omitempty"`
	TokenType string `json:"token_type,omitempty"`
}

// LogLogin logs a login attempt
func (s *LogService) LogLogin(userID uint, username, clientIP string, success bool, err error) error {
	details := AuthOperationDetails{
		Username: username,
		ClientIP: clientIP,
		Status:   "success",
	}

	level := models.LogLevelInfo
	message := "User logged in successfully"

	if !success {
		level = models.LogLevelWarn
		details.Status = "failed"
		message = "Login attempt failed"
		if err != nil {
			details.ErrorMsg = err.Error()
		}
	}

	return s.Log(LogEntry{
		UserID:  userID,
		Level:   level,
		Module:  models.LogModuleAuth,
		Action:  "login",
		Message: message,
		Details: details,
	})
}

// LogLogout logs a logout event
func (s *LogService) LogLogout(userID uint) error {
	return s.LogInfo(userID, models.LogModuleAuth, "logout", "User logged out", nil)
}

// LogTokenGenerated logs a token generation event
func (s *LogService) LogTokenGenerated(userID uint, tokenType string) error {
	return s.LogInfo(userID, models.LogModuleAuth, "token_generated", "Token generated", AuthOperationDetails{
		TokenType: tokenType,
		Status:    "success",
	})
}

// LogTokenValidation logs a token validation attempt
func (s *LogService) LogTokenValidation(userID uint, success bool, err error) error {
	details := AuthOperationDetails{
		Status: "valid",
	}

	level := models.LogLevelDebug
	message := "Token validated successfully"

	if !success {
		level = models.LogLevelWarn
		details.Status = "invalid"
		message = "Token validation failed"
		if err != nil {
			details.ErrorMsg = err.Error()
		}
	}

	return s.Log(LogEntry{
		UserID:  userID,
		Level:   level,
		Module:  models.LogModuleAuth,
		Action:  "token_validation",
		Message: message,
		Details: details,
	})
}

// LogAPIKeyValidation logs an API key validation attempt
func (s *LogService) LogAPIKeyValidation(success bool, clientIP string, err error) error {
	details := AuthOperationDetails{
		ClientIP: clientIP,
		Status:   "valid",
	}

	level := models.LogLevelDebug
	message := "API key validated successfully"

	if !success {
		level = models.LogLevelWarn
		details.Status = "invalid"
		message = "API key validation failed"
		if err != nil {
			details.ErrorMsg = err.Error()
		}
	}

	return s.Log(LogEntry{
		UserID:  0, // No user ID for API key validation
		Level:   level,
		Module:  models.LogModuleAuth,
		Action:  "api_key_validation",
		Message: message,
		Details: details,
	})
}

// LogAPIKeyReset logs an API key reset event
func (s *LogService) LogAPIKeyReset(userID uint) error {
	return s.LogInfo(userID, models.LogModuleAuth, "api_key_reset", "API key reset", nil)
}

// LogPasswordChange logs a password change event
func (s *LogService) LogPasswordChange(userID uint, success bool, err error) error {
	details := AuthOperationDetails{
		Status: "success",
	}

	level := models.LogLevelInfo
	message := "Password changed successfully"

	if !success {
		level = models.LogLevelWarn
		details.Status = "failed"
		message = "Password change failed"
		if err != nil {
			details.ErrorMsg = err.Error()
		}
	}

	return s.Log(LogEntry{
		UserID:  userID,
		Level:   level,
		Module:  models.LogModuleAuth,
		Action:  "password_change",
		Message: message,
		Details: details,
	})
}

// ===== Log Query Methods =====

// LogQuery represents query parameters for log retrieval
type LogQuery struct {
	UserID    uint
	Level     string
	Module    string
	Action    string
	StartTime *time.Time
	EndTime   *time.Time
	Page      int
	Limit     int
}

// LogQueryResult represents the result of a log query
type LogQueryResult struct {
	Total int64
	Logs  []models.Log
}

// QueryLogs retrieves logs based on query parameters
func (s *LogService) QueryLogs(query LogQuery) (*LogQueryResult, error) {
	db := s.db.Model(&models.Log{})

	if query.UserID > 0 {
		db = db.Where("user_id = ?", query.UserID)
	}
	if query.Level != "" {
		db = db.Where("level = ?", query.Level)
	}
	if query.Module != "" {
		db = db.Where("module = ?", query.Module)
	}
	if query.Action != "" {
		db = db.Where("action = ?", query.Action)
	}
	if query.StartTime != nil {
		db = db.Where("created_at >= ?", query.StartTime)
	}
	if query.EndTime != nil {
		db = db.Where("created_at <= ?", query.EndTime)
	}

	var total int64
	if err := db.Count(&total).Error; err != nil {
		return nil, err
	}

	if query.Page <= 0 {
		query.Page = 1
	}
	if query.Limit <= 0 {
		query.Limit = 50
	}

	offset := (query.Page - 1) * query.Limit

	var logs []models.Log
	if err := db.Order("created_at DESC").Offset(offset).Limit(query.Limit).Find(&logs).Error; err != nil {
		return nil, err
	}

	return &LogQueryResult{
		Total: total,
		Logs:  logs,
	}, nil
}

// GetLogByID retrieves a single log entry by ID
func (s *LogService) GetLogByID(id uint) (*models.Log, error) {
	var log models.Log
	if err := s.db.First(&log, id).Error; err != nil {
		return nil, err
	}
	return &log, nil
}

// GetRecentLogs retrieves the most recent logs
func (s *LogService) GetRecentLogs(limit int) ([]models.Log, error) {
	if limit <= 0 {
		limit = 100
	}

	var logs []models.Log
	if err := s.db.Order("created_at DESC").Limit(limit).Find(&logs).Error; err != nil {
		return nil, err
	}
	return logs, nil
}

// GetLogsByModule retrieves logs for a specific module
func (s *LogService) GetLogsByModule(module models.LogModule, limit int) ([]models.Log, error) {
	if limit <= 0 {
		limit = 100
	}

	var logs []models.Log
	if err := s.db.Where("module = ?", string(module)).Order("created_at DESC").Limit(limit).Find(&logs).Error; err != nil {
		return nil, err
	}
	return logs, nil
}

// GetLogsByUserID retrieves logs for a specific user
func (s *LogService) GetLogsByUserID(userID uint, limit int) ([]models.Log, error) {
	if limit <= 0 {
		limit = 100
	}

	var logs []models.Log
	if err := s.db.Where("user_id = ?", userID).Order("created_at DESC").Limit(limit).Find(&logs).Error; err != nil {
		return nil, err
	}
	return logs, nil
}
