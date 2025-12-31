package services

import (
	"os"
	"testing"
	"time"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
	"github.com/luo-one/core/internal/database/models"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Feature: luo-one-email-manager, Property 13: 操作日志完整性
// For any API request, email operation, processing operation, or authentication operation,
// after execution there should be a corresponding record in the log table,
// and the record should contain the correct operation type, user ID, and timestamp.
// Validates: Requirements 2.5, 7.1, 7.2, 7.3, 7.4, 7.5

func setupLogTestDB(t *testing.T) (*gorm.DB, func()) {
	tmpFile, err := os.CreateTemp("", "log_test_*.db")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	tmpFile.Close()

	db, err := gorm.Open(sqlite.Open(tmpFile.Name()), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		os.Remove(tmpFile.Name())
		t.Fatalf("Failed to open database: %v", err)
	}

	err = db.AutoMigrate(&models.Log{})
	if err != nil {
		os.Remove(tmpFile.Name())
		t.Fatalf("Failed to migrate: %v", err)
	}

	cleanup := func() {
		sqlDB, _ := db.DB()
		if sqlDB != nil {
			sqlDB.Close()
		}
		os.Remove(tmpFile.Name())
	}

	return db, cleanup
}

// TestProperty_LogCompleteness_APIRequest tests that API requests are logged correctly
func TestProperty_LogCompleteness_APIRequest(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 20
	properties := gopter.NewProperties(parameters)

	// Property 13.1: API request logging creates complete log entry
	properties.Property("api_request_creates_complete_log_entry", prop.ForAll(
		func(userID uint, statusCode int) bool {
			db, cleanup := setupLogTestDB(t)
			defer cleanup()

			service := NewLogService(db)
			beforeTime := time.Now().Add(-time.Second)

			method := "GET"
			path := "/api/test"
			durationMs := int64(100)
			clientIP := "127.0.0.1"
			userAgent := "TestAgent"

			err := service.LogAPIRequest(userID, method, path, statusCode, durationMs, clientIP, userAgent)
			if err != nil {
				return false
			}

			afterTime := time.Now().Add(time.Second)

			// Query the log
			var log models.Log
			if err := db.Where("module = ? AND action = ?", "api", "request").First(&log).Error; err != nil {
				return false
			}

			// Verify log entry completeness
			return log.UserID == userID &&
				log.Module == "api" &&
				log.Action == "request" &&
				log.Message == method+" "+path &&
				log.CreatedAt.After(beforeTime) &&
				log.CreatedAt.Before(afterTime)
		},
		gen.UIntRange(1, 1000),
		gen.IntRange(200, 599),
	))

	properties.TestingRun(t)
}


// TestProperty_LogCompleteness_EmailOperations tests that email operations are logged correctly
func TestProperty_LogCompleteness_EmailOperations(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 20
	properties := gopter.NewProperties(parameters)

	// Property 13.2: Email fetch logging creates complete log entry
	properties.Property("email_fetch_creates_complete_log_entry", prop.ForAll(
		func(userID uint, accountID uint, emailCount int) bool {
			db, cleanup := setupLogTestDB(t)
			defer cleanup()

			service := NewLogService(db)
			beforeTime := time.Now().Add(-time.Second)

			err := service.LogEmailFetch(userID, accountID, emailCount, nil)
			if err != nil {
				return false
			}

			afterTime := time.Now().Add(time.Second)

			var log models.Log
			if err := db.Where("module = ? AND action = ?", "email", "fetch").First(&log).Error; err != nil {
				return false
			}

			return log.UserID == userID &&
				log.Module == "email" &&
				log.Action == "fetch" &&
				log.Level == "INFO" &&
				log.CreatedAt.After(beforeTime) &&
				log.CreatedAt.Before(afterTime)
		},
		gen.UIntRange(1, 1000),
		gen.UIntRange(1, 100),
		gen.IntRange(0, 100),
	))

	// Property 13.3: Email send logging creates complete log entry
	properties.Property("email_send_creates_complete_log_entry", prop.ForAll(
		func(userID uint, accountID uint) bool {
			db, cleanup := setupLogTestDB(t)
			defer cleanup()

			service := NewLogService(db)
			beforeTime := time.Now().Add(-time.Second)

			to := "recipient@example.com"
			subject := "Test Subject"

			err := service.LogEmailSend(userID, accountID, to, subject, nil)
			if err != nil {
				return false
			}

			afterTime := time.Now().Add(time.Second)

			var log models.Log
			if err := db.Where("module = ? AND action = ?", "email", "send").First(&log).Error; err != nil {
				return false
			}

			return log.UserID == userID &&
				log.Module == "email" &&
				log.Action == "send" &&
				log.Level == "INFO" &&
				log.CreatedAt.After(beforeTime) &&
				log.CreatedAt.Before(afterTime)
		},
		gen.UIntRange(1, 1000),
		gen.UIntRange(1, 100),
	))

	// Property 13.4: Email receive logging creates complete log entry
	properties.Property("email_receive_creates_complete_log_entry", prop.ForAll(
		func(userID uint, accountID uint, emailID uint) bool {
			db, cleanup := setupLogTestDB(t)
			defer cleanup()

			service := NewLogService(db)
			beforeTime := time.Now().Add(-time.Second)

			messageID := "test-message-id"
			subject := "Test Subject"
			from := "sender@example.com"

			err := service.LogEmailReceived(userID, accountID, emailID, messageID, subject, from)
			if err != nil {
				return false
			}

			afterTime := time.Now().Add(time.Second)

			var log models.Log
			if err := db.Where("module = ? AND action = ?", "email", "receive").First(&log).Error; err != nil {
				return false
			}

			return log.UserID == userID &&
				log.Module == "email" &&
				log.Action == "receive" &&
				log.Level == "INFO" &&
				log.CreatedAt.After(beforeTime) &&
				log.CreatedAt.Before(afterTime)
		},
		gen.UIntRange(1, 1000),
		gen.UIntRange(1, 100),
		gen.UIntRange(1, 1000),
	))

	properties.TestingRun(t)
}

// TestProperty_LogCompleteness_ProcessingOperations tests that processing operations are logged correctly
func TestProperty_LogCompleteness_ProcessingOperations(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 20
	properties := gopter.NewProperties(parameters)

	// Property 13.5: Email processing logging creates complete log entry
	properties.Property("email_processing_creates_complete_log_entry", prop.ForAll(
		func(userID uint, emailID uint, isAI bool) bool {
			db, cleanup := setupLogTestDB(t)
			defer cleanup()

			service := NewLogService(db)
			beforeTime := time.Now().Add(-time.Second)

			processedBy := "local"
			if isAI {
				processedBy = "ai"
			}

			result := &ProcessingResult{
				VerificationCode: "123456",
				IsAd:             false,
				Summary:          "Test summary",
				Importance:       "medium",
			}

			err := service.LogEmailProcessing(userID, emailID, processedBy, result, 100, nil)
			if err != nil {
				return false
			}

			afterTime := time.Now().Add(time.Second)

			var log models.Log
			if err := db.Where("module = ? AND action = ?", "process", "process").First(&log).Error; err != nil {
				return false
			}

			return log.UserID == userID &&
				log.Module == "process" &&
				log.Action == "process" &&
				log.Level == "INFO" &&
				log.CreatedAt.After(beforeTime) &&
				log.CreatedAt.Before(afterTime)
		},
		gen.UIntRange(1, 1000),
		gen.UIntRange(1, 1000),
		gen.Bool(),
	))

	properties.TestingRun(t)
}


// TestProperty_LogCompleteness_AuthOperations tests that authentication operations are logged correctly
func TestProperty_LogCompleteness_AuthOperations(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 20
	properties := gopter.NewProperties(parameters)

	// Property 13.6: Login logging creates complete log entry
	properties.Property("login_creates_complete_log_entry", prop.ForAll(
		func(userID uint, success bool) bool {
			db, cleanup := setupLogTestDB(t)
			defer cleanup()

			service := NewLogService(db)
			beforeTime := time.Now().Add(-time.Second)

			username := "testuser"
			clientIP := "127.0.0.1"

			err := service.LogLogin(userID, username, clientIP, success, nil)
			if err != nil {
				return false
			}

			afterTime := time.Now().Add(time.Second)

			var log models.Log
			if err := db.Where("module = ? AND action = ?", "auth", "login").First(&log).Error; err != nil {
				return false
			}

			expectedLevel := "INFO"
			if !success {
				expectedLevel = "WARN"
			}

			return log.UserID == userID &&
				log.Module == "auth" &&
				log.Action == "login" &&
				log.Level == expectedLevel &&
				log.CreatedAt.After(beforeTime) &&
				log.CreatedAt.Before(afterTime)
		},
		gen.UIntRange(1, 1000),
		gen.Bool(),
	))

	// Property 13.7: Password change logging creates complete log entry
	properties.Property("password_change_creates_complete_log_entry", prop.ForAll(
		func(userID uint, success bool) bool {
			db, cleanup := setupLogTestDB(t)
			defer cleanup()

			service := NewLogService(db)
			beforeTime := time.Now().Add(-time.Second)

			err := service.LogPasswordChange(userID, success, nil)
			if err != nil {
				return false
			}

			afterTime := time.Now().Add(time.Second)

			var log models.Log
			if err := db.Where("module = ? AND action = ?", "auth", "password_change").First(&log).Error; err != nil {
				return false
			}

			expectedLevel := "INFO"
			if !success {
				expectedLevel = "WARN"
			}

			return log.UserID == userID &&
				log.Module == "auth" &&
				log.Action == "password_change" &&
				log.Level == expectedLevel &&
				log.CreatedAt.After(beforeTime) &&
				log.CreatedAt.Before(afterTime)
		},
		gen.UIntRange(1, 1000),
		gen.Bool(),
	))

	// Property 13.8: API key reset logging creates complete log entry
	properties.Property("api_key_reset_creates_complete_log_entry", prop.ForAll(
		func(userID uint) bool {
			db, cleanup := setupLogTestDB(t)
			defer cleanup()

			service := NewLogService(db)
			beforeTime := time.Now().Add(-time.Second)

			err := service.LogAPIKeyReset(userID)
			if err != nil {
				return false
			}

			afterTime := time.Now().Add(time.Second)

			var log models.Log
			if err := db.Where("module = ? AND action = ?", "auth", "api_key_reset").First(&log).Error; err != nil {
				return false
			}

			return log.UserID == userID &&
				log.Module == "auth" &&
				log.Action == "api_key_reset" &&
				log.Level == "INFO" &&
				log.CreatedAt.After(beforeTime) &&
				log.CreatedAt.Before(afterTime)
		},
		gen.UIntRange(1, 1000),
	))

	properties.TestingRun(t)
}

// TestProperty_LogCompleteness_AccountConfigChanges tests that account config changes are logged (Requirement 2.5)
func TestProperty_LogCompleteness_AccountConfigChanges(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 20
	properties := gopter.NewProperties(parameters)

	// Property 13.9: Account status change logging creates complete log entry
	properties.Property("account_status_change_creates_complete_log_entry", prop.ForAll(
		func(userID uint, accountID uint, enabled bool) bool {
			db, cleanup := setupLogTestDB(t)
			defer cleanup()

			service := NewLogService(db)
			beforeTime := time.Now().Add(-time.Second)

			email := "test@example.com"

			err := service.LogAccountStatusChanged(userID, accountID, email, enabled)
			if err != nil {
				return false
			}

			afterTime := time.Now().Add(time.Second)

			var log models.Log
			if err := db.Where("module = ? AND action = ?", "account", "status_change").First(&log).Error; err != nil {
				return false
			}

			return log.UserID == userID &&
				log.Module == "account" &&
				log.Action == "status_change" &&
				log.Level == "INFO" &&
				log.CreatedAt.After(beforeTime) &&
				log.CreatedAt.Before(afterTime)
		},
		gen.UIntRange(1, 1000),
		gen.UIntRange(1, 100),
		gen.Bool(),
	))

	// Property 13.10: Account creation logging creates complete log entry
	properties.Property("account_creation_creates_complete_log_entry", prop.ForAll(
		func(userID uint, accountID uint) bool {
			db, cleanup := setupLogTestDB(t)
			defer cleanup()

			service := NewLogService(db)
			beforeTime := time.Now().Add(-time.Second)

			email := "test@example.com"

			err := service.LogAccountCreated(userID, accountID, email)
			if err != nil {
				return false
			}

			afterTime := time.Now().Add(time.Second)

			var log models.Log
			if err := db.Where("module = ? AND action = ?", "account", "create").First(&log).Error; err != nil {
				return false
			}

			return log.UserID == userID &&
				log.Module == "account" &&
				log.Action == "create" &&
				log.Level == "INFO" &&
				log.CreatedAt.After(beforeTime) &&
				log.CreatedAt.Before(afterTime)
		},
		gen.UIntRange(1, 1000),
		gen.UIntRange(1, 100),
	))

	properties.TestingRun(t)
}

// TestProperty_LogLevelFiltering tests that log level filtering works correctly
func TestProperty_LogLevelFiltering(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 20
	properties := gopter.NewProperties(parameters)

	// Property 13.11: Log level filtering respects configured level
	properties.Property("log_level_filtering_respects_configured_level", prop.ForAll(
		func(userID uint) bool {
			db, cleanup := setupLogTestDB(t)
			defer cleanup()

			// Create service with ERROR level - should only log ERROR
			service := NewLogServiceWithLevel(db, "ERROR")

			// Try to log at different levels
			service.LogDebug(userID, models.LogModuleAPI, "test", "debug message", nil)
			service.LogInfo(userID, models.LogModuleAPI, "test", "info message", nil)
			service.LogWarn(userID, models.LogModuleAPI, "test", "warn message", nil)
			service.LogError(userID, models.LogModuleAPI, "test", "error message", nil)

			// Only ERROR should be logged
			var count int64
			db.Model(&models.Log{}).Count(&count)

			return count == 1
		},
		gen.UIntRange(1, 1000),
	))

	// Property 13.12: INFO level logs INFO, WARN, and ERROR
	properties.Property("info_level_logs_info_warn_error", prop.ForAll(
		func(userID uint) bool {
			db, cleanup := setupLogTestDB(t)
			defer cleanup()

			service := NewLogServiceWithLevel(db, "INFO")

			service.LogDebug(userID, models.LogModuleAPI, "test", "debug message", nil)
			service.LogInfo(userID, models.LogModuleAPI, "test", "info message", nil)
			service.LogWarn(userID, models.LogModuleAPI, "test", "warn message", nil)
			service.LogError(userID, models.LogModuleAPI, "test", "error message", nil)

			// INFO, WARN, ERROR should be logged (3 entries)
			var count int64
			db.Model(&models.Log{}).Count(&count)

			return count == 3
		},
		gen.UIntRange(1, 1000),
	))

	properties.TestingRun(t)
}
