package services

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
	"github.com/luo-one/core/internal/database/models"
	"github.com/luo-one/core/internal/user"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// setupEmailTestDB creates a test database for email service tests
func setupEmailTestDB(t *testing.T) (*gorm.DB, func()) {
	tempDir, err := os.MkdirTemp("", "email_service_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	dbPath := filepath.Join(tempDir, "test.db")
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		os.RemoveAll(tempDir)
		t.Fatalf("Failed to open database: %v", err)
	}

	// Auto migrate
	db.AutoMigrate(&models.User{}, &models.EmailAccount{}, &models.Email{}, &models.ProcessedResult{}, &models.Log{})

	cleanup := func() {
		sqlDB, _ := db.DB()
		if sqlDB != nil {
			sqlDB.Close()
		}
		os.RemoveAll(tempDir)
	}

	return db, cleanup
}

// Feature: luo-one-email-manager, Property 6: 附件上传下载一致性（Round-trip）
// For any attachment file, uploading and then downloading should return the exact same content.
// Validates: Requirements 3.5

func TestProperty_AttachmentUploadDownloadConsistency(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 20
	properties := gopter.NewProperties(parameters)

	properties.Property("attachment_upload_download_roundtrip", prop.ForAll(
		func(userID uint, emailID uint, filename string, content []byte) bool {
			// Skip invalid inputs
			if userID == 0 || emailID == 0 || filename == "" || len(content) == 0 {
				return true
			}

			// Create a fresh temp directory for each test
			tempDir, err := os.MkdirTemp("", "attachment_test_*")
			if err != nil {
				return false
			}
			defer os.RemoveAll(tempDir)

			// Create user manager and storage
			manager := user.NewManager(tempDir)
			storage := user.NewStorage(manager)

			// Create user directories
			if err := manager.CreateUserDirectories(userID); err != nil {
				return false
			}

			// Save attachment
			_, err = storage.SaveAttachment(userID, emailID, filename, content)
			if err != nil {
				return false
			}

			// Retrieve attachment
			retrieved, err := storage.GetAttachment(userID, emailID, filename)
			if err != nil {
				return false
			}

			// Verify content matches exactly
			return bytes.Equal(content, retrieved)
		},
		gen.UIntRange(1, 1000),
		gen.UIntRange(1, 1000),
		genSafeFilename(),
		gen.SliceOf(gen.UInt8()),
	))

	properties.TestingRun(t)
}


// Property 6.2: Multiple attachments maintain individual integrity
func TestProperty_MultipleAttachmentsIntegrity(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 20
	properties := gopter.NewProperties(parameters)

	properties.Property("multiple_attachments_maintain_integrity", prop.ForAll(
		func(userID uint, emailID uint, numAttachments int) bool {
			// Skip invalid inputs
			if userID == 0 || emailID == 0 || numAttachments < 1 || numAttachments > 10 {
				return true
			}

			// Create a fresh temp directory for each test
			tempDir, err := os.MkdirTemp("", "multi_attachment_test_*")
			if err != nil {
				return false
			}
			defer os.RemoveAll(tempDir)

			// Create user manager and storage
			manager := user.NewManager(tempDir)
			storage := user.NewStorage(manager)

			// Create user directories
			if err := manager.CreateUserDirectories(userID); err != nil {
				return false
			}

			// Create and save multiple attachments
			attachments := make(map[string][]byte)
			for i := 0; i < numAttachments; i++ {
				filename := generateTestFilename(i)
				content := generateTestContent(i, userID, emailID)
				attachments[filename] = content

				_, err := storage.SaveAttachment(userID, emailID, filename, content)
				if err != nil {
					return false
				}
			}

			// Verify each attachment
			for filename, expectedContent := range attachments {
				retrieved, err := storage.GetAttachment(userID, emailID, filename)
				if err != nil {
					return false
				}
				if !bytes.Equal(expectedContent, retrieved) {
					return false
				}
			}

			// Verify list attachments returns correct count
			list, err := storage.ListAttachments(userID, emailID)
			if err != nil {
				return false
			}
			if len(list) != numAttachments {
				return false
			}

			return true
		},
		gen.UIntRange(1, 1000),
		gen.UIntRange(1, 1000),
		gen.IntRange(1, 10),
	))

	properties.TestingRun(t)
}

// Property 6.3: Attachment deletion removes only the specified file
func TestProperty_AttachmentDeletionIsolation(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 20
	properties := gopter.NewProperties(parameters)

	properties.Property("attachment_deletion_isolation", prop.ForAll(
		func(userID uint, emailID uint) bool {
			// Skip invalid inputs
			if userID == 0 || emailID == 0 {
				return true
			}

			// Create a fresh temp directory for each test
			tempDir, err := os.MkdirTemp("", "delete_attachment_test_*")
			if err != nil {
				return false
			}
			defer os.RemoveAll(tempDir)

			// Create user manager and storage
			manager := user.NewManager(tempDir)
			storage := user.NewStorage(manager)

			// Create user directories
			if err := manager.CreateUserDirectories(userID); err != nil {
				return false
			}

			// Create two attachments
			file1 := "file1.txt"
			content1 := []byte("content of file 1")
			file2 := "file2.txt"
			content2 := []byte("content of file 2")

			storage.SaveAttachment(userID, emailID, file1, content1)
			storage.SaveAttachment(userID, emailID, file2, content2)

			// Delete first attachment
			if err := storage.DeleteAttachment(userID, emailID, file1); err != nil {
				return false
			}

			// First attachment should not exist
			_, err = storage.GetAttachment(userID, emailID, file1)
			if err == nil {
				return false // Should have been deleted
			}

			// Second attachment should still exist and be intact
			retrieved, err := storage.GetAttachment(userID, emailID, file2)
			if err != nil {
				return false
			}
			if !bytes.Equal(content2, retrieved) {
				return false
			}

			return true
		},
		gen.UIntRange(1, 1000),
		gen.UIntRange(1, 1000),
	))

	properties.TestingRun(t)
}

// genSafeFilename generates safe filenames for testing
func genSafeFilename() gopter.Gen {
	return gen.AlphaString().Map(func(s string) string {
		if len(s) == 0 {
			return "file.txt"
		}
		if len(s) > 50 {
			s = s[:50]
		}
		return s + ".txt"
	})
}

// generateTestFilename generates a test filename
func generateTestFilename(index int) string {
	return "attachment_" + string(rune('a'+index)) + ".txt"
}

// generateTestContent generates test content based on parameters
func generateTestContent(index int, userID, emailID uint) []byte {
	content := make([]byte, 100+index*10)
	for i := range content {
		content[i] = byte((int(userID) + int(emailID) + index + i) % 256)
	}
	return content
}


// Feature: luo-one-email-manager, Property 2: 文件存储位置正确性
// For any email, raw emails should be stored in raw_emails/{account_id}/ directory,
// and processed results should be stored in processed_emails/{account_id}/ directory.
// Validates: Requirements 1.2, 1.3, 3.2, 4.7

func TestProperty_FileStorageLocationCorrectness(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 20
	properties := gopter.NewProperties(parameters)

	properties.Property("raw_email_stored_in_correct_location", prop.ForAll(
		func(userID uint, accountID uint, messageID string) bool {
			// Skip invalid inputs
			if userID == 0 || accountID == 0 || messageID == "" {
				return true
			}

			// Create a fresh temp directory for each test
			tempDir, err := os.MkdirTemp("", "storage_location_test_*")
			if err != nil {
				return false
			}
			defer os.RemoveAll(tempDir)

			// Create user manager and storage
			manager := user.NewManager(tempDir)
			storage := user.NewStorage(manager)

			// Create user and account directories
			if err := manager.CreateUserDirectories(userID); err != nil {
				return false
			}
			if err := manager.CreateAccountDirectories(userID, accountID); err != nil {
				return false
			}

			// Save raw email
			content := []byte("From: test@example.com\r\nSubject: Test\r\n\r\nTest body")
			filePath, err := storage.SaveRawEmail(userID, accountID, messageID, content)
			if err != nil {
				return false
			}

			// Verify file exists
			if _, err := os.Stat(filePath); os.IsNotExist(err) {
				return false
			}

			// Verify file is in correct directory structure
			expectedDir, _ := manager.GetRawEmailsAccountDir(userID, accountID)
			absFilePath, _ := filepath.Abs(filePath)
			absExpectedDir, _ := filepath.Abs(expectedDir)

			// File should be under raw_emails/{account_id}/
			if !hasPathPrefix(absFilePath, absExpectedDir) {
				return false
			}

			// Verify the path contains "raw_emails" and account ID
			if !containsPathSegment(filePath, "raw_emails") {
				return false
			}

			return true
		},
		gen.UIntRange(1, 1000),
		gen.UIntRange(1, 1000),
		genMessageID(),
	))

	properties.TestingRun(t)
}

func TestProperty_ProcessedResultStorageLocation(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 20
	properties := gopter.NewProperties(parameters)

	properties.Property("processed_result_stored_in_correct_location", prop.ForAll(
		func(userID uint, accountID uint, messageID string) bool {
			// Skip invalid inputs
			if userID == 0 || accountID == 0 || messageID == "" {
				return true
			}

			// Create a fresh temp directory for each test
			tempDir, err := os.MkdirTemp("", "processed_location_test_*")
			if err != nil {
				return false
			}
			defer os.RemoveAll(tempDir)

			// Create user manager and storage
			manager := user.NewManager(tempDir)
			storage := user.NewStorage(manager)

			// Create user and account directories
			if err := manager.CreateUserDirectories(userID); err != nil {
				return false
			}
			if err := manager.CreateAccountDirectories(userID, accountID); err != nil {
				return false
			}

			// Save processed result
			result := map[string]interface{}{
				"verification_code": "123456",
				"is_ad":             false,
				"summary":           "Test summary",
				"importance":        "medium",
			}
			filePath, err := storage.SaveProcessedResult(userID, accountID, messageID, result)
			if err != nil {
				return false
			}

			// Verify file exists
			if _, err := os.Stat(filePath); os.IsNotExist(err) {
				return false
			}

			// Verify file is in correct directory structure
			expectedDir, _ := manager.GetProcessedEmailsAccountDir(userID, accountID)
			absFilePath, _ := filepath.Abs(filePath)
			absExpectedDir, _ := filepath.Abs(expectedDir)

			// File should be under processed_emails/{account_id}/
			if !hasPathPrefix(absFilePath, absExpectedDir) {
				return false
			}

			// Verify the path contains "processed_emails" and account ID
			if !containsPathSegment(filePath, "processed_emails") {
				return false
			}

			return true
		},
		gen.UIntRange(1, 1000),
		gen.UIntRange(1, 1000),
		genMessageID(),
	))

	properties.TestingRun(t)
}

func TestProperty_AttachmentStorageLocation(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 20
	properties := gopter.NewProperties(parameters)

	properties.Property("attachment_stored_in_correct_location", prop.ForAll(
		func(userID uint, emailID uint, filename string) bool {
			// Skip invalid inputs
			if userID == 0 || emailID == 0 || filename == "" {
				return true
			}

			// Create a fresh temp directory for each test
			tempDir, err := os.MkdirTemp("", "attachment_location_test_*")
			if err != nil {
				return false
			}
			defer os.RemoveAll(tempDir)

			// Create user manager and storage
			manager := user.NewManager(tempDir)
			storage := user.NewStorage(manager)

			// Create user directories
			if err := manager.CreateUserDirectories(userID); err != nil {
				return false
			}

			// Save attachment
			content := []byte("attachment content")
			filePath, err := storage.SaveAttachment(userID, emailID, filename, content)
			if err != nil {
				return false
			}

			// Verify file exists
			if _, err := os.Stat(filePath); os.IsNotExist(err) {
				return false
			}

			// Verify file is in correct directory structure
			expectedDir, _ := manager.GetEmailAttachmentsDir(userID, emailID)
			absFilePath, _ := filepath.Abs(filePath)
			absExpectedDir, _ := filepath.Abs(expectedDir)

			// File should be under attachments/{email_id}/
			if !hasPathPrefix(absFilePath, absExpectedDir) {
				return false
			}

			// Verify the path contains "attachments"
			if !containsPathSegment(filePath, "attachments") {
				return false
			}

			return true
		},
		gen.UIntRange(1, 1000),
		gen.UIntRange(1, 1000),
		genSafeFilename(),
	))

	properties.TestingRun(t)
}

// genMessageID generates message IDs for testing
func genMessageID() gopter.Gen {
	return gen.AlphaString().Map(func(s string) string {
		if len(s) == 0 {
			return "msg_001"
		}
		if len(s) > 50 {
			s = s[:50]
		}
		return "msg_" + s
	})
}

// containsPathSegment checks if a path contains a specific segment
func containsPathSegment(path, segment string) bool {
	parts := filepath.SplitList(path)
	if len(parts) == 0 {
		// Try splitting by separator
		cleanPath := filepath.Clean(path)
		for cleanPath != "" && cleanPath != "." && cleanPath != string(filepath.Separator) {
			dir, file := filepath.Split(cleanPath)
			if file == segment {
				return true
			}
			cleanPath = filepath.Clean(dir)
		}
	}
	for _, part := range parts {
		if part == segment {
			return true
		}
	}
	// Also check using string contains as fallback
	return filepath.Base(filepath.Dir(filepath.Dir(path))) == segment ||
		filepath.Base(filepath.Dir(path)) == segment ||
		bytes.Contains([]byte(path), []byte(segment))
}

// hasPathPrefixEmail checks if path has the given prefix (reused from manager tests)
func hasPathPrefixEmail(path, prefix string) bool {
	if len(path) < len(prefix) {
		return false
	}
	if path[:len(prefix)] != prefix {
		return false
	}
	if len(path) > len(prefix) && path[len(prefix)] != filepath.Separator {
		return false
	}
	return true
}

// hasPathPrefix checks if path has the given prefix
func hasPathPrefix(path, prefix string) bool {
	if len(path) < len(prefix) {
		return false
	}
	if path[:len(prefix)] != prefix {
		return false
	}
	if len(path) > len(prefix) && path[len(prefix)] != filepath.Separator {
		return false
	}
	return true
}
