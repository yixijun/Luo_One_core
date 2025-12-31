package user

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

var (
	// ErrFileNotFound indicates the requested file was not found
	ErrFileNotFound = errors.New("file not found")
	// ErrFileWriteFailed indicates file write operation failed
	ErrFileWriteFailed = errors.New("failed to write file")
	// ErrFileReadFailed indicates file read operation failed
	ErrFileReadFailed = errors.New("failed to read file")
)

// Storage handles user file storage operations
type Storage struct {
	manager *Manager
}

// NewStorage creates a new user Storage instance
func NewStorage(manager *Manager) *Storage {
	return &Storage{
		manager: manager,
	}
}

// SaveRawEmail saves a raw email file for a user
func (s *Storage) SaveRawEmail(userID, accountID uint, messageID string, content []byte) (string, error) {
	dir, err := s.manager.GetRawEmailsAccountDir(userID, accountID)
	if err != nil {
		return "", err
	}

	// Ensure directory exists
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("%w: %s", ErrFileWriteFailed, err.Error())
	}

	// Sanitize messageID for filename
	filename := sanitizeFilename(messageID) + ".eml"
	filePath := filepath.Join(dir, filename)

	if err := os.WriteFile(filePath, content, 0644); err != nil {
		return "", fmt.Errorf("%w: %s", ErrFileWriteFailed, err.Error())
	}

	return filePath, nil
}

// GetRawEmail retrieves a raw email file
func (s *Storage) GetRawEmail(userID, accountID uint, messageID string) ([]byte, error) {
	dir, err := s.manager.GetRawEmailsAccountDir(userID, accountID)
	if err != nil {
		return nil, err
	}

	filename := sanitizeFilename(messageID) + ".eml"
	filePath := filepath.Join(dir, filename)

	content, err := os.ReadFile(filePath)
	if os.IsNotExist(err) {
		return nil, ErrFileNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrFileReadFailed, err.Error())
	}

	return content, nil
}


// SaveProcessedResult saves a processed email result as JSON
func (s *Storage) SaveProcessedResult(userID, accountID uint, messageID string, result interface{}) (string, error) {
	dir, err := s.manager.GetProcessedEmailsAccountDir(userID, accountID)
	if err != nil {
		return "", err
	}

	// Ensure directory exists
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("%w: %s", ErrFileWriteFailed, err.Error())
	}

	filename := sanitizeFilename(messageID) + ".json"
	filePath := filepath.Join(dir, filename)

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", fmt.Errorf("%w: %s", ErrFileWriteFailed, err.Error())
	}

	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return "", fmt.Errorf("%w: %s", ErrFileWriteFailed, err.Error())
	}

	return filePath, nil
}

// GetProcessedResult retrieves a processed email result
func (s *Storage) GetProcessedResult(userID, accountID uint, messageID string, result interface{}) error {
	dir, err := s.manager.GetProcessedEmailsAccountDir(userID, accountID)
	if err != nil {
		return err
	}

	filename := sanitizeFilename(messageID) + ".json"
	filePath := filepath.Join(dir, filename)

	content, err := os.ReadFile(filePath)
	if os.IsNotExist(err) {
		return ErrFileNotFound
	}
	if err != nil {
		return fmt.Errorf("%w: %s", ErrFileReadFailed, err.Error())
	}

	if err := json.Unmarshal(content, result); err != nil {
		return fmt.Errorf("%w: %s", ErrFileReadFailed, err.Error())
	}

	return nil
}

// SaveAttachment saves an attachment file
func (s *Storage) SaveAttachment(userID, emailID uint, filename string, content []byte) (string, error) {
	dir, err := s.manager.GetEmailAttachmentsDir(userID, emailID)
	if err != nil {
		return "", err
	}

	// Ensure directory exists
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("%w: %s", ErrFileWriteFailed, err.Error())
	}

	// Sanitize filename
	safeFilename := sanitizeFilename(filename)
	filePath := filepath.Join(dir, safeFilename)

	if err := os.WriteFile(filePath, content, 0644); err != nil {
		return "", fmt.Errorf("%w: %s", ErrFileWriteFailed, err.Error())
	}

	return filePath, nil
}

// GetAttachment retrieves an attachment file
func (s *Storage) GetAttachment(userID, emailID uint, filename string) ([]byte, error) {
	dir, err := s.manager.GetEmailAttachmentsDir(userID, emailID)
	if err != nil {
		return nil, err
	}

	safeFilename := sanitizeFilename(filename)
	filePath := filepath.Join(dir, safeFilename)

	// Validate path belongs to user
	if err := s.manager.ValidatePathBelongsToUser(userID, filePath); err != nil {
		return nil, err
	}

	content, err := os.ReadFile(filePath)
	if os.IsNotExist(err) {
		return nil, ErrFileNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrFileReadFailed, err.Error())
	}

	return content, nil
}


// SaveAttachmentFromReader saves an attachment from an io.Reader
func (s *Storage) SaveAttachmentFromReader(userID, emailID uint, filename string, reader io.Reader) (string, error) {
	dir, err := s.manager.GetEmailAttachmentsDir(userID, emailID)
	if err != nil {
		return "", err
	}

	// Ensure directory exists
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("%w: %s", ErrFileWriteFailed, err.Error())
	}

	safeFilename := sanitizeFilename(filename)
	filePath := filepath.Join(dir, safeFilename)

	file, err := os.Create(filePath)
	if err != nil {
		return "", fmt.Errorf("%w: %s", ErrFileWriteFailed, err.Error())
	}
	defer file.Close()

	if _, err := io.Copy(file, reader); err != nil {
		return "", fmt.Errorf("%w: %s", ErrFileWriteFailed, err.Error())
	}

	return filePath, nil
}

// DeleteAttachment deletes an attachment file
func (s *Storage) DeleteAttachment(userID, emailID uint, filename string) error {
	dir, err := s.manager.GetEmailAttachmentsDir(userID, emailID)
	if err != nil {
		return err
	}

	safeFilename := sanitizeFilename(filename)
	filePath := filepath.Join(dir, safeFilename)

	// Validate path belongs to user
	if err := s.manager.ValidatePathBelongsToUser(userID, filePath); err != nil {
		return err
	}

	if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
		return err
	}

	return nil
}

// ListAttachments lists all attachments for an email
func (s *Storage) ListAttachments(userID, emailID uint) ([]string, error) {
	dir, err := s.manager.GetEmailAttachmentsDir(userID, emailID)
	if err != nil {
		return nil, err
	}

	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return []string{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrFileReadFailed, err.Error())
	}

	var files []string
	for _, entry := range entries {
		if !entry.IsDir() {
			files = append(files, entry.Name())
		}
	}

	return files, nil
}

// sanitizeFilename removes or replaces unsafe characters from filenames
func sanitizeFilename(name string) string {
	// Replace unsafe characters with underscores
	unsafe := []string{"/", "\\", ":", "*", "?", "\"", "<", ">", "|", "\x00"}
	result := name
	for _, char := range unsafe {
		result = filepath.Clean(result)
		for i := 0; i < len(result); i++ {
			if string(result[i]) == char {
				result = result[:i] + "_" + result[i+1:]
			}
		}
	}
	// Use filepath.Base to prevent directory traversal
	return filepath.Base(result)
}
