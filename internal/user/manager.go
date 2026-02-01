package user

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var (
	// ErrInvalidUserID indicates an invalid user ID was provided
	ErrInvalidUserID = errors.New("invalid user ID")
	// ErrUserDataAccessDenied indicates unauthorized access to user data
	ErrUserDataAccessDenied = errors.New("access to user data denied")
	// ErrDirectoryCreationFailed indicates directory creation failed
	ErrDirectoryCreationFailed = errors.New("failed to create directory")
)

// Manager handles user data directory management
type Manager struct {
	dataDir   string // 数据目录（配置、数据库等）
	emailsDir string // 邮件存储目录（可独立配置）
}

// NewManager creates a new user Manager instance
// emailsDir 为空时，邮件存储在 dataDir/users 下
func NewManager(dataDir string) *Manager {
	return &Manager{
		dataDir:   dataDir,
		emailsDir: "", // 默认使用 dataDir/users
	}
}

// NewManagerWithEmailsDir creates a new user Manager with separate emails directory
func NewManagerWithEmailsDir(dataDir, emailsDir string) *Manager {
	return &Manager{
		dataDir:   dataDir,
		emailsDir: emailsDir,
	}
}

// getEmailsBaseDir returns the base directory for email storage
func (m *Manager) getEmailsBaseDir() string {
	if m.emailsDir != "" {
		return m.emailsDir
	}
	return filepath.Join(m.dataDir, "users")
}

// GetUserDataDir returns the base data directory for a specific user
func (m *Manager) GetUserDataDir(userID uint) (string, error) {
	if userID == 0 {
		return "", ErrInvalidUserID
	}
	return filepath.Join(m.getEmailsBaseDir(), fmt.Sprintf("%d", userID)), nil
}

// GetRawEmailsDir returns the raw emails directory for a user
func (m *Manager) GetRawEmailsDir(userID uint) (string, error) {
	userDir, err := m.GetUserDataDir(userID)
	if err != nil {
		return "", err
	}
	return filepath.Join(userDir, "raw_emails"), nil
}

// GetProcessedEmailsDir returns the processed emails directory for a user
func (m *Manager) GetProcessedEmailsDir(userID uint) (string, error) {
	userDir, err := m.GetUserDataDir(userID)
	if err != nil {
		return "", err
	}
	return filepath.Join(userDir, "processed_emails"), nil
}

// GetAttachmentsDir returns the attachments directory for a user
func (m *Manager) GetAttachmentsDir(userID uint) (string, error) {
	userDir, err := m.GetUserDataDir(userID)
	if err != nil {
		return "", err
	}
	return filepath.Join(userDir, "attachments"), nil
}


// GetRawEmailsAccountDir returns the raw emails directory for a specific account
func (m *Manager) GetRawEmailsAccountDir(userID uint, accountID uint) (string, error) {
	rawDir, err := m.GetRawEmailsDir(userID)
	if err != nil {
		return "", err
	}
	return filepath.Join(rawDir, fmt.Sprintf("%d", accountID)), nil
}

// GetProcessedEmailsAccountDir returns the processed emails directory for a specific account
func (m *Manager) GetProcessedEmailsAccountDir(userID uint, accountID uint) (string, error) {
	processedDir, err := m.GetProcessedEmailsDir(userID)
	if err != nil {
		return "", err
	}
	return filepath.Join(processedDir, fmt.Sprintf("%d", accountID)), nil
}

// GetEmailAttachmentsDir returns the attachments directory for a specific email
func (m *Manager) GetEmailAttachmentsDir(userID uint, emailID uint) (string, error) {
	attachDir, err := m.GetAttachmentsDir(userID)
	if err != nil {
		return "", err
	}
	return filepath.Join(attachDir, fmt.Sprintf("%d", emailID)), nil
}

// CreateUserDirectories creates all necessary directories for a user
func (m *Manager) CreateUserDirectories(userID uint) error {
	if userID == 0 {
		return ErrInvalidUserID
	}

	baseDir := m.getEmailsBaseDir()
	userDir := filepath.Join(baseDir, fmt.Sprintf("%d", userID))

	dirs := []string{
		userDir,
		filepath.Join(userDir, "raw_emails"),
		filepath.Join(userDir, "processed_emails"),
		filepath.Join(userDir, "attachments"),
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("%w: %s", ErrDirectoryCreationFailed, err.Error())
		}
	}

	return nil
}

// CreateAccountDirectories creates directories for a specific email account
func (m *Manager) CreateAccountDirectories(userID uint, accountID uint) error {
	if userID == 0 {
		return ErrInvalidUserID
	}

	rawDir, err := m.GetRawEmailsAccountDir(userID, accountID)
	if err != nil {
		return err
	}

	processedDir, err := m.GetProcessedEmailsAccountDir(userID, accountID)
	if err != nil {
		return err
	}

	dirs := []string{rawDir, processedDir}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("%w: %s", ErrDirectoryCreationFailed, err.Error())
		}
	}

	return nil
}


// ValidateUserAccess validates that a requesting user can access the target user's data
// This ensures user data isolation - users can only access their own data
func (m *Manager) ValidateUserAccess(requestingUserID, targetUserID uint) error {
	if requestingUserID == 0 || targetUserID == 0 {
		return ErrInvalidUserID
	}
	if requestingUserID != targetUserID {
		return ErrUserDataAccessDenied
	}
	return nil
}

// ValidatePathBelongsToUser validates that a file path belongs to a specific user
// This prevents path traversal attacks and ensures data isolation
func (m *Manager) ValidatePathBelongsToUser(userID uint, path string) error {
	if userID == 0 {
		return ErrInvalidUserID
	}

	userDir, err := m.GetUserDataDir(userID)
	if err != nil {
		return err
	}

	// Clean and resolve the path
	cleanPath := filepath.Clean(path)
	absPath, err := filepath.Abs(cleanPath)
	if err != nil {
		return ErrUserDataAccessDenied
	}

	absUserDir, err := filepath.Abs(userDir)
	if err != nil {
		return ErrUserDataAccessDenied
	}

	// Ensure the path starts with the user's directory
	if !strings.HasPrefix(absPath, absUserDir+string(filepath.Separator)) && absPath != absUserDir {
		return ErrUserDataAccessDenied
	}

	return nil
}

// UserDirectoriesExist checks if user directories already exist
func (m *Manager) UserDirectoriesExist(userID uint) (bool, error) {
	userDir, err := m.GetUserDataDir(userID)
	if err != nil {
		return false, err
	}

	info, err := os.Stat(userDir)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	return info.IsDir(), nil
}

// DeleteUserDirectories removes all directories for a user
func (m *Manager) DeleteUserDirectories(userID uint) error {
	userDir, err := m.GetUserDataDir(userID)
	if err != nil {
		return err
	}

	return os.RemoveAll(userDir)
}

// GetDataDir returns the base data directory
func (m *Manager) GetDataDir() string {
	return m.dataDir
}
