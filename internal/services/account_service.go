package services

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"

	"github.com/luo-one/core/internal/database/models"
	"gorm.io/gorm"
)

var (
	// ErrAccountNotFound indicates the email account was not found
	ErrAccountNotFound = errors.New("email account not found")
	// ErrAccountAlreadyExists indicates the email account already exists for this user
	ErrAccountAlreadyExists = errors.New("email account already exists for this user")
	// ErrInvalidAccountData indicates invalid account data
	ErrInvalidAccountData = errors.New("invalid account data")
	// ErrEncryptionFailed indicates password encryption failed
	ErrEncryptionFailed = errors.New("password encryption failed")
	// ErrDecryptionFailed indicates password decryption failed
	ErrDecryptionFailed = errors.New("password decryption failed")
)

// AccountService handles email account-related business logic
type AccountService struct {
	db            *gorm.DB
	encryptionKey []byte // 32 bytes for AES-256
	logService    *LogService
}

// NewAccountService creates a new AccountService instance
func NewAccountService(db *gorm.DB, encryptionKey []byte) *AccountService {
	// Ensure key is 32 bytes for AES-256
	key := make([]byte, 32)
	copy(key, encryptionKey)
	return &AccountService{
		db:            db,
		encryptionKey: key,
		logService:    NewLogService(db),
	}
}

// encryptPassword encrypts a password using AES-256-GCM
func (s *AccountService) encryptPassword(password string) (string, error) {
	block, err := aes.NewCipher(s.encryptionKey)
	if err != nil {
		return "", ErrEncryptionFailed
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", ErrEncryptionFailed
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", ErrEncryptionFailed
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(password), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// decryptPassword decrypts a password using AES-256-GCM
func (s *AccountService) decryptPassword(encryptedPassword string) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedPassword)
	if err != nil {
		return "", ErrDecryptionFailed
	}

	block, err := aes.NewCipher(s.encryptionKey)
	if err != nil {
		return "", ErrDecryptionFailed
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", ErrDecryptionFailed
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", ErrDecryptionFailed
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", ErrDecryptionFailed
	}

	return string(plaintext), nil
}


// CreateAccountInput represents the input for creating an email account
type CreateAccountInput struct {
	UserID      uint
	Email       string
	DisplayName string
	IMAPHost    string
	IMAPPort    int
	SMTPHost    string
	SMTPPort    int
	Username    string
	Password    string
	UseSSL      bool
	SyncDays    int
}

// CreateAccount creates a new email account for a user
func (s *AccountService) CreateAccount(input CreateAccountInput) (*models.EmailAccount, error) {
	// Validate required fields
	if input.Email == "" || input.IMAPHost == "" || input.SMTPHost == "" || input.Username == "" || input.Password == "" {
		return nil, ErrInvalidAccountData
	}

	// Check if account already exists for this user
	var existingAccount models.EmailAccount
	if err := s.db.Where("user_id = ? AND email = ?", input.UserID, input.Email).First(&existingAccount).Error; err == nil {
		return nil, ErrAccountAlreadyExists
	}

	// Encrypt the password
	encryptedPassword, err := s.encryptPassword(input.Password)
	if err != nil {
		return nil, err
	}

	account := &models.EmailAccount{
		UserID:            input.UserID,
		Email:             input.Email,
		DisplayName:       input.DisplayName,
		IMAPHost:          input.IMAPHost,
		IMAPPort:          input.IMAPPort,
		SMTPHost:          input.SMTPHost,
		SMTPPort:          input.SMTPPort,
		Username:          input.Username,
		PasswordEncrypted: encryptedPassword,
		UseSSL:            input.UseSSL,
		SyncDays:          input.SyncDays,
		Enabled:           true, // Default to enabled
	}

	if err := s.db.Create(account).Error; err != nil {
		return nil, err
	}

	// Log the account creation
	s.logService.LogAccountCreated(input.UserID, account.ID, account.Email)

	return account, nil
}

// GetAccountByID retrieves an email account by ID
func (s *AccountService) GetAccountByID(id uint) (*models.EmailAccount, error) {
	var account models.EmailAccount
	if err := s.db.First(&account, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrAccountNotFound
		}
		return nil, err
	}
	return &account, nil
}

// GetAccountByIDAndUserID retrieves an email account by ID and user ID (for authorization)
func (s *AccountService) GetAccountByIDAndUserID(id, userID uint) (*models.EmailAccount, error) {
	var account models.EmailAccount
	if err := s.db.Where("id = ? AND user_id = ?", id, userID).First(&account).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrAccountNotFound
		}
		return nil, err
	}
	return &account, nil
}

// GetAccountsByUserID retrieves all email accounts for a user
func (s *AccountService) GetAccountsByUserID(userID uint) ([]models.EmailAccount, error) {
	var accounts []models.EmailAccount
	if err := s.db.Where("user_id = ?", userID).Find(&accounts).Error; err != nil {
		return nil, err
	}
	return accounts, nil
}

// UpdateAccountInput represents the input for updating an email account
type UpdateAccountInput struct {
	DisplayName string
	IMAPHost    string
	IMAPPort    int
	SMTPHost    string
	SMTPPort    int
	Username    string
	Password    string // Optional: only update if not empty
	UseSSL      bool
	SyncDays    *int // 使用指针区分 0 和未设置
}

// UpdateAccount updates an email account
func (s *AccountService) UpdateAccount(id, userID uint, input UpdateAccountInput) (*models.EmailAccount, error) {
	account, err := s.GetAccountByIDAndUserID(id, userID)
	if err != nil {
		return nil, err
	}

	// Update fields
	if input.DisplayName != "" {
		account.DisplayName = input.DisplayName
	}
	if input.IMAPHost != "" {
		account.IMAPHost = input.IMAPHost
	}
	if input.IMAPPort > 0 {
		account.IMAPPort = input.IMAPPort
	}
	if input.SMTPHost != "" {
		account.SMTPHost = input.SMTPHost
	}
	if input.SMTPPort > 0 {
		account.SMTPPort = input.SMTPPort
	}
	if input.Username != "" {
		account.Username = input.Username
	}
	account.UseSSL = input.UseSSL

	// Update sync_days if provided
	if input.SyncDays != nil {
		account.SyncDays = *input.SyncDays
	}

	// Update password if provided
	if input.Password != "" {
		encryptedPassword, err := s.encryptPassword(input.Password)
		if err != nil {
			return nil, err
		}
		account.PasswordEncrypted = encryptedPassword
	}

	if err := s.db.Save(account).Error; err != nil {
		return nil, err
	}

	// Log the account update
	s.logService.LogAccountUpdated(userID, account.ID, account.Email)

	return account, nil
}

// DeleteAccount deletes an email account
func (s *AccountService) DeleteAccount(id, userID uint) error {
	account, err := s.GetAccountByIDAndUserID(id, userID)
	if err != nil {
		return err
	}

	email := account.Email

	if err := s.db.Delete(account).Error; err != nil {
		return err
	}

	// Log the account deletion
	s.logService.LogAccountDeleted(userID, id, email)

	return nil
}

// GetDecryptedPassword retrieves the decrypted password for an account
func (s *AccountService) GetDecryptedPassword(account *models.EmailAccount) (string, error) {
	return s.decryptPassword(account.PasswordEncrypted)
}


// ConnectionTestResult represents the result of a connection test
type ConnectionTestResult struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// TestIMAPConnection tests the IMAP connection for an account
func (s *AccountService) TestIMAPConnection(account *models.EmailAccount) ConnectionTestResult {
	password, err := s.decryptPassword(account.PasswordEncrypted)
	if err != nil {
		return ConnectionTestResult{
			Success: false,
			Message: "Failed to decrypt password: " + err.Error(),
		}
	}

	// Build the address
	addr := buildAddress(account.IMAPHost, account.IMAPPort)

	// Try to connect
	result := testIMAPConnectionInternal(addr, account.Username, password, account.UseSSL)
	return result
}

// TestSMTPConnection tests the SMTP connection for an account
func (s *AccountService) TestSMTPConnection(account *models.EmailAccount) ConnectionTestResult {
	password, err := s.decryptPassword(account.PasswordEncrypted)
	if err != nil {
		return ConnectionTestResult{
			Success: false,
			Message: "Failed to decrypt password: " + err.Error(),
		}
	}

	// Build the address
	addr := buildAddress(account.SMTPHost, account.SMTPPort)

	// Try to connect
	result := testSMTPConnectionInternal(addr, account.Username, password, account.UseSSL)
	return result
}

// TestConnection tests both IMAP and SMTP connections for an account
func (s *AccountService) TestConnection(account *models.EmailAccount) ConnectionTestResult {
	// Test IMAP first
	imapResult := s.TestIMAPConnection(account)
	if !imapResult.Success {
		return ConnectionTestResult{
			Success: false,
			Message: "IMAP connection failed: " + imapResult.Message,
		}
	}

	// Test SMTP
	smtpResult := s.TestSMTPConnection(account)
	if !smtpResult.Success {
		return ConnectionTestResult{
			Success: false,
			Message: "SMTP connection failed: " + smtpResult.Message,
		}
	}

	return ConnectionTestResult{
		Success: true,
		Message: "Both IMAP and SMTP connections successful",
	}
}

// TestConnectionByID tests the connection for an account by ID
func (s *AccountService) TestConnectionByID(id, userID uint) (ConnectionTestResult, error) {
	account, err := s.GetAccountByIDAndUserID(id, userID)
	if err != nil {
		return ConnectionTestResult{}, err
	}

	return s.TestConnection(account), nil
}

// TestConnectionInput represents the input for testing a connection without saving
type TestConnectionInput struct {
	IMAPHost string
	IMAPPort int
	SMTPHost string
	SMTPPort int
	Username string
	Password string
	UseSSL   bool
}

// TestConnectionDirect tests the connection with provided credentials (without saving)
func (s *AccountService) TestConnectionDirect(input TestConnectionInput) ConnectionTestResult {
	// Test IMAP first
	imapAddr := buildAddress(input.IMAPHost, input.IMAPPort)
	imapResult := testIMAPConnectionInternal(imapAddr, input.Username, input.Password, input.UseSSL)
	if !imapResult.Success {
		return ConnectionTestResult{
			Success: false,
			Message: "IMAP connection failed: " + imapResult.Message,
		}
	}

	// Test SMTP
	smtpAddr := buildAddress(input.SMTPHost, input.SMTPPort)
	smtpResult := testSMTPConnectionInternal(smtpAddr, input.Username, input.Password, input.UseSSL)
	if !smtpResult.Success {
		return ConnectionTestResult{
			Success: false,
			Message: "SMTP connection failed: " + smtpResult.Message,
		}
	}

	return ConnectionTestResult{
		Success: true,
		Message: "Both IMAP and SMTP connections successful",
	}
}


// SetAccountEnabled sets the enabled status of an account
func (s *AccountService) SetAccountEnabled(id, userID uint, enabled bool) (*models.EmailAccount, error) {
	account, err := s.GetAccountByIDAndUserID(id, userID)
	if err != nil {
		return nil, err
	}

	account.Enabled = enabled

	if err := s.db.Save(account).Error; err != nil {
		return nil, err
	}

	// Log the status change
	s.logService.LogAccountStatusChanged(userID, account.ID, account.Email, enabled)

	return account, nil
}

// EnableAccount enables an email account
func (s *AccountService) EnableAccount(id, userID uint) (*models.EmailAccount, error) {
	return s.SetAccountEnabled(id, userID, true)
}

// DisableAccount disables an email account
func (s *AccountService) DisableAccount(id, userID uint) (*models.EmailAccount, error) {
	return s.SetAccountEnabled(id, userID, false)
}

// ToggleAccountEnabled toggles the enabled status of an account
func (s *AccountService) ToggleAccountEnabled(id, userID uint) (*models.EmailAccount, error) {
	account, err := s.GetAccountByIDAndUserID(id, userID)
	if err != nil {
		return nil, err
	}

	account.Enabled = !account.Enabled

	if err := s.db.Save(account).Error; err != nil {
		return nil, err
	}

	// Log the status change
	s.logService.LogAccountStatusChanged(userID, account.ID, account.Email, account.Enabled)

	return account, nil
}

// GetEnabledAccountsByUserID retrieves all enabled email accounts for a user
func (s *AccountService) GetEnabledAccountsByUserID(userID uint) ([]models.EmailAccount, error) {
	var accounts []models.EmailAccount
	if err := s.db.Where("user_id = ? AND enabled = ?", userID, true).Find(&accounts).Error; err != nil {
		return nil, err
	}
	return accounts, nil
}

// CreateAccountWithOAuth creates a new email account with OAuth tokens
func (s *AccountService) CreateAccountWithOAuth(account *models.EmailAccount, accessToken, refreshToken string) error {
	// Check if account already exists for this user
	var existingAccount models.EmailAccount
	if err := s.db.Where("user_id = ? AND email = ?", account.UserID, account.Email).First(&existingAccount).Error; err == nil {
		// Update existing account with new OAuth tokens
		encryptedAccess, err := s.encryptPassword(accessToken)
		if err != nil {
			return err
		}
		encryptedRefresh, err := s.encryptPassword(refreshToken)
		if err != nil {
			return err
		}

		existingAccount.AuthType = models.AuthTypeOAuth2
		existingAccount.OAuthProvider = account.OAuthProvider
		existingAccount.OAuthAccessToken = encryptedAccess
		existingAccount.OAuthRefreshToken = encryptedRefresh
		existingAccount.OAuthTokenExpiry = account.OAuthTokenExpiry
		existingAccount.Enabled = true

		return s.db.Save(&existingAccount).Error
	}

	// Encrypt tokens
	encryptedAccess, err := s.encryptPassword(accessToken)
	if err != nil {
		return err
	}
	encryptedRefresh, err := s.encryptPassword(refreshToken)
	if err != nil {
		return err
	}

	account.OAuthAccessToken = encryptedAccess
	account.OAuthRefreshToken = encryptedRefresh

	if err := s.db.Create(account).Error; err != nil {
		return err
	}

	// Log the account creation
	s.logService.LogAccountCreated(account.UserID, account.ID, account.Email)

	return nil
}

// GetDecryptedOAuthTokens returns the decrypted OAuth tokens for an account
func (s *AccountService) GetDecryptedOAuthTokens(account *models.EmailAccount) (accessToken, refreshToken string, err error) {
	if account.OAuthAccessToken != "" {
		accessToken, err = s.decryptPassword(account.OAuthAccessToken)
		if err != nil {
			return "", "", err
		}
	}
	if account.OAuthRefreshToken != "" {
		refreshToken, err = s.decryptPassword(account.OAuthRefreshToken)
		if err != nil {
			return "", "", err
		}
	}
	return accessToken, refreshToken, nil
}

// UpdateOAuthTokens updates the OAuth tokens for an account
func (s *AccountService) UpdateOAuthTokens(accountID uint, accessToken, refreshToken string, expiry interface{}) error {
	updates := make(map[string]interface{})

	if accessToken != "" {
		encryptedAccess, err := s.encryptPassword(accessToken)
		if err != nil {
			return err
		}
		updates["oauth_access_token"] = encryptedAccess
	}

	if refreshToken != "" {
		encryptedRefresh, err := s.encryptPassword(refreshToken)
		if err != nil {
			return err
		}
		updates["oauth_refresh_token"] = encryptedRefresh
	}

	if expiry != nil {
		updates["oauth_token_expiry"] = expiry
	}

	return s.db.Model(&models.EmailAccount{}).Where("id = ?", accountID).Updates(updates).Error
}
