package services

import (
	"errors"

	"github.com/luo-one/core/internal/database/models"
	"github.com/luo-one/core/internal/user"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

var (
	// ErrUserNotFound indicates the user was not found
	ErrUserNotFound = errors.New("user not found")
	// ErrUserAlreadyExists indicates the username is already taken
	ErrUserAlreadyExists = errors.New("user already exists")
	// ErrInvalidCredentials indicates invalid login credentials
	ErrInvalidCredentials = errors.New("invalid credentials")
	// ErrPasswordTooShort indicates the password is too short
	ErrPasswordTooShort = errors.New("password must be at least 6 characters")
)

// UserService handles user-related business logic
type UserService struct {
	db          *gorm.DB
	userManager *user.Manager
}

// NewUserService creates a new UserService instance
func NewUserService(db *gorm.DB, userManager *user.Manager) *UserService {
	return &UserService{
		db:          db,
		userManager: userManager,
	}
}

// CreateUser creates a new user with encrypted password
func (s *UserService) CreateUser(username, password, nickname string) (*models.User, error) {
	if len(password) < 6 {
		return nil, ErrPasswordTooShort
	}

	// Check if username already exists
	var existingUser models.User
	if err := s.db.Where("username = ?", username).First(&existingUser).Error; err == nil {
		return nil, ErrUserAlreadyExists
	}

	// Hash the password using bcrypt
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	newUser := &models.User{
		Username:     username,
		PasswordHash: string(hashedPassword),
		Nickname:     nickname,
	}

	// Create user in database
	if err := s.db.Create(newUser).Error; err != nil {
		return nil, err
	}

	// Create user directories
	if err := s.userManager.CreateUserDirectories(newUser.ID); err != nil {
		// Rollback user creation if directory creation fails
		s.db.Delete(newUser)
		return nil, err
	}

	// Create default user settings
	settings := &models.UserSettings{
		UserID:          newUser.ID,
		AIEnabled:       false,
		ExtractCode:     true,
		DetectAd:        true,
		Summarize:       false,
		JudgeImportance: true,
	}
	if err := s.db.Create(settings).Error; err != nil {
		// Rollback
		s.userManager.DeleteUserDirectories(newUser.ID)
		s.db.Delete(newUser)
		return nil, err
	}

	return newUser, nil
}


// GetUserByID retrieves a user by ID
func (s *UserService) GetUserByID(id uint) (*models.User, error) {
	var foundUser models.User
	if err := s.db.First(&foundUser, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return &foundUser, nil
}

// GetUserByUsername retrieves a user by username
func (s *UserService) GetUserByUsername(username string) (*models.User, error) {
	var foundUser models.User
	if err := s.db.Where("username = ?", username).First(&foundUser).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return &foundUser, nil
}

// UpdateUser updates user information
func (s *UserService) UpdateUser(id uint, nickname, avatar string) (*models.User, error) {
	foundUser, err := s.GetUserByID(id)
	if err != nil {
		return nil, err
	}

	foundUser.Nickname = nickname
	foundUser.Avatar = avatar

	if err := s.db.Save(foundUser).Error; err != nil {
		return nil, err
	}

	return foundUser, nil
}

// DeleteUser deletes a user and their data
func (s *UserService) DeleteUser(id uint) error {
	foundUser, err := s.GetUserByID(id)
	if err != nil {
		return err
	}

	// Delete user settings
	s.db.Where("user_id = ?", id).Delete(&models.UserSettings{})

	// Delete user directories
	if err := s.userManager.DeleteUserDirectories(id); err != nil {
		// Log but continue with database deletion
	}

	// Delete user from database
	return s.db.Delete(foundUser).Error
}

// ListUsers returns all users
func (s *UserService) ListUsers() ([]models.User, error) {
	var users []models.User
	if err := s.db.Find(&users).Error; err != nil {
		return nil, err
	}
	return users, nil
}


// VerifyPassword verifies a user's password
func (s *UserService) VerifyPassword(username, password string) (*models.User, error) {
	foundUser, err := s.GetUserByUsername(username)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	if err := bcrypt.CompareHashAndPassword([]byte(foundUser.PasswordHash), []byte(password)); err != nil {
		return nil, ErrInvalidCredentials
	}

	return foundUser, nil
}

// ChangePassword changes a user's password
func (s *UserService) ChangePassword(id uint, oldPassword, newPassword string) error {
	if len(newPassword) < 6 {
		return ErrPasswordTooShort
	}

	foundUser, err := s.GetUserByID(id)
	if err != nil {
		return err
	}

	// Verify old password
	if err := bcrypt.CompareHashAndPassword([]byte(foundUser.PasswordHash), []byte(oldPassword)); err != nil {
		return ErrInvalidCredentials
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	foundUser.PasswordHash = string(hashedPassword)
	return s.db.Save(foundUser).Error
}

// ResetPassword resets a user's password (admin operation)
func (s *UserService) ResetPassword(id uint, newPassword string) error {
	if len(newPassword) < 6 {
		return ErrPasswordTooShort
	}

	foundUser, err := s.GetUserByID(id)
	if err != nil {
		return err
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	foundUser.PasswordHash = string(hashedPassword)
	return s.db.Save(foundUser).Error
}

// GetUserSettings retrieves user settings
func (s *UserService) GetUserSettings(userID uint) (*models.UserSettings, error) {
	var settings models.UserSettings
	if err := s.db.Where("user_id = ?", userID).First(&settings).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// Create default settings if not found
			settings = models.UserSettings{
				UserID:          userID,
				AIEnabled:       false,
				ExtractCode:     true,
				DetectAd:        true,
				Summarize:       false,
				JudgeImportance: true,
			}
			if err := s.db.Create(&settings).Error; err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}
	return &settings, nil
}

// UpdateUserSettings updates user settings
func (s *UserService) UpdateUserSettings(userID uint, settings *models.UserSettings) error {
	settings.UserID = userID
	return s.db.Where("user_id = ?", userID).Save(settings).Error
}

// IsPasswordHashed checks if a string looks like a bcrypt hash
func IsPasswordHashed(password string) bool {
	// bcrypt hashes start with $2a$, $2b$, or $2y$
	if len(password) < 4 {
		return false
	}
	return password[:4] == "$2a$" || password[:4] == "$2b$" || password[:4] == "$2y$"
}

// HashPassword hashes a password using bcrypt
func HashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}

// ComparePassword compares a password with a hash
func ComparePassword(hashedPassword, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err == nil
}
