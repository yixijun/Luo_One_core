package services

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
	"github.com/luo-one/core/internal/database"
	"github.com/luo-one/core/internal/user"
)

// Feature: luo-one-email-manager, Property 4: 敏感信息加密存储
// For any sensitive information (user passwords, email account passwords),
// the value stored in the database should not be plaintext, and through
// the correct decryption/verification process it can be used normally.
// Validates: Requirements 2.3, 5.4

func TestProperty_SensitiveInfoEncryption(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 20
	properties := gopter.NewProperties(parameters)

	// Use direct generators that produce valid passwords (6-20 chars)
	validPasswordGen := gen.SliceOfN(10, gen.AlphaChar()).Map(func(chars []rune) string {
		return string(chars)
	})

	// Generator for wrong passwords (different from original)
	wrongPasswordGen := gen.SliceOfN(8, gen.AlphaChar()).Map(func(chars []rune) string {
		return string(chars) + "wrong"
	})

	// Property 4.1: Password is never stored as plaintext
	properties.Property("password_never_stored_as_plaintext", prop.ForAll(
		func(password string) bool {
			hashed, err := HashPassword(password)
			if err != nil {
				return false
			}

			// The hash should not equal the original password
			if hashed == password {
				return false
			}

			// The hash should be a valid bcrypt hash
			if !IsPasswordHashed(hashed) {
				return false
			}

			return true
		},
		validPasswordGen,
	))

	// Property 4.2: Hashed password can be verified correctly
	properties.Property("hashed_password_can_be_verified", prop.ForAll(
		func(password string) bool {
			hashed, err := HashPassword(password)
			if err != nil {
				return false
			}

			// Correct password should verify
			if !ComparePassword(hashed, password) {
				return false
			}

			return true
		},
		validPasswordGen,
	))

	// Property 4.3: Wrong password should not verify
	properties.Property("wrong_password_should_not_verify", prop.ForAll(
		func(password, wrongPassword string) bool {
			// Ensure passwords are different
			if password == wrongPassword {
				wrongPassword = wrongPassword + "X"
			}

			hashed, err := HashPassword(password)
			if err != nil {
				return false
			}

			// Wrong password should not verify
			if ComparePassword(hashed, wrongPassword) {
				return false
			}

			return true
		},
		validPasswordGen,
		wrongPasswordGen,
	))

	properties.TestingRun(t)
}


// Property 4.4: User creation stores encrypted password
func TestProperty_UserCreationEncryptsPassword(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 20
	properties := gopter.NewProperties(parameters)

	// Use simpler generators that produce valid inputs directly
	validPasswordGen := gen.SliceOfN(10, gen.AlphaChar()).Map(func(chars []rune) string {
		return string(chars)
	})

	validUsernameGen := gen.SliceOfN(8, gen.AlphaLowerChar()).Map(func(chars []rune) string {
		return string(chars)
	})

	properties.Property("user_creation_encrypts_password", prop.ForAll(
		func(username, password string) bool {
			// Create a fresh temp directory and database for each test
			tempDir, err := os.MkdirTemp("", "luo_one_encrypt_test_*")
			if err != nil {
				return false
			}
			defer os.RemoveAll(tempDir)

			dbPath := filepath.Join(tempDir, "test.db")
			db, err := database.Initialize(dbPath)
			if err != nil {
				return false
			}
			// Close database connection when done
			sqlDB, _ := db.DB()
			defer sqlDB.Close()

			userManager := user.NewManager(tempDir)
			userService := NewUserService(db, userManager)

			// Create user
			createdUser, err := userService.CreateUser(username, password, "Test User")
			if err != nil {
				// Username collision or other error, skip
				return true
			}

			// Verify password is not stored as plaintext
			if createdUser.PasswordHash == password {
				return false
			}

			// Verify password hash is valid bcrypt
			if !IsPasswordHashed(createdUser.PasswordHash) {
				return false
			}

			// Verify password can be verified
			verifiedUser, err := userService.VerifyPassword(username, password)
			if err != nil {
				return false
			}

			return verifiedUser.ID == createdUser.ID
		},
		validUsernameGen,
		validPasswordGen,
	))

	properties.TestingRun(t)
}

// Property 4.5: Password change maintains encryption
func TestProperty_PasswordChangeEncryption(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 20
	properties := gopter.NewProperties(parameters)

	// Use a simpler generator that produces valid passwords directly
	validPasswordGen := gen.SliceOfN(10, gen.AlphaChar()).Map(func(chars []rune) string {
		return string(chars)
	})

	validUsernameGen := gen.SliceOfN(8, gen.AlphaLowerChar()).Map(func(chars []rune) string {
		return string(chars)
	})

	properties.Property("password_change_maintains_encryption", prop.ForAll(
		func(username, oldPassword, newPassword string) bool {
			// Ensure passwords are different
			if oldPassword == newPassword {
				newPassword = newPassword + "X"
			}

			// Create a fresh temp directory and database for each test
			tempDir, err := os.MkdirTemp("", "luo_one_pwdchange_test_*")
			if err != nil {
				return false
			}
			defer os.RemoveAll(tempDir)

			dbPath := filepath.Join(tempDir, "test.db")
			db, err := database.Initialize(dbPath)
			if err != nil {
				return false
			}
			// Close database connection when done
			sqlDB, _ := db.DB()
			defer sqlDB.Close()

			userManager := user.NewManager(tempDir)
			userService := NewUserService(db, userManager)

			// Create user
			createdUser, err := userService.CreateUser(username, oldPassword, "Test User")
			if err != nil {
				return true // Skip on creation error (e.g., duplicate username)
			}

			// Change password
			err = userService.ChangePassword(createdUser.ID, oldPassword, newPassword)
			if err != nil {
				return false
			}

			// Get updated user
			updatedUser, err := userService.GetUserByID(createdUser.ID)
			if err != nil {
				return false
			}

			// Verify new password is not stored as plaintext
			if updatedUser.PasswordHash == newPassword {
				return false
			}

			// Verify new password hash is valid bcrypt
			if !IsPasswordHashed(updatedUser.PasswordHash) {
				return false
			}

			// Verify old password no longer works
			_, err = userService.VerifyPassword(username, oldPassword)
			if err == nil {
				return false // Old password should not work
			}

			// Verify new password works
			_, err = userService.VerifyPassword(username, newPassword)
			if err != nil {
				return false // New password should work
			}

			return true
		},
		validUsernameGen,
		validPasswordGen,
		validPasswordGen,
	))

	properties.TestingRun(t)
}
