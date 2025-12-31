package handlers

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
	"github.com/luo-one/core/internal/database"
	"github.com/luo-one/core/internal/services"
	"github.com/luo-one/core/internal/user"
)

// Feature: luo-one-email-manager, Property 12: 用户密码重置有效性
// For any user password reset operation, after reset the old password should
// not be able to login, and the new password should be able to login normally.
// Validates: Requirements 6.4, 9.2

func TestProperty_UserPasswordResetValidity(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 20
	properties := gopter.NewProperties(parameters)

	// Generator for valid passwords (6-20 chars)
	validPasswordGen := gen.SliceOfN(10, gen.AlphaChar()).Map(func(chars []rune) string {
		return string(chars)
	})

	// Generator for valid usernames
	validUsernameGen := gen.SliceOfN(8, gen.AlphaLowerChar()).Map(func(chars []rune) string {
		return string(chars)
	})

	// Property 12.1: After password reset, old password should not work
	properties.Property("old_password_invalid_after_reset", prop.ForAll(
		func(username, oldPassword, newPassword string) bool {
			// Ensure passwords are different
			if oldPassword == newPassword {
				newPassword = newPassword + "X"
			}

			// Create a fresh temp directory and database for each test
			tempDir, err := os.MkdirTemp("", "luo_one_pwd_reset_test_*")
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
			userService := services.NewUserService(db, userManager)

			// Create user with old password
			createdUser, err := userService.CreateUser(username, oldPassword, "Test User")
			if err != nil {
				return true // Skip on creation error
			}

			// Verify old password works before reset
			_, err = userService.VerifyPassword(username, oldPassword)
			if err != nil {
				return false // Old password should work before reset
			}

			// Reset password (admin operation)
			err = userService.ResetPassword(createdUser.ID, newPassword)
			if err != nil {
				return false
			}

			// Verify old password no longer works
			_, err = userService.VerifyPassword(username, oldPassword)
			if err == nil {
				return false // Old password should NOT work after reset
			}

			return true
		},
		validUsernameGen,
		validPasswordGen,
		validPasswordGen,
	))

	// Property 12.2: After password reset, new password should work
	properties.Property("new_password_valid_after_reset", prop.ForAll(
		func(username, oldPassword, newPassword string) bool {
			// Ensure passwords are different
			if oldPassword == newPassword {
				newPassword = newPassword + "X"
			}

			// Create a fresh temp directory and database for each test
			tempDir, err := os.MkdirTemp("", "luo_one_pwd_reset_test2_*")
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
			userService := services.NewUserService(db, userManager)

			// Create user with old password
			createdUser, err := userService.CreateUser(username, oldPassword, "Test User")
			if err != nil {
				return true // Skip on creation error
			}

			// Reset password (admin operation)
			err = userService.ResetPassword(createdUser.ID, newPassword)
			if err != nil {
				return false
			}

			// Verify new password works
			verifiedUser, err := userService.VerifyPassword(username, newPassword)
			if err != nil {
				return false // New password should work after reset
			}

			return verifiedUser.ID == createdUser.ID
		},
		validUsernameGen,
		validPasswordGen,
		validPasswordGen,
	))

	// Property 12.3: Password change via API (with old password verification)
	properties.Property("password_change_requires_old_password", prop.ForAll(
		func(username, oldPassword, newPassword, wrongPassword string) bool {
			// Ensure passwords are different
			if oldPassword == newPassword {
				newPassword = newPassword + "X"
			}
			if wrongPassword == oldPassword {
				wrongPassword = wrongPassword + "Y"
			}

			// Create a fresh temp directory and database for each test
			tempDir, err := os.MkdirTemp("", "luo_one_pwd_change_test_*")
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
			userService := services.NewUserService(db, userManager)

			// Create user
			createdUser, err := userService.CreateUser(username, oldPassword, "Test User")
			if err != nil {
				return true // Skip on creation error
			}

			// Try to change password with wrong old password - should fail
			err = userService.ChangePassword(createdUser.ID, wrongPassword, newPassword)
			if err == nil {
				return false // Should fail with wrong old password
			}

			// Change password with correct old password - should succeed
			err = userService.ChangePassword(createdUser.ID, oldPassword, newPassword)
			if err != nil {
				return false // Should succeed with correct old password
			}

			// Verify new password works
			_, err = userService.VerifyPassword(username, newPassword)
			if err != nil {
				return false
			}

			return true
		},
		validUsernameGen,
		validPasswordGen,
		validPasswordGen,
		validPasswordGen,
	))

	properties.TestingRun(t)
}
