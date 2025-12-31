package services

import (
	"os"
	"testing"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
	"github.com/luo-one/core/internal/database/models"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Feature: luo-one-email-manager, Property 5: 邮箱账户状态切换幂等性
// For any email account, executing the same enable/disable operation consecutively
// should keep the state unchanged, and querying after status switch should return
// the correct status value.
// Validates: Requirements 2.4

func setupTestDB(t *testing.T) (*gorm.DB, func()) {
	// Create a temporary database file
	tmpFile, err := os.CreateTemp("", "test_*.db")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	tmpFile.Close()

	// Open database
	db, err := gorm.Open(sqlite.Open(tmpFile.Name()), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		os.Remove(tmpFile.Name())
		t.Fatalf("Failed to open database: %v", err)
	}

	// Run migrations
	err = db.AutoMigrate(
		&models.User{},
		&models.UserSettings{},
		&models.EmailAccount{},
		&models.Log{},
	)
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

func createTestAccount(t *testing.T, service *AccountService, userID uint, email string, enabled bool) *models.EmailAccount {
	account, err := service.CreateAccount(CreateAccountInput{
		UserID:      userID,
		Email:       email,
		DisplayName: "Test Account",
		IMAPHost:    "imap.test.com",
		IMAPPort:    993,
		SMTPHost:    "smtp.test.com",
		SMTPPort:    587,
		Username:    "test@test.com",
		Password:    "testpassword",
		UseSSL:      true,
	})
	if err != nil {
		t.Fatalf("Failed to create test account: %v", err)
	}

	// Set initial enabled state if different from default
	if !enabled {
		account, err = service.SetAccountEnabled(account.ID, userID, enabled)
		if err != nil {
			t.Fatalf("Failed to set initial enabled state: %v", err)
		}
	}

	return account
}

func TestProperty_AccountStatusSwitchIdempotency(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 20
	properties := gopter.NewProperties(parameters)

	// Property 5.1: Enabling an already enabled account keeps it enabled
	properties.Property("enabling_enabled_account_is_idempotent", prop.ForAll(
		func(userID uint) bool {
			db, cleanup := setupTestDB(t)
			defer cleanup()

			encryptionKey := []byte("test-encryption-key-32-bytes!!")
			service := NewAccountService(db, encryptionKey)

			// Create a test user first
			user := &models.User{Username: "testuser", PasswordHash: "hash"}
			db.Create(user)

			email := "test@example.com"
			account := createTestAccount(t, service, user.ID, email, true)

			// Enable the already enabled account multiple times
			for i := 0; i < 3; i++ {
				updatedAccount, err := service.EnableAccount(account.ID, user.ID)
				if err != nil {
					return false
				}
				if !updatedAccount.Enabled {
					return false
				}
			}

			// Verify final state
			finalAccount, err := service.GetAccountByID(account.ID)
			if err != nil {
				return false
			}

			return finalAccount.Enabled == true
		},
		gen.UIntRange(1, 1000),
	))

	// Property 5.2: Disabling an already disabled account keeps it disabled
	properties.Property("disabling_disabled_account_is_idempotent", prop.ForAll(
		func(userID uint) bool {
			db, cleanup := setupTestDB(t)
			defer cleanup()

			encryptionKey := []byte("test-encryption-key-32-bytes!!")
			service := NewAccountService(db, encryptionKey)

			// Create a test user first
			user := &models.User{Username: "testuser", PasswordHash: "hash"}
			db.Create(user)

			email := "test@example.com"
			account := createTestAccount(t, service, user.ID, email, false)

			// Disable the already disabled account multiple times
			for i := 0; i < 3; i++ {
				updatedAccount, err := service.DisableAccount(account.ID, user.ID)
				if err != nil {
					return false
				}
				if updatedAccount.Enabled {
					return false
				}
			}

			// Verify final state
			finalAccount, err := service.GetAccountByID(account.ID)
			if err != nil {
				return false
			}

			return finalAccount.Enabled == false
		},
		gen.UIntRange(1, 1000),
	))

	// Property 5.3: SetAccountEnabled with same value is idempotent
	properties.Property("set_account_enabled_same_value_is_idempotent", prop.ForAll(
		func(userID uint, initialEnabled bool) bool {
			db, cleanup := setupTestDB(t)
			defer cleanup()

			encryptionKey := []byte("test-encryption-key-32-bytes!!")
			service := NewAccountService(db, encryptionKey)

			// Create a test user first
			user := &models.User{Username: "testuser", PasswordHash: "hash"}
			db.Create(user)

			email := "test@example.com"
			account := createTestAccount(t, service, user.ID, email, initialEnabled)

			// Set to the same value multiple times
			for i := 0; i < 3; i++ {
				updatedAccount, err := service.SetAccountEnabled(account.ID, user.ID, initialEnabled)
				if err != nil {
					return false
				}
				if updatedAccount.Enabled != initialEnabled {
					return false
				}
			}

			// Verify final state matches initial
			finalAccount, err := service.GetAccountByID(account.ID)
			if err != nil {
				return false
			}

			return finalAccount.Enabled == initialEnabled
		},
		gen.UIntRange(1, 1000),
		gen.Bool(),
	))

	// Property 5.4: Status query returns correct value after switch
	properties.Property("status_query_returns_correct_value_after_switch", prop.ForAll(
		func(userID uint, targetEnabled bool) bool {
			db, cleanup := setupTestDB(t)
			defer cleanup()

			encryptionKey := []byte("test-encryption-key-32-bytes!!")
			service := NewAccountService(db, encryptionKey)

			// Create a test user first
			user := &models.User{Username: "testuser", PasswordHash: "hash"}
			db.Create(user)

			email := "test@example.com"
			// Start with opposite state
			account := createTestAccount(t, service, user.ID, email, !targetEnabled)

			// Switch to target state
			_, err := service.SetAccountEnabled(account.ID, user.ID, targetEnabled)
			if err != nil {
				return false
			}

			// Query and verify
			queriedAccount, err := service.GetAccountByID(account.ID)
			if err != nil {
				return false
			}

			return queriedAccount.Enabled == targetEnabled
		},
		gen.UIntRange(1, 1000),
		gen.Bool(),
	))

	properties.TestingRun(t)
}

// TestProperty_AccountStatusToggleConsistency tests that toggle operations are consistent
func TestProperty_AccountStatusToggleConsistency(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 20
	properties := gopter.NewProperties(parameters)

	// Property 5.5: Double toggle returns to original state
	properties.Property("double_toggle_returns_to_original_state", prop.ForAll(
		func(userID uint, initialEnabled bool) bool {
			db, cleanup := setupTestDB(t)
			defer cleanup()

			encryptionKey := []byte("test-encryption-key-32-bytes!!")
			service := NewAccountService(db, encryptionKey)

			// Create a test user first
			user := &models.User{Username: "testuser", PasswordHash: "hash"}
			db.Create(user)

			email := "test@example.com"
			account := createTestAccount(t, service, user.ID, email, initialEnabled)

			// Toggle twice
			_, err := service.ToggleAccountEnabled(account.ID, user.ID)
			if err != nil {
				return false
			}

			finalAccount, err := service.ToggleAccountEnabled(account.ID, user.ID)
			if err != nil {
				return false
			}

			// Should be back to original state
			return finalAccount.Enabled == initialEnabled
		},
		gen.UIntRange(1, 1000),
		gen.Bool(),
	))

	// Property 5.6: Single toggle inverts the state
	properties.Property("single_toggle_inverts_state", prop.ForAll(
		func(userID uint, initialEnabled bool) bool {
			db, cleanup := setupTestDB(t)
			defer cleanup()

			encryptionKey := []byte("test-encryption-key-32-bytes!!")
			service := NewAccountService(db, encryptionKey)

			// Create a test user first
			user := &models.User{Username: "testuser", PasswordHash: "hash"}
			db.Create(user)

			email := "test@example.com"
			account := createTestAccount(t, service, user.ID, email, initialEnabled)

			// Toggle once
			toggledAccount, err := service.ToggleAccountEnabled(account.ID, user.ID)
			if err != nil {
				return false
			}

			// Should be inverted
			return toggledAccount.Enabled == !initialEnabled
		},
		gen.UIntRange(1, 1000),
		gen.Bool(),
	))

	properties.TestingRun(t)
}
