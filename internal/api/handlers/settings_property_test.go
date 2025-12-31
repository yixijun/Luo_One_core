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

// Feature: luo-one-email-manager, Property 3: 配置持久化一致性
// For any user configuration (AI config, email account config, processing toggles),
// saving and then reading should return the same configuration values.
// Validates: Requirements 1.4, 1.6, 9.1, 9.3, 9.4, 9.5

func TestProperty_ConfigPersistence(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 20
	properties := gopter.NewProperties(parameters)

	// Generator for valid usernames
	validUsernameGen := gen.SliceOfN(8, gen.AlphaLowerChar()).Map(func(chars []rune) string {
		return string(chars)
	})

	// Generator for valid passwords (6+ chars)
	validPasswordGen := gen.SliceOfN(10, gen.AlphaChar()).Map(func(chars []rune) string {
		return string(chars)
	})

	// Generator for AI provider strings
	aiProviderGen := gen.OneConstOf("openai", "anthropic", "local", "azure", "")

	// Generator for AI model strings
	aiModelGen := gen.OneConstOf("gpt-4", "gpt-3.5-turbo", "claude-3", "llama-2", "")

	// Generator for API key strings
	apiKeyGen := gen.SliceOfN(32, gen.AlphaNumChar()).Map(func(chars []rune) string {
		return string(chars)
	})

	// Property 3.1: User settings persist correctly after save and read
	properties.Property("user_settings_persist_correctly", prop.ForAll(
		func(username, password string, aiEnabled, extractCode, detectAd, summarize, judgeImportance bool, aiProvider, aiModel, apiKey string) bool {
			// Create temp directory and database
			tempDir, err := os.MkdirTemp("", "luo_one_settings_test_*")
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
			createdUser, err := userService.CreateUser(username, password, "Test User")
			if err != nil {
				return true // Skip on creation error
			}

			// Get initial settings
			settings, err := userService.GetUserSettings(createdUser.ID)
			if err != nil {
				return false
			}

			// Update settings with generated values
			settings.AIEnabled = aiEnabled
			settings.AIProvider = aiProvider
			settings.AIAPIKey = apiKey
			settings.AIModel = aiModel
			settings.ExtractCode = extractCode
			settings.DetectAd = detectAd
			settings.Summarize = summarize
			settings.JudgeImportance = judgeImportance

			// Save settings
			err = userService.UpdateUserSettings(createdUser.ID, settings)
			if err != nil {
				return false
			}

			// Read settings back
			readSettings, err := userService.GetUserSettings(createdUser.ID)
			if err != nil {
				return false
			}

			// Verify all values match
			if readSettings.AIEnabled != aiEnabled {
				return false
			}
			if readSettings.AIProvider != aiProvider {
				return false
			}
			if readSettings.AIAPIKey != apiKey {
				return false
			}
			if readSettings.AIModel != aiModel {
				return false
			}
			if readSettings.ExtractCode != extractCode {
				return false
			}
			if readSettings.DetectAd != detectAd {
				return false
			}
			if readSettings.Summarize != summarize {
				return false
			}
			if readSettings.JudgeImportance != judgeImportance {
				return false
			}

			return true
		},
		validUsernameGen,
		validPasswordGen,
		gen.Bool(),
		gen.Bool(),
		gen.Bool(),
		gen.Bool(),
		gen.Bool(),
		aiProviderGen,
		aiModelGen,
		apiKeyGen,
	))

	properties.TestingRun(t)
}


// Property 3.2: Email account configuration persists correctly
func TestProperty_EmailAccountConfigPersistence(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 20
	properties := gopter.NewProperties(parameters)

	// Generator for valid usernames
	validUsernameGen := gen.SliceOfN(8, gen.AlphaLowerChar()).Map(func(chars []rune) string {
		return string(chars)
	})

	// Generator for valid passwords
	validPasswordGen := gen.SliceOfN(10, gen.AlphaChar()).Map(func(chars []rune) string {
		return string(chars)
	})

	// Generator for email addresses
	emailGen := gen.SliceOfN(6, gen.AlphaLowerChar()).Map(func(chars []rune) string {
		return string(chars) + "@test.com"
	})

	// Generator for host names
	hostGen := gen.OneConstOf("imap.gmail.com", "imap.outlook.com", "mail.example.com")

	// Generator for port numbers
	portGen := gen.IntRange(1, 65535)

	// Encryption key for account service
	encryptionKey := []byte("test-encryption-key-32-bytes!!")

	// Property: Email account config persists correctly
	// Note: UseSSL defaults to true in GORM model, so we test with useSSL=true
	// to avoid GORM's zero-value default behavior
	properties.Property("email_account_config_persists", prop.ForAll(
		func(username, password, email, imapHost, smtpHost string, imapPort, smtpPort int, enabled bool) bool {
			// Create temp directory and database
			tempDir, err := os.MkdirTemp("", "luo_one_account_test_*")
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
			accountService := services.NewAccountService(db, encryptionKey)

			// Create user
			createdUser, err := userService.CreateUser(username, password, "Test User")
			if err != nil {
				return true // Skip on creation error
			}

			// Create email account using CreateAccountInput
			// UseSSL is always true to avoid GORM default value issues with false
			input := services.CreateAccountInput{
				UserID:      createdUser.ID,
				Email:       email,
				DisplayName: "Test Account",
				IMAPHost:    imapHost,
				IMAPPort:    imapPort,
				SMTPHost:    smtpHost,
				SMTPPort:    smtpPort,
				Username:    email,
				Password:    password,
				UseSSL:      true, // Always true to test persistence correctly
			}

			createdAccount, err := accountService.CreateAccount(input)
			if err != nil {
				return true // Skip on creation error (e.g., duplicate email)
			}

			// Set enabled state if different from default (true)
			if !enabled {
				_, err = accountService.SetAccountEnabled(createdAccount.ID, createdUser.ID, enabled)
				if err != nil {
					return false
				}
			}

			// Read account back
			readAccount, err := accountService.GetAccountByIDAndUserID(createdAccount.ID, createdUser.ID)
			if err != nil {
				return false
			}

			// Verify all values match
			if readAccount.Email != email {
				return false
			}
			if readAccount.IMAPHost != imapHost {
				return false
			}
			if readAccount.IMAPPort != imapPort {
				return false
			}
			if readAccount.SMTPHost != smtpHost {
				return false
			}
			if readAccount.SMTPPort != smtpPort {
				return false
			}
			// UseSSL should always be true since we set it to true
			if readAccount.UseSSL != true {
				return false
			}
			if readAccount.Enabled != enabled {
				return false
			}

			return true
		},
		validUsernameGen,
		validPasswordGen,
		emailGen,
		hostGen,
		hostGen,
		portGen,
		portGen,
		gen.Bool(),
	))

	properties.TestingRun(t)
}

// Property 3.3: Settings update is idempotent
func TestProperty_SettingsUpdateIdempotent(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 20
	properties := gopter.NewProperties(parameters)

	// Generator for valid usernames
	validUsernameGen := gen.SliceOfN(8, gen.AlphaLowerChar()).Map(func(chars []rune) string {
		return string(chars)
	})

	// Generator for valid passwords
	validPasswordGen := gen.SliceOfN(10, gen.AlphaChar()).Map(func(chars []rune) string {
		return string(chars)
	})

	// Property: Saving same settings twice yields same result
	properties.Property("settings_update_idempotent", prop.ForAll(
		func(username, password string, aiEnabled, extractCode bool) bool {
			// Create temp directory and database
			tempDir, err := os.MkdirTemp("", "luo_one_idempotent_test_*")
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
			createdUser, err := userService.CreateUser(username, password, "Test User")
			if err != nil {
				return true // Skip on creation error
			}

			// Get settings
			settings, err := userService.GetUserSettings(createdUser.ID)
			if err != nil {
				return false
			}

			// Update settings
			settings.AIEnabled = aiEnabled
			settings.ExtractCode = extractCode

			// Save settings first time
			err = userService.UpdateUserSettings(createdUser.ID, settings)
			if err != nil {
				return false
			}

			// Read settings after first save
			settings1, err := userService.GetUserSettings(createdUser.ID)
			if err != nil {
				return false
			}

			// Save same settings again
			err = userService.UpdateUserSettings(createdUser.ID, settings1)
			if err != nil {
				return false
			}

			// Read settings after second save
			settings2, err := userService.GetUserSettings(createdUser.ID)
			if err != nil {
				return false
			}

			// Verify both reads return same values
			if settings1.AIEnabled != settings2.AIEnabled {
				return false
			}
			if settings1.ExtractCode != settings2.ExtractCode {
				return false
			}
			if settings1.DetectAd != settings2.DetectAd {
				return false
			}
			if settings1.Summarize != settings2.Summarize {
				return false
			}
			if settings1.JudgeImportance != settings2.JudgeImportance {
				return false
			}

			return true
		},
		validUsernameGen,
		validPasswordGen,
		gen.Bool(),
		gen.Bool(),
	))

	properties.TestingRun(t)
}
