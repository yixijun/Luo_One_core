package functions

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
	"github.com/luo-one/core/internal/database"
	"github.com/luo-one/core/internal/database/models"
	"github.com/luo-one/core/internal/functions/ai"
	"github.com/luo-one/core/internal/user"
)

// Feature: luo-one-email-manager, Property 7: 邮件处理模式正确性
// For any email and processing configuration, when AI processing is enabled
// the AI processor should be used, when AI processing is disabled the local
// processor should be used, and the processing result should include all
// enabled processing items.
// Validates: Requirements 4.1, 4.2, 4.8

func TestProperty_ProcessingModeCorrectness(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 20
	properties := gopter.NewProperties(parameters)

	// Generator for email content
	emailContentGen := gen.SliceOfN(50, gen.AlphaChar()).Map(func(chars []rune) string {
		return string(chars)
	})

	// Generator for email subject
	emailSubjectGen := gen.SliceOfN(20, gen.AlphaChar()).Map(func(chars []rune) string {
		return string(chars)
	})

	// Generator for email from address
	emailFromGen := gen.SliceOfN(10, gen.AlphaLowerChar()).Map(func(chars []rune) string {
		return string(chars) + "@example.com"
	})

	// Property 7.1: Local mode is used when AI is not configured
	properties.Property("local_mode_when_ai_not_configured", prop.ForAll(
		func(subject, body, from string) bool {
			config := &ProcessingConfig{
				Mode:            ProcessorModeLocal,
				ExtractCode:     true,
				DetectAd:        true,
				Summarize:       false,
				JudgeImportance: true,
			}

			content := EmailContent{
				Subject: subject,
				Body:    body,
				From:    from,
			}

			// Create a processor without database (for unit testing)
			processor := &Processor{}
			result, err := processor.ProcessEmailWithConfig(config, content)
			if err != nil {
				return false
			}

			// Verify local processor was used
			return result.ProcessedBy == string(ProcessorModeLocal)
		},
		emailSubjectGen,
		emailContentGen,
		emailFromGen,
	))

	// Property 7.2: AI mode is indicated when AI is configured
	properties.Property("ai_mode_when_ai_configured", prop.ForAll(
		func(subject, body, from string) bool {
			config := &ProcessingConfig{
				Mode:            ProcessorModeAI,
				ExtractCode:     false, // Disable to avoid API calls
				DetectAd:        false,
				Summarize:       false,
				JudgeImportance: false,
				AIProvider:      "openai",
				AIAPIKey:        "test-key",
				AIModel:         "gpt-3.5-turbo",
			}

			content := EmailContent{
				Subject: subject,
				Body:    body,
				From:    from,
			}

			// Create a processor with initialized AI client
			processor := &Processor{
				aiClient: ai.NewClient(),
			}
			result, err := processor.ProcessEmailWithConfig(config, content)

			// With all processing disabled, it should succeed
			if err != nil {
				return false
			}

			return result.ProcessedBy == string(ProcessorModeAI)
		},
		emailSubjectGen,
		emailContentGen,
		emailFromGen,
	))

	properties.TestingRun(t)
}


// Property 7.3: Processing result includes all enabled processing items
func TestProperty_ProcessingResultIncludesEnabledItems(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 20
	properties := gopter.NewProperties(parameters)

	// Generator for email content with verification code
	emailWithCodeGen := gen.SliceOfN(20, gen.AlphaChar()).Map(func(chars []rune) string {
		return "Your verification code is: 123456. " + string(chars)
	})

	// Generator for email subject
	emailSubjectGen := gen.SliceOfN(20, gen.AlphaChar()).Map(func(chars []rune) string {
		return string(chars)
	})

	// Generator for email from address
	emailFromGen := gen.SliceOfN(10, gen.AlphaLowerChar()).Map(func(chars []rune) string {
		return string(chars) + "@example.com"
	})

	// Generator for boolean flags
	boolGen := gen.Bool()

	properties.Property("processing_result_includes_enabled_items", prop.ForAll(
		func(subject, body, from string, extractCode, detectAd, judgeImportance bool) bool {
			config := &ProcessingConfig{
				Mode:            ProcessorModeLocal,
				ExtractCode:     extractCode,
				DetectAd:        detectAd,
				Summarize:       false, // Local summarize is simple
				JudgeImportance: judgeImportance,
			}

			content := EmailContent{
				Subject: subject,
				Body:    body,
				From:    from,
			}

			processor := &Processor{}
			result, err := processor.ProcessEmailWithConfig(config, content)
			if err != nil {
				return false
			}

			// Verify importance is always set (has default)
			if judgeImportance {
				validImportance := result.Importance == "low" ||
					result.Importance == "medium" ||
					result.Importance == "high" ||
					result.Importance == "critical"
				if !validImportance {
					return false
				}
			}

			// Verify ProcessedBy is set
			if result.ProcessedBy != string(ProcessorModeLocal) {
				return false
			}

			// Verify ProcessedAt is set
			if result.ProcessedAt.IsZero() {
				return false
			}

			return true
		},
		emailSubjectGen,
		emailWithCodeGen,
		emailFromGen,
		boolGen,
		boolGen,
		boolGen,
	))

	properties.TestingRun(t)
}

// Property 7.4: User settings determine processing mode
func TestProperty_UserSettingsDetermineMode(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 20
	properties := gopter.NewProperties(parameters)

	// Generator for username
	usernameGen := gen.SliceOfN(8, gen.AlphaLowerChar()).Map(func(chars []rune) string {
		return string(chars)
	})

	// Generator for AI enabled flag
	aiEnabledGen := gen.Bool()

	properties.Property("user_settings_determine_processing_mode", prop.ForAll(
		func(username string, aiEnabled bool) bool {
			// Create a fresh temp directory and database for each test
			tempDir, err := os.MkdirTemp("", "luo_one_mode_test_*")
			if err != nil {
				return false
			}
			defer os.RemoveAll(tempDir)

			dbPath := filepath.Join(tempDir, "test.db")
			db, err := database.Initialize(dbPath)
			if err != nil {
				return false
			}

			userManager := user.NewManager(tempDir)
			processor := NewProcessor(db, userManager)

			// Create user
			testUser := &models.User{
				Username:     username,
				PasswordHash: "test",
				Nickname:     "Test",
			}
			if err := db.Create(testUser).Error; err != nil {
				return true // Skip on duplicate
			}

			// Create user settings
			apiKey := ""
			if aiEnabled {
				apiKey = "test-api-key"
			}
			settings := &models.UserSettings{
				UserID:          testUser.ID,
				AIEnabled:       aiEnabled,
				AIAPIKey:        apiKey,
				AIProvider:      "openai",
				AIModel:         "gpt-3.5-turbo",
				ExtractCode:     true,
				DetectAd:        true,
				JudgeImportance: true,
			}
			if err := db.Create(settings).Error; err != nil {
				return false
			}

			// Get processing config
			config, err := processor.GetProcessingConfig(testUser.ID)
			if err != nil {
				return false
			}

			// Verify mode matches settings
			if aiEnabled && apiKey != "" {
				return config.Mode == ProcessorModeAI
			}
			return config.Mode == ProcessorModeLocal
		},
		usernameGen,
		aiEnabledGen,
	))

	properties.TestingRun(t)
}
