package functions

import (
	"errors"
	"time"

	"github.com/luo-one/core/internal/database/models"
	"github.com/luo-one/core/internal/functions/ai"
	"github.com/luo-one/core/internal/functions/local"
	"github.com/luo-one/core/internal/user"
	"gorm.io/gorm"
)

var (
	// ErrProcessingFailed indicates email processing failed
	ErrProcessingFailed = errors.New("email processing failed")
	// ErrEmailNotFound indicates the email was not found
	ErrEmailNotFound = errors.New("email not found")
	// ErrSettingsNotFound indicates user settings were not found
	ErrSettingsNotFound = errors.New("user settings not found")
)

// ProcessorMode represents the processing mode (AI or local)
type ProcessorMode string

const (
	// ProcessorModeAI uses AI for email processing
	ProcessorModeAI ProcessorMode = "ai"
	// ProcessorModeLocal uses local methods for email processing
	ProcessorModeLocal ProcessorMode = "local"
)

// ProcessingConfig holds the configuration for email processing
type ProcessingConfig struct {
	Mode            ProcessorMode
	ExtractCode     bool
	DetectAd        bool
	Summarize       bool
	JudgeImportance bool
	AIProvider      string
	AIAPIKey        string
	AIModel         string
}

// EmailContent represents the content to be processed
type EmailContent struct {
	Subject  string
	Body     string
	HTMLBody string
	From     string
	To       []string
}

// ProcessingResult represents the result of email processing
type ProcessingResult struct {
	VerificationCode string
	IsAd             bool
	Summary          string
	Importance       string
	ProcessedBy      string
	ProcessedAt      time.Time
}

// Processor handles email processing with AI or local methods
type Processor struct {
	db          *gorm.DB
	aiClient    *ai.Client
	userStorage *user.Storage
}

// NewProcessor creates a new Processor instance
func NewProcessor(db *gorm.DB, userManager *user.Manager) *Processor {
	return &Processor{
		db:          db,
		aiClient:    ai.NewClient(),
		userStorage: user.NewStorage(userManager),
	}
}


// GetProcessingConfig retrieves the processing configuration for a user
func (p *Processor) GetProcessingConfig(userID uint) (*ProcessingConfig, error) {
	var settings models.UserSettings
	if err := p.db.Where("user_id = ?", userID).First(&settings).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// Return default config if no settings found
			return &ProcessingConfig{
				Mode:            ProcessorModeLocal,
				ExtractCode:     true,
				DetectAd:        true,
				Summarize:       false,
				JudgeImportance: true,
			}, nil
		}
		return nil, err
	}

	config := &ProcessingConfig{
		ExtractCode:     settings.ExtractCode,
		DetectAd:        settings.DetectAd,
		Summarize:       settings.Summarize,
		JudgeImportance: settings.JudgeImportance,
	}

	// Determine processing mode based on AI settings
	if settings.AIEnabled && settings.AIAPIKey != "" {
		config.Mode = ProcessorModeAI
		config.AIProvider = settings.AIProvider
		config.AIAPIKey = settings.AIAPIKey
		config.AIModel = settings.AIModel
	} else {
		config.Mode = ProcessorModeLocal
	}

	return config, nil
}

// ProcessEmail processes an email based on user configuration
func (p *Processor) ProcessEmail(userID uint, email *models.Email, content EmailContent) (*ProcessingResult, error) {
	config, err := p.GetProcessingConfig(userID)
	if err != nil {
		return nil, err
	}

	return p.ProcessEmailWithConfig(config, content)
}

// ProcessEmailWithConfig processes an email with the given configuration
func (p *Processor) ProcessEmailWithConfig(config *ProcessingConfig, content EmailContent) (*ProcessingResult, error) {
	result := &ProcessingResult{
		ProcessedAt: time.Now(),
		Importance:  string(models.ImportanceMedium), // Default importance
	}

	// Determine which processor to use
	if config.Mode == ProcessorModeAI {
		result.ProcessedBy = string(ProcessorModeAI)
		return p.processWithAI(config, content, result)
	}

	result.ProcessedBy = string(ProcessorModeLocal)
	return p.processWithLocal(config, content, result)
}

// processWithAI processes email using AI
func (p *Processor) processWithAI(config *ProcessingConfig, content EmailContent, result *ProcessingResult) (*ProcessingResult, error) {
	// Configure AI client
	p.aiClient.Configure(config.AIProvider, config.AIAPIKey, config.AIModel)

	// Get combined content for processing
	textContent := content.Body
	if textContent == "" {
		textContent = content.HTMLBody
	}

	// Extract verification code
	if config.ExtractCode {
		code, err := p.aiClient.ExtractVerificationCode(textContent)
		if err == nil {
			result.VerificationCode = code
		}
	}

	// Detect advertisement
	if config.DetectAd {
		isAd, err := p.aiClient.DetectAd(content.Subject, textContent)
		if err == nil {
			result.IsAd = isAd
		}
	}

	// Summarize content
	if config.Summarize {
		summary, err := p.aiClient.Summarize(textContent)
		if err == nil {
			result.Summary = summary
		}
	}

	// Judge importance
	if config.JudgeImportance {
		importance, err := p.aiClient.JudgeImportance(content.Subject, textContent, content.From)
		if err == nil {
			result.Importance = importance
		}
	}

	return result, nil
}

// processWithLocal processes email using local methods
func (p *Processor) processWithLocal(config *ProcessingConfig, content EmailContent, result *ProcessingResult) (*ProcessingResult, error) {
	// Get combined content for processing
	textContent := content.Body
	if textContent == "" {
		textContent = content.HTMLBody
	}

	// Extract verification code
	if config.ExtractCode {
		result.VerificationCode = local.ExtractVerificationCode(textContent)
	}

	// Detect advertisement
	if config.DetectAd {
		result.IsAd = local.DetectAd(content.Subject, textContent)
	}

	// Summarize content (local summarization is limited)
	if config.Summarize {
		result.Summary = local.Summarize(textContent)
	}

	// Judge importance
	if config.JudgeImportance {
		result.Importance = local.JudgeImportance(content.Subject, textContent, content.From)
	}

	return result, nil
}


// SaveProcessingResult saves the processing result to database and file system
func (p *Processor) SaveProcessingResult(userID, accountID uint, email *models.Email, result *ProcessingResult) error {
	// Create or update processed result in database
	processedResult := &models.ProcessedResult{
		EmailID:          email.ID,
		VerificationCode: result.VerificationCode,
		IsAd:             result.IsAd,
		Summary:          result.Summary,
		Importance:       result.Importance,
		ProcessedBy:      result.ProcessedBy,
		ProcessedAt:      result.ProcessedAt,
	}

	// Check if result already exists
	var existing models.ProcessedResult
	if err := p.db.Where("email_id = ?", email.ID).First(&existing).Error; err == nil {
		// Update existing
		processedResult.ID = existing.ID
		if err := p.db.Save(processedResult).Error; err != nil {
			return err
		}
	} else {
		// Create new
		if err := p.db.Create(processedResult).Error; err != nil {
			return err
		}
	}

	// Save to file system
	fileResult := map[string]interface{}{
		"email_id":          email.ID,
		"message_id":        email.MessageID,
		"verification_code": result.VerificationCode,
		"is_ad":             result.IsAd,
		"summary":           result.Summary,
		"importance":        result.Importance,
		"processed_by":      result.ProcessedBy,
		"processed_at":      result.ProcessedAt,
	}

	_, err := p.userStorage.SaveProcessedResult(userID, accountID, email.MessageID, fileResult)
	return err
}

// ProcessAndSaveEmail processes an email and saves the result
func (p *Processor) ProcessAndSaveEmail(userID, accountID uint, email *models.Email) (*ProcessingResult, error) {
	content := EmailContent{
		Subject:  email.Subject,
		Body:     email.Body,
		HTMLBody: email.HTMLBody,
		From:     email.FromAddr,
	}

	result, err := p.ProcessEmail(userID, email, content)
	if err != nil {
		return nil, err
	}

	if err := p.SaveProcessingResult(userID, accountID, email, result); err != nil {
		return nil, err
	}

	return result, nil
}

// GetProcessedResult retrieves the processed result for an email
func (p *Processor) GetProcessedResult(emailID uint) (*models.ProcessedResult, error) {
	var result models.ProcessedResult
	if err := p.db.Where("email_id = ?", emailID).First(&result).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &result, nil
}

// IsAIMode checks if the processor is configured to use AI mode for a user
func (p *Processor) IsAIMode(userID uint) (bool, error) {
	config, err := p.GetProcessingConfig(userID)
	if err != nil {
		return false, err
	}
	return config.Mode == ProcessorModeAI, nil
}
