package ai

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

var (
	// ErrNotConfigured indicates the AI client is not configured
	ErrNotConfigured = errors.New("AI client not configured")
	// ErrAPICallFailed indicates the AI API call failed
	ErrAPICallFailed = errors.New("AI API call failed")
	// ErrInvalidResponse indicates an invalid response from the AI API
	ErrInvalidResponse = errors.New("invalid AI API response")
	// ErrUnsupportedProvider indicates an unsupported AI provider
	ErrUnsupportedProvider = errors.New("unsupported AI provider")
)

// Provider represents an AI provider
type Provider string

const (
	// ProviderOpenAI represents OpenAI API
	ProviderOpenAI Provider = "openai"
	// ProviderAzure represents Azure OpenAI API
	ProviderAzure Provider = "azure"
	// ProviderClaude represents Anthropic Claude API
	ProviderClaude Provider = "claude"
	// ProviderCustom represents a custom API endpoint
	ProviderCustom Provider = "custom"
)

// Client handles AI API communication for email processing
type Client struct {
	provider   Provider
	apiKey     string
	model      string
	baseURL    string
	httpClient *http.Client
	configured bool
}

// NewClient creates a new AI Client instance
func NewClient() *Client {
	return &Client{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Configure configures the AI client with provider settings
func (c *Client) Configure(provider, apiKey, model string) {
	c.ConfigureWithBaseURL(provider, apiKey, model, "")
}

// ConfigureWithBaseURL configures the AI client with provider settings and custom base URL
func (c *Client) ConfigureWithBaseURL(provider, apiKey, model, baseURL string) {
	c.provider = Provider(strings.ToLower(provider))
	c.apiKey = apiKey
	c.model = model
	c.configured = apiKey != ""

	// Use custom base URL if provided
	if baseURL != "" {
		c.baseURL = strings.TrimSuffix(baseURL, "/")
	} else {
		// Set default base URLs based on provider
		switch c.provider {
		case ProviderOpenAI:
			c.baseURL = "https://api.openai.com/v1"
			if c.model == "" {
				c.model = "gpt-3.5-turbo"
			}
		case ProviderClaude:
			c.baseURL = "https://api.anthropic.com/v1"
			if c.model == "" {
				c.model = "claude-3-haiku-20240307"
			}
		case ProviderAzure:
			// Azure requires custom endpoint
			if c.model == "" {
				c.model = "gpt-35-turbo"
			}
		default:
			c.provider = ProviderOpenAI
			c.baseURL = "https://api.openai.com/v1"
		}
	}
}

// SetBaseURL sets a custom base URL for the API
func (c *Client) SetBaseURL(url string) {
	c.baseURL = strings.TrimSuffix(url, "/")
}

// IsConfigured returns whether the client is configured
func (c *Client) IsConfigured() bool {
	return c.configured && c.apiKey != ""
}


// ChatMessage represents a message in a chat conversation
type ChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// ChatRequest represents a chat completion request
type ChatRequest struct {
	Model       string        `json:"model"`
	Messages    []ChatMessage `json:"messages"`
	MaxTokens   int           `json:"max_tokens,omitempty"`
	Temperature float64       `json:"temperature,omitempty"`
}

// ChatResponse represents a chat completion response
type ChatResponse struct {
	ID      string `json:"id"`
	Choices []struct {
		Message ChatMessage `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// sendChatRequest sends a chat completion request to the AI API
func (c *Client) sendChatRequest(messages []ChatMessage) (string, error) {
	if !c.IsConfigured() {
		return "", ErrNotConfigured
	}

	request := ChatRequest{
		Model:       c.model,
		Messages:    messages,
		MaxTokens:   500,
		Temperature: 0.3,
	}

	body, err := json.Marshal(request)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrAPICallFailed, err)
	}

	url := c.baseURL + "/chat/completions"
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrAPICallFailed, err)
	}

	req.Header.Set("Content-Type", "application/json")

	// Set authorization header based on provider
	switch c.provider {
	case ProviderClaude:
		req.Header.Set("x-api-key", c.apiKey)
		req.Header.Set("anthropic-version", "2023-06-01")
	default:
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrAPICallFailed, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrAPICallFailed, err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%w: status %d: %s", ErrAPICallFailed, resp.StatusCode, string(respBody))
	}

	var chatResp ChatResponse
	if err := json.Unmarshal(respBody, &chatResp); err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidResponse, err)
	}

	if chatResp.Error != nil {
		return "", fmt.Errorf("%w: %s", ErrAPICallFailed, chatResp.Error.Message)
	}

	if len(chatResp.Choices) == 0 {
		return "", ErrInvalidResponse
	}

	return chatResp.Choices[0].Message.Content, nil
}


// ExtractVerificationCode uses AI to extract verification codes from email content
func (c *Client) ExtractVerificationCode(content string) (string, error) {
	return c.ExtractVerificationCodeWithPrompt(content, "")
}

// ExtractVerificationCodeWithPrompt uses AI to extract verification codes with custom prompt
func (c *Client) ExtractVerificationCodeWithPrompt(content, customPrompt string) (string, error) {
	if content == "" {
		return "", nil
	}

	// Truncate content if too long
	if len(content) > 2000 {
		content = content[:2000]
	}

	systemPrompt := customPrompt
	if systemPrompt == "" {
		systemPrompt = `You are a verification code extractor. Extract the verification code from the email content.
Rules:
- Only extract codes that are 4-8 characters long
- Codes can be numeric (e.g., 123456) or alphanumeric (e.g., ABC123)
- Return ONLY the code, nothing else
- If no verification code is found, return "NONE"
- Do not include any explanation or additional text`
	}

	messages := []ChatMessage{
		{
			Role:    "system",
			Content: systemPrompt,
		},
		{
			Role:    "user",
			Content: "Extract the verification code from this email:\n\n" + content,
		},
	}

	response, err := c.sendChatRequest(messages)
	if err != nil {
		return "", err
	}

	response = strings.TrimSpace(response)
	if response == "NONE" || response == "" {
		return "", nil
	}

	// Validate the extracted code
	if len(response) >= 4 && len(response) <= 8 {
		return response, nil
	}

	return "", nil
}

// DetectAd uses AI to determine if an email is an advertisement
func (c *Client) DetectAd(subject, content string) (bool, error) {
	return c.DetectAdWithPrompt(subject, content, "")
}

// DetectAdWithPrompt uses AI to determine if an email is an advertisement with custom prompt
func (c *Client) DetectAdWithPrompt(subject, content, customPrompt string) (bool, error) {
	// Truncate content if too long
	if len(content) > 1500 {
		content = content[:1500]
	}

	systemPrompt := customPrompt
	if systemPrompt == "" {
		systemPrompt = `You are an email classifier. Determine if the email is an advertisement or promotional content.
Rules:
- Respond with only "YES" if it's an advertisement/promotional email
- Respond with only "NO" if it's not an advertisement
- Consider: promotional offers, sales, marketing campaigns, newsletters as advertisements
- Personal emails, transactional emails, and important notifications are NOT advertisements`
	}

	messages := []ChatMessage{
		{
			Role:    "system",
			Content: systemPrompt,
		},
		{
			Role:    "user",
			Content: fmt.Sprintf("Subject: %s\n\nContent:\n%s", subject, content),
		},
	}

	response, err := c.sendChatRequest(messages)
	if err != nil {
		return false, err
	}

	response = strings.ToUpper(strings.TrimSpace(response))
	return response == "YES", nil
}

// Summarize uses AI to create a summary of the email content
func (c *Client) Summarize(content string) (string, error) {
	return c.SummarizeWithPrompt(content, "")
}

// SummarizeWithPrompt uses AI to create a summary with custom prompt
func (c *Client) SummarizeWithPrompt(content, customPrompt string) (string, error) {
	if content == "" {
		return "", nil
	}

	// Truncate content if too long
	if len(content) > 3000 {
		content = content[:3000]
	}

	systemPrompt := customPrompt
	if systemPrompt == "" {
		systemPrompt = `You are an email summarizer. Create a brief, concise summary of the email content.
Rules:
- Keep the summary under 200 characters
- Focus on the main point or action required
- Use the same language as the original email
- Be direct and informative`
	}

	messages := []ChatMessage{
		{
			Role:    "system",
			Content: systemPrompt,
		},
		{
			Role:    "user",
			Content: "Summarize this email:\n\n" + content,
		},
	}

	response, err := c.sendChatRequest(messages)
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(response), nil
}

// JudgeImportance uses AI to determine the importance level of an email
func (c *Client) JudgeImportance(subject, content, from string) (string, error) {
	return c.JudgeImportanceWithPrompt(subject, content, from, "")
}

// JudgeImportanceWithPrompt uses AI to determine importance with custom prompt
func (c *Client) JudgeImportanceWithPrompt(subject, content, from, customPrompt string) (string, error) {
	// Truncate content if too long
	if len(content) > 1500 {
		content = content[:1500]
	}

	systemPrompt := customPrompt
	if systemPrompt == "" {
		systemPrompt = `You are an email importance classifier. Determine the importance level of the email.
Rules:
- Respond with ONLY one of: "critical", "high", "medium", "low"
- critical: Urgent matters, security alerts, payment issues, legal notices
- high: Important business matters, interviews, contracts, deadlines
- medium: Regular correspondence, updates, general information
- low: Newsletters, promotions, automated notifications, spam-like content`
	}

	messages := []ChatMessage{
		{
			Role:    "system",
			Content: systemPrompt,
		},
		{
			Role:    "user",
			Content: fmt.Sprintf("From: %s\nSubject: %s\n\nContent:\n%s", from, subject, content),
		},
	}

	response, err := c.sendChatRequest(messages)
	if err != nil {
		return "medium", err
	}

	response = strings.ToLower(strings.TrimSpace(response))

	// Validate response
	validLevels := map[string]bool{
		"critical": true,
		"high":     true,
		"medium":   true,
		"low":      true,
	}

	if validLevels[response] {
		return response, nil
	}

	return "medium", nil
}

// ProcessEmail processes an email with all AI functions
func (c *Client) ProcessEmail(subject, content, from string, extractCode, detectAd, summarize, judgeImportance bool) (map[string]interface{}, error) {
	result := make(map[string]interface{})

	if extractCode {
		code, err := c.ExtractVerificationCode(content)
		if err == nil {
			result["verification_code"] = code
		}
	}

	if detectAd {
		isAd, err := c.DetectAd(subject, content)
		if err == nil {
			result["is_ad"] = isAd
		}
	}

	if summarize {
		summary, err := c.Summarize(content)
		if err == nil {
			result["summary"] = summary
		}
	}

	if judgeImportance {
		importance, err := c.JudgeImportance(subject, content, from)
		if err == nil {
			result["importance"] = importance
		}
	}

	return result, nil
}
