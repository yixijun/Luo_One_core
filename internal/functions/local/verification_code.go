package local

import (
	"regexp"
	"sort"
	"strings"
)

// Common verification code patterns - ordered by specificity (most specific first)
var verificationCodePatterns = []*regexp.Regexp{
	// Chinese patterns for verification codes (highest priority)
	regexp.MustCompile(`(?i)(?:验证码|校验码|确认码|动态码|安全码|授权码|登录码|登陆码)[：:\s]*([A-Za-z0-9]{4,8})`),
	// Pattern: code in brackets with Chinese keyword
	regexp.MustCompile(`(?i)(?:验证码|校验码|确认码)[：:\s]*[\[【\(]([A-Za-z0-9]{4,8})[\]】\)]`),
	// English verification code patterns
	regexp.MustCompile(`(?i)(?:verification\s*code|security\s*code|confirmation\s*code)[：:\s]*([A-Za-z0-9]{4,8})`),
	// Pattern: "Your code is: 123456"
	regexp.MustCompile(`(?i)(?:your\s+)?(?:verification\s+)?(?:code|pin|otp)\s+(?:is|:)\s*([A-Za-z0-9]{4,8})`),
	// Pattern: "123456 is your verification code"
	regexp.MustCompile(`(?i)([A-Za-z0-9]{4,8})\s+(?:is\s+)?(?:your\s+)?(?:verification\s*)?(?:code|pin|otp)`),
	// Pattern: code in brackets with English keyword
	regexp.MustCompile(`(?i)(?:code|pin|otp)[：:\s]*[\[【\(]([A-Za-z0-9]{4,8})[\]】\)]`),
}

// Fallback pattern for standalone codes (only used when email is confirmed to be verification-related)
var standaloneCodePattern = regexp.MustCompile(`(?:^|[\s\p{P}])([A-Za-z0-9]{4,8})(?:[\s\p{P}]|$)`)

// Keywords that indicate an email contains a verification code
var verificationKeywords = []string{
	"验证码", "校验码", "确认码", "动态码", "安全码", "授权码", "登录码", "登陆码",
	"verification code", "security code", "confirmation code", "login code",
	"one-time password", "one time password", "otp", "2fa", "two-factor",
	"verify your", "confirm your", "验证您的", "确认您的",
}

// Keywords that indicate an email is NOT about verification codes (promotional/marketing)
var nonVerificationKeywords = []string{
	"sale", "discount", "offer", "promotion", "promo", "deal", "save",
	"clearance", "limited time", "special offer", "buy now", "shop now",
	"unsubscribe", "newsletter", "marketing", "advertisement",
	"促销", "优惠", "折扣", "特价", "限时", "抢购", "活动", "广告",
	"年终", "年末", "新年", "圣诞", "黑五", "双十一", "双十二",
}

// CodeCandidate represents a potential verification code with its confidence score
type CodeCandidate struct {
	Code       string
	Confidence float64
	Position   int
}

// ExtractVerificationCode extracts verification codes from email content using regex
// Returns the most likely verification code found, or empty string if none found
func ExtractVerificationCode(content string) string {
	if content == "" {
		return ""
	}

	// Normalize content
	content = normalizeContent(content)
	lowerContent := strings.ToLower(content)

	// First check if this looks like a verification code email
	if !looksLikeVerificationEmail(lowerContent) {
		return ""
	}

	var candidates []CodeCandidate

	// Try each pattern
	for i, pattern := range verificationCodePatterns {
		matches := pattern.FindAllStringSubmatchIndex(content, -1)
		for _, match := range matches {
			if len(match) >= 4 {
				code := content[match[2]:match[3]]
				code = strings.TrimSpace(code)

				// Validate the code
				if isValidCode(code) {
					// Higher confidence for earlier patterns (more specific)
					confidence := 1.0 - float64(i)*0.1
					candidates = append(candidates, CodeCandidate{
						Code:       code,
						Confidence: confidence,
						Position:   match[0],
					})
				}
			}
		}
	}

	// If no candidates found with specific patterns, try standalone pattern
	// Only for emails that strongly look like verification emails
	if len(candidates) == 0 && stronglyLooksLikeVerificationEmail(lowerContent) {
		matches := standaloneCodePattern.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) >= 2 {
				code := strings.TrimSpace(match[1])
				if isValidCode(code) && looksLikeCode(code) {
					candidates = append(candidates, CodeCandidate{
						Code:       code,
						Confidence: 0.5,
						Position:   0,
					})
				}
			}
		}
	}

	if len(candidates) == 0 {
		return ""
	}

	// Sort by confidence (descending), then by position (ascending)
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].Confidence != candidates[j].Confidence {
			return candidates[i].Confidence > candidates[j].Confidence
		}
		return candidates[i].Position < candidates[j].Position
	})

	return candidates[0].Code
}

// stronglyLooksLikeVerificationEmail checks if the email is very likely a verification code email
func stronglyLooksLikeVerificationEmail(lowerContent string) bool {
	strongKeywords := []string{
		"验证码", "校验码", "确认码", "动态码",
		"verification code", "security code", "one-time",
		"verify your email", "confirm your email",
		"验证您的", "确认您的",
	}
	for _, keyword := range strongKeywords {
		if strings.Contains(lowerContent, keyword) {
			return true
		}
	}
	return false
}

// looksLikeCode checks if a string looks like a verification code (not a common word)
func looksLikeCode(code string) bool {
	// Must have at least one digit
	hasDigit := false
	for _, c := range code {
		if c >= '0' && c <= '9' {
			hasDigit = true
			break
		}
	}
	if !hasDigit {
		return false
	}

	// Reject if it's all letters (likely a word)
	allLetters := true
	for _, c := range code {
		if c < 'A' || (c > 'Z' && c < 'a') || c > 'z' {
			allLetters = false
			break
		}
	}
	if allLetters {
		return false
	}

	// Reject common words that might slip through
	lowerCode := strings.ToLower(code)
	commonWords := []string{
		"hello", "world", "email", "click", "here", "view", "open",
		"from", "sent", "date", "time", "year", "month", "day",
	}
	for _, word := range commonWords {
		if lowerCode == word {
			return false
		}
	}

	return true
}

// looksLikeVerificationEmail checks if the content appears to be a verification code email
func looksLikeVerificationEmail(lowerContent string) bool {
	// Check for non-verification keywords (promotional emails)
	nonVerificationCount := 0
	for _, keyword := range nonVerificationKeywords {
		if strings.Contains(lowerContent, strings.ToLower(keyword)) {
			nonVerificationCount++
		}
	}
	// If too many promotional keywords, likely not a verification email
	if nonVerificationCount >= 2 {
		return false
	}

	// Check for verification keywords
	for _, keyword := range verificationKeywords {
		if strings.Contains(lowerContent, strings.ToLower(keyword)) {
			return true
		}
	}

	return false
}

// ExtractAllVerificationCodes extracts all potential verification codes from content
func ExtractAllVerificationCodes(content string) []string {
	if content == "" {
		return nil
	}

	content = normalizeContent(content)
	codeSet := make(map[string]bool)
	var codes []string

	for _, pattern := range verificationCodePatterns {
		matches := pattern.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) >= 2 {
				code := strings.TrimSpace(match[1])
				if isValidCode(code) && !codeSet[code] {
					codeSet[code] = true
					codes = append(codes, code)
				}
			}
		}
	}

	return codes
}

// normalizeContent normalizes the content for better pattern matching
func normalizeContent(content string) string {
	// Remove HTML tags if present
	htmlTagPattern := regexp.MustCompile(`<[^>]*>`)
	content = htmlTagPattern.ReplaceAllString(content, " ")

	// Normalize whitespace
	whitespacePattern := regexp.MustCompile(`\s+`)
	content = whitespacePattern.ReplaceAllString(content, " ")

	// Decode common HTML entities
	content = strings.ReplaceAll(content, "&nbsp;", " ")
	content = strings.ReplaceAll(content, "&amp;", "&")
	content = strings.ReplaceAll(content, "&lt;", "<")
	content = strings.ReplaceAll(content, "&gt;", ">")
	content = strings.ReplaceAll(content, "&quot;", "\"")

	return strings.TrimSpace(content)
}

// isValidCode checks if a string is a valid verification code
func isValidCode(code string) bool {
	// Must be 4-8 characters
	if len(code) < 4 || len(code) > 8 {
		return false
	}

	// Must contain at least one digit
	hasDigit := false
	digitCount := 0
	for _, c := range code {
		if c >= '0' && c <= '9' {
			hasDigit = true
			digitCount++
		}
	}
	if !hasDigit {
		return false
	}

	// Must be alphanumeric only
	for _, c := range code {
		if !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) {
			return false
		}
	}

	// Exclude common false positives
	lowerCode := strings.ToLower(code)
	falsePositives := []string{
		"http", "https", "www", "html", "text", "mail", "email",
		"2024", "2025", "2026", "2027", "2028", "2029", "2030", // Years
		"1234", "12345", "123456", "1234567", "12345678", // Sequential numbers
		"0000", "1111", "2222", "3333", "4444", "5555", "6666", "7777", "8888", "9999", // Repeated digits
	}
	for _, fp := range falsePositives {
		if lowerCode == fp {
			return false
		}
	}

	// If it's a 4-digit number that looks like a year (19xx, 20xx), reject it
	if len(code) == 4 && digitCount == 4 {
		if strings.HasPrefix(code, "19") || strings.HasPrefix(code, "20") {
			return false
		}
	}

	return true
}
