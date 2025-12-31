package local

import (
	"regexp"
	"sort"
	"strings"
)

// Common verification code patterns
var verificationCodePatterns = []*regexp.Regexp{
	// Chinese patterns for verification codes
	regexp.MustCompile(`(?i)(?:验证码|校验码|确认码|动态码|安全码|授权码)[：:\s]*([A-Za-z0-9]{4,8})`),
	regexp.MustCompile(`(?i)(?:verification\s*code|code|pin|otp)[：:\s]*([A-Za-z0-9]{4,8})`),
	// Pattern: "Your code is: 123456"
	regexp.MustCompile(`(?i)(?:your\s+)?(?:code|pin|otp)\s+(?:is|:)\s*([A-Za-z0-9]{4,8})`),
	// Pattern: "123456 is your verification code"
	regexp.MustCompile(`(?i)([A-Za-z0-9]{4,8})\s+(?:is\s+)?(?:your\s+)?(?:verification\s*)?(?:code|pin|otp)`),
	// Pattern: code in brackets or parentheses
	regexp.MustCompile(`(?i)(?:验证码|code|pin|otp)[：:\s]*[\[【\(]([A-Za-z0-9]{4,8})[\]】\)]`),
	// Pattern: standalone 4-8 digit numbers that look like codes
	regexp.MustCompile(`(?:^|\s)(\d{4,8})(?:\s|$|[。，,.])`),
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
	for _, c := range code {
		if c >= '0' && c <= '9' {
			hasDigit = true
			break
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
	falsePositives := []string{"http", "https", "www", "html", "text", "mail", "email"}
	for _, fp := range falsePositives {
		if lowerCode == fp {
			return false
		}
	}

	return true
}
