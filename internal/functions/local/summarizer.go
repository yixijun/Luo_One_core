package local

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

const (
	// MaxSummaryLength is the maximum length of a summary
	MaxSummaryLength = 200
	// MinContentLength is the minimum content length to summarize
	MinContentLength = 50
)

// Summarize creates a simple summary of the email content
// Local summarization is limited - it extracts the first meaningful sentences
func Summarize(content string) string {
	if content == "" {
		return ""
	}

	// Normalize content
	content = normalizeForSummary(content)

	// If content is short enough, return as is
	if utf8.RuneCountInString(content) <= MaxSummaryLength {
		return content
	}

	// Extract first few sentences
	sentences := extractSentences(content)
	if len(sentences) == 0 {
		// Fallback: truncate content
		return truncateContent(content, MaxSummaryLength)
	}

	// Build summary from sentences
	var summary strings.Builder
	for _, sentence := range sentences {
		if summary.Len() == 0 {
			summary.WriteString(sentence)
		} else if summary.Len()+len(sentence)+1 <= MaxSummaryLength {
			summary.WriteString(" ")
			summary.WriteString(sentence)
		} else {
			break
		}
	}

	result := summary.String()
	if utf8.RuneCountInString(result) > MaxSummaryLength {
		result = truncateContent(result, MaxSummaryLength)
	}

	return result
}

// SummarizeWithLength creates a summary with a custom maximum length
func SummarizeWithLength(content string, maxLength int) string {
	if content == "" {
		return ""
	}

	content = normalizeForSummary(content)

	if utf8.RuneCountInString(content) <= maxLength {
		return content
	}

	sentences := extractSentences(content)
	if len(sentences) == 0 {
		return truncateContent(content, maxLength)
	}

	var summary strings.Builder
	for _, sentence := range sentences {
		if summary.Len() == 0 {
			summary.WriteString(sentence)
		} else if summary.Len()+len(sentence)+1 <= maxLength {
			summary.WriteString(" ")
			summary.WriteString(sentence)
		} else {
			break
		}
	}

	result := summary.String()
	if utf8.RuneCountInString(result) > maxLength {
		result = truncateContent(result, maxLength)
	}

	return result
}

// normalizeForSummary normalizes content for summarization
func normalizeForSummary(content string) string {
	// Remove HTML tags
	htmlTagPattern := regexp.MustCompile(`<[^>]*>`)
	content = htmlTagPattern.ReplaceAllString(content, " ")

	// Decode HTML entities
	content = strings.ReplaceAll(content, "&nbsp;", " ")
	content = strings.ReplaceAll(content, "&amp;", "&")
	content = strings.ReplaceAll(content, "&lt;", "<")
	content = strings.ReplaceAll(content, "&gt;", ">")
	content = strings.ReplaceAll(content, "&quot;", "\"")
	content = strings.ReplaceAll(content, "&#39;", "'")

	// Remove URLs
	urlPattern := regexp.MustCompile(`https?://[^\s]+`)
	content = urlPattern.ReplaceAllString(content, "")

	// Remove email addresses
	emailPattern := regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
	content = emailPattern.ReplaceAllString(content, "")

	// Normalize whitespace
	whitespacePattern := regexp.MustCompile(`\s+`)
	content = whitespacePattern.ReplaceAllString(content, " ")

	// Remove leading/trailing whitespace
	content = strings.TrimSpace(content)

	return content
}

// extractSentences extracts sentences from content
func extractSentences(content string) []string {
	// Split by sentence-ending punctuation
	// Supports both Chinese and English punctuation
	sentencePattern := regexp.MustCompile(`[.!?。！？]+\s*`)
	parts := sentencePattern.Split(content, -1)

	var sentences []string
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if len(part) > 0 {
			sentences = append(sentences, part)
		}
	}

	return sentences
}

// truncateContent truncates content to the specified length
func truncateContent(content string, maxLength int) string {
	runes := []rune(content)
	if len(runes) <= maxLength {
		return content
	}

	// Try to truncate at a word boundary
	truncated := string(runes[:maxLength])
	lastSpace := strings.LastIndex(truncated, " ")
	if lastSpace > maxLength/2 {
		truncated = truncated[:lastSpace]
	}

	return strings.TrimSpace(truncated) + "..."
}

// ExtractKeyPhrases extracts key phrases from content (simple implementation)
func ExtractKeyPhrases(content string, maxPhrases int) []string {
	content = normalizeForSummary(content)
	words := strings.Fields(content)

	// Simple frequency-based extraction
	wordCount := make(map[string]int)
	for _, word := range words {
		word = strings.ToLower(word)
		// Skip short words and common words
		if len(word) < 3 || isCommonWord(word) {
			continue
		}
		wordCount[word]++
	}

	// Sort by frequency
	type wordFreq struct {
		word  string
		count int
	}
	var freqs []wordFreq
	for word, count := range wordCount {
		freqs = append(freqs, wordFreq{word, count})
	}

	// Simple bubble sort for small lists
	for i := 0; i < len(freqs); i++ {
		for j := i + 1; j < len(freqs); j++ {
			if freqs[j].count > freqs[i].count {
				freqs[i], freqs[j] = freqs[j], freqs[i]
			}
		}
	}

	// Extract top phrases
	var phrases []string
	for i := 0; i < len(freqs) && i < maxPhrases; i++ {
		phrases = append(phrases, freqs[i].word)
	}

	return phrases
}

// isCommonWord checks if a word is a common stop word
func isCommonWord(word string) bool {
	commonWords := map[string]bool{
		"the": true, "a": true, "an": true, "and": true, "or": true,
		"but": true, "in": true, "on": true, "at": true, "to": true,
		"for": true, "of": true, "with": true, "by": true, "from": true,
		"is": true, "are": true, "was": true, "were": true, "be": true,
		"have": true, "has": true, "had": true, "do": true, "does": true,
		"did": true, "will": true, "would": true, "could": true, "should": true,
		"this": true, "that": true, "these": true, "those": true,
		"it": true, "its": true, "you": true, "your": true, "we": true,
		"our": true, "they": true, "their": true, "he": true, "she": true,
		"的": true, "是": true, "在": true, "了": true, "和": true,
		"与": true, "或": true, "但": true, "这": true, "那": true,
	}
	return commonWords[word]
}
