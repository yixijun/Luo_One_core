package local

import (
	"regexp"
	"strings"

	"github.com/luo-one/core/internal/database/models"
)

// Importance level keywords
var (
	// Critical importance keywords
	criticalKeywords = []string{
		// Chinese critical terms
		"紧急", "立即", "马上", "尽快", "重要通知", "重要提醒",
		"账户异常", "安全警告", "密码重置", "账号被盗", "风险提示",
		"支付失败", "订单问题", "退款", "法律", "诉讼", "传票",
		// English critical terms
		"urgent", "immediate", "asap", "critical", "emergency",
		"security alert", "password reset", "account compromised",
		"payment failed", "legal notice", "action required",
		"final notice", "deadline",
	}

	// High importance keywords
	highKeywords = []string{
		// Chinese high importance terms
		"重要", "请注意", "提醒", "通知", "确认", "审批",
		"面试", "offer", "录用", "入职", "合同", "协议",
		"账单", "发票", "付款", "转账", "银行",
		// English high importance terms
		"important", "attention", "reminder", "notice", "confirm",
		"interview", "job offer", "contract", "agreement",
		"invoice", "payment", "bank", "financial",
		"meeting", "appointment", "schedule",
	}

	// Low importance keywords (typically automated/marketing)
	lowKeywords = []string{
		// Chinese low importance terms
		"订阅", "推荐", "精选", "热门", "活动", "促销",
		"优惠", "折扣", "新闻", "周报", "月报", "简报",
		// English low importance terms
		"newsletter", "digest", "weekly", "monthly", "update",
		"subscription", "recommended", "trending", "popular",
		"marketing", "promotional", "advertisement",
	}

	// Sender domain patterns for importance
	importantDomains = []string{
		"gov", "edu", "bank", "finance",
	}

	// Patterns indicating automated/bulk emails
	automatedPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)no-?reply`),
		regexp.MustCompile(`(?i)do-?not-?reply`),
		regexp.MustCompile(`(?i)automated`),
		regexp.MustCompile(`(?i)notification@`),
		regexp.MustCompile(`(?i)noreply@`),
		regexp.MustCompile(`(?i)mailer-daemon`),
	}
)

// ImportanceScore represents the importance score breakdown
type ImportanceScore struct {
	Total         float64
	CriticalScore float64
	HighScore     float64
	LowScore      float64
	SenderScore   float64
	AdPenalty     float64
}

// JudgeImportance determines the importance level of an email
// Returns one of: "low", "medium", "high", "critical"
func JudgeImportance(subject, content, from string) string {
	score := CalculateImportanceScore(subject, content, from)
	return ImportanceFromScore(score.Total)
}

// ImportanceFromScore converts a numeric score to importance level
func ImportanceFromScore(score float64) string {
	switch {
	case score >= 0.8:
		return string(models.ImportanceCritical)
	case score >= 0.6:
		return string(models.ImportanceHigh)
	case score <= 0.3:
		return string(models.ImportanceLow)
	default:
		return string(models.ImportanceMedium)
	}
}

// CalculateImportanceScore calculates a detailed importance score
func CalculateImportanceScore(subject, content, from string) ImportanceScore {
	score := ImportanceScore{}

	// Normalize inputs
	subject = strings.ToLower(subject)
	content = strings.ToLower(normalizeForImportance(content))
	from = strings.ToLower(from)
	combined := subject + " " + content

	// Check critical keywords (weight: 0.4)
	criticalCount := countKeywordMatchesImportance(combined, criticalKeywords)
	if criticalCount > 0 {
		score.CriticalScore = minFloat(float64(criticalCount)*0.2, 0.4)
	}

	// Check high importance keywords (weight: 0.3)
	highCount := countKeywordMatchesImportance(combined, highKeywords)
	score.HighScore = minFloat(float64(highCount)*0.1, 0.3)

	// Check low importance keywords (negative weight: -0.2)
	lowCount := countKeywordMatchesImportance(combined, lowKeywords)
	score.LowScore = -minFloat(float64(lowCount)*0.1, 0.2)

	// Check sender importance (weight: 0.2)
	score.SenderScore = calculateSenderScore(from)

	// Apply ad penalty
	if DetectAd(subject, content) {
		score.AdPenalty = -0.3
	}

	// Calculate total score (base: 0.5 for medium)
	score.Total = 0.5 + score.CriticalScore + score.HighScore +
		score.LowScore + score.SenderScore + score.AdPenalty

	// Clamp to [0, 1]
	if score.Total < 0 {
		score.Total = 0
	}
	if score.Total > 1 {
		score.Total = 1
	}

	return score
}

// JudgeImportanceWithScore returns the importance level and the score
func JudgeImportanceWithScore(subject, content, from string) (string, float64) {
	score := CalculateImportanceScore(subject, content, from)
	return ImportanceFromScore(score.Total), score.Total
}

// calculateSenderScore calculates importance based on sender
func calculateSenderScore(from string) float64 {
	// Check for automated/bulk email patterns
	for _, pattern := range automatedPatterns {
		if pattern.MatchString(from) {
			return -0.1
		}
	}

	// Check for important domains
	for _, domain := range importantDomains {
		if strings.Contains(from, "."+domain) || strings.Contains(from, "@"+domain) {
			return 0.15
		}
	}

	return 0
}

// countKeywordMatchesImportance counts keyword matches for importance calculation
func countKeywordMatchesImportance(text string, keywords []string) int {
	count := 0
	for _, keyword := range keywords {
		if strings.Contains(text, strings.ToLower(keyword)) {
			count++
		}
	}
	return count
}

// normalizeForImportance normalizes content for importance judgment
func normalizeForImportance(content string) string {
	// Remove HTML tags
	htmlTagPattern := regexp.MustCompile(`<[^>]*>`)
	content = htmlTagPattern.ReplaceAllString(content, " ")

	// Normalize whitespace
	whitespacePattern := regexp.MustCompile(`\s+`)
	content = whitespacePattern.ReplaceAllString(content, " ")

	return strings.TrimSpace(content)
}

// minFloat returns the minimum of two float64 values
func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

// IsUrgent checks if the email appears to be urgent
func IsUrgent(subject, content string) bool {
	combined := strings.ToLower(subject + " " + content)
	urgentTerms := []string{"urgent", "紧急", "立即", "马上", "asap", "emergency"}
	for _, term := range urgentTerms {
		if strings.Contains(combined, term) {
			return true
		}
	}
	return false
}

// IsFromAutomatedSender checks if the email is from an automated sender
func IsFromAutomatedSender(from string) bool {
	from = strings.ToLower(from)
	for _, pattern := range automatedPatterns {
		if pattern.MatchString(from) {
			return true
		}
	}
	return false
}

// ValidateImportanceLevel checks if an importance level is valid
func ValidateImportanceLevel(level string) bool {
	return models.ImportanceLevel(level).IsValid()
}
