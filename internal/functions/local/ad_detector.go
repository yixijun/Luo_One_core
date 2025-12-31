package local

import (
	"regexp"
	"strings"
)

// Ad detection keywords categorized by type
var (
	// Promotional keywords (Chinese and English)
	promotionalKeywords = []string{
		// Chinese promotional terms
		"促销", "优惠", "折扣", "特价", "限时", "抢购", "秒杀", "满减",
		"红包", "优惠券", "代金券", "返现", "免费领", "大促", "狂欢",
		"双十一", "双十二", "618", "年货节", "清仓", "甩卖",
		"会员专享", "新人专享", "首单", "立减", "包邮",
		// English promotional terms
		"sale", "discount", "offer", "deal", "promo", "promotion",
		"limited time", "flash sale", "clearance", "save", "off",
		"free shipping", "buy one get one", "bogo", "coupon",
		"voucher", "cashback", "reward",
	}

	// Marketing keywords
	marketingKeywords = []string{
		// Chinese marketing terms
		"订阅", "推荐", "精选", "热卖", "爆款", "新品", "上新",
		"品牌", "官方", "旗舰店", "商城", "购物",
		// English marketing terms
		"subscribe", "newsletter", "recommended", "trending",
		"bestseller", "new arrival", "shop now", "buy now",
		"click here", "learn more", "don't miss",
	}

	// Unsubscribe indicators (strong ad signal)
	unsubscribeKeywords = []string{
		"退订", "取消订阅", "不再接收", "unsubscribe",
		"opt out", "opt-out", "remove me", "stop receiving",
	}

	// Spam-like patterns
	spamPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)act\s+now`),
		regexp.MustCompile(`(?i)limited\s+offer`),
		regexp.MustCompile(`(?i)click\s+here`),
		regexp.MustCompile(`(?i)100%\s+free`),
		regexp.MustCompile(`(?i)no\s+obligation`),
		regexp.MustCompile(`(?i)risk\s+free`),
		regexp.MustCompile(`(?i)winner|won|congratulations`),
		regexp.MustCompile(`(?i)earn\s+\$|赚钱|挣钱`),
		regexp.MustCompile(`(?i)make\s+money`),
	}
)

// AdScore represents the advertisement score breakdown
type AdScore struct {
	Total            float64
	PromotionalScore float64
	MarketingScore   float64
	UnsubscribeScore float64
	SpamScore        float64
}

// DetectAd checks if an email is an advertisement using keyword matching
// Returns true if the email is likely an advertisement
func DetectAd(subject, content string) bool {
	score := CalculateAdScore(subject, content)
	// Threshold for considering an email as an ad
	return score.Total >= 0.5
}

// CalculateAdScore calculates a detailed ad score for the email
func CalculateAdScore(subject, content string) AdScore {
	score := AdScore{}

	// Normalize inputs
	subject = strings.ToLower(subject)
	content = strings.ToLower(normalizeForAdDetection(content))
	combined := subject + " " + content

	// Check promotional keywords (weight: 0.3)
	promotionalCount := countKeywordMatches(combined, promotionalKeywords)
	score.PromotionalScore = min(float64(promotionalCount)*0.1, 0.3)

	// Check marketing keywords (weight: 0.2)
	marketingCount := countKeywordMatches(combined, marketingKeywords)
	score.MarketingScore = min(float64(marketingCount)*0.05, 0.2)

	// Check unsubscribe keywords (weight: 0.3) - strong indicator
	unsubscribeCount := countKeywordMatches(combined, unsubscribeKeywords)
	if unsubscribeCount > 0 {
		score.UnsubscribeScore = 0.3
	}

	// Check spam patterns (weight: 0.2)
	spamCount := countPatternMatches(combined, spamPatterns)
	score.SpamScore = min(float64(spamCount)*0.1, 0.2)

	// Calculate total score
	score.Total = score.PromotionalScore + score.MarketingScore +
		score.UnsubscribeScore + score.SpamScore

	// Cap at 1.0
	if score.Total > 1.0 {
		score.Total = 1.0
	}

	return score
}

// DetectAdWithConfidence returns whether the email is an ad and the confidence level
func DetectAdWithConfidence(subject, content string) (bool, float64) {
	score := CalculateAdScore(subject, content)
	return score.Total >= 0.5, score.Total
}

// countKeywordMatches counts how many keywords are found in the text
func countKeywordMatches(text string, keywords []string) int {
	count := 0
	for _, keyword := range keywords {
		if strings.Contains(text, strings.ToLower(keyword)) {
			count++
		}
	}
	return count
}

// countPatternMatches counts how many patterns match in the text
func countPatternMatches(text string, patterns []*regexp.Regexp) int {
	count := 0
	for _, pattern := range patterns {
		if pattern.MatchString(text) {
			count++
		}
	}
	return count
}

// normalizeForAdDetection normalizes content for ad detection
func normalizeForAdDetection(content string) string {
	// Remove HTML tags
	htmlTagPattern := regexp.MustCompile(`<[^>]*>`)
	content = htmlTagPattern.ReplaceAllString(content, " ")

	// Normalize whitespace
	whitespacePattern := regexp.MustCompile(`\s+`)
	content = whitespacePattern.ReplaceAllString(content, " ")

	// Decode common HTML entities
	content = strings.ReplaceAll(content, "&nbsp;", " ")
	content = strings.ReplaceAll(content, "&amp;", "&")

	return strings.TrimSpace(content)
}

// min returns the minimum of two float64 values
func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

// IsPromotionalEmail checks if the email is specifically promotional
func IsPromotionalEmail(subject, content string) bool {
	combined := strings.ToLower(subject + " " + content)
	count := countKeywordMatches(combined, promotionalKeywords)
	return count >= 2
}

// HasUnsubscribeLink checks if the email has unsubscribe indicators
func HasUnsubscribeLink(content string) bool {
	content = strings.ToLower(content)
	return countKeywordMatches(content, unsubscribeKeywords) > 0
}
