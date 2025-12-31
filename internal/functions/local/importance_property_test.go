package local

import (
	"testing"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
)

// Feature: luo-one-email-manager, Property 9: 重要度判断有效性
// For any email, the processed importance level should be one of the valid values
// (low, medium, high, critical).
// Validates: Requirements 4.6

func TestProperty_ImportanceJudgmentValidity(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 20
	properties := gopter.NewProperties(parameters)

	// Generator for email subject
	subjectGen := gen.SliceOfN(30, gen.AlphaChar()).Map(func(chars []rune) string {
		return string(chars)
	})

	// Generator for email content
	contentGen := gen.SliceOfN(100, gen.AlphaChar()).Map(func(chars []rune) string {
		return string(chars)
	})

	// Generator for email from address
	fromGen := gen.SliceOfN(10, gen.AlphaLowerChar()).Map(func(chars []rune) string {
		return string(chars) + "@example.com"
	})

	// Property 9.1: Importance level is always valid
	properties.Property("importance_level_always_valid", prop.ForAll(
		func(subject, content, from string) bool {
			importance := JudgeImportance(subject, content, from)
			return ValidateImportanceLevel(importance)
		},
		subjectGen,
		contentGen,
		fromGen,
	))

	// Property 9.2: Urgent keywords result in high or critical importance
	properties.Property("urgent_keywords_increase_importance", prop.ForAll(
		func(content, from string) bool {
			// Test with urgent subject
			urgentSubject := "紧急：请立即处理"
			importance := JudgeImportance(urgentSubject, content, from)
			// Should be high or critical
			return importance == "high" || importance == "critical"
		},
		contentGen,
		fromGen,
	))

	// Property 9.3: Promotional content results in low importance
	properties.Property("promotional_content_low_importance", prop.ForAll(
		func(from string) bool {
			// Test with promotional subject and content
			promoSubject := "限时优惠 折扣促销"
			promoContent := "点击订阅 unsubscribe 退订"
			importance := JudgeImportance(promoSubject, promoContent, from)
			// Should be low or medium (ad penalty applied)
			return importance == "low" || importance == "medium"
		},
		fromGen,
	))

	// Property 9.4: Importance score is bounded
	properties.Property("importance_score_bounded", prop.ForAll(
		func(subject, content, from string) bool {
			score := CalculateImportanceScore(subject, content, from)
			return score.Total >= 0 && score.Total <= 1
		},
		subjectGen,
		contentGen,
		fromGen,
	))

	properties.TestingRun(t)
}

// TestProperty_ImportanceConsistency tests that importance judgment is consistent
func TestProperty_ImportanceConsistency(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 20
	properties := gopter.NewProperties(parameters)

	// Generator for email subject
	subjectGen := gen.SliceOfN(30, gen.AlphaChar()).Map(func(chars []rune) string {
		return string(chars)
	})

	// Generator for email content
	contentGen := gen.SliceOfN(100, gen.AlphaChar()).Map(func(chars []rune) string {
		return string(chars)
	})

	// Generator for email from address
	fromGen := gen.SliceOfN(10, gen.AlphaLowerChar()).Map(func(chars []rune) string {
		return string(chars) + "@example.com"
	})

	// Property 9.5: Same input produces same output (deterministic)
	properties.Property("importance_judgment_deterministic", prop.ForAll(
		func(subject, content, from string) bool {
			importance1 := JudgeImportance(subject, content, from)
			importance2 := JudgeImportance(subject, content, from)
			return importance1 == importance2
		},
		subjectGen,
		contentGen,
		fromGen,
	))

	// Property 9.6: Score and level are consistent
	properties.Property("score_and_level_consistent", prop.ForAll(
		func(subject, content, from string) bool {
			level, score := JudgeImportanceWithScore(subject, content, from)
			expectedLevel := ImportanceFromScore(score)
			return level == expectedLevel
		},
		subjectGen,
		contentGen,
		fromGen,
	))

	properties.TestingRun(t)
}
