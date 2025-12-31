package local

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
)

// Feature: luo-one-email-manager, Property 8: 验证码提取正确性
// For any email containing a verification code (4-8 digit numeric or alphanumeric),
// the processing should correctly extract the verification code.
// Validates: Requirements 4.3

func TestProperty_VerificationCodeExtraction(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 20
	properties := gopter.NewProperties(parameters)

	// Generator for 4-8 digit numeric codes
	numericCodeGen := gen.IntRange(4, 8).FlatMap(func(length interface{}) gopter.Gen {
		return gen.SliceOfN(length.(int), gen.NumChar()).Map(func(chars []rune) string {
			return string(chars)
		})
	}, reflect.TypeOf(""))

	// Generator for alphanumeric codes (4-8 chars)
	alphanumericCodeGen := gen.IntRange(4, 8).FlatMap(func(length interface{}) gopter.Gen {
		return gen.SliceOfN(length.(int), gen.AlphaNumChar()).Map(func(chars []rune) string {
			return string(chars)
		})
	}, reflect.TypeOf(""))

	// Generator for random text prefix/suffix
	randomTextGen := gen.SliceOfN(20, gen.AlphaChar()).Map(func(chars []rune) string {
		return string(chars)
	})

	// Property 8.1: Numeric codes with Chinese pattern are extracted
	properties.Property("numeric_code_with_chinese_pattern_extracted", prop.ForAll(
		func(code, prefix, suffix string) bool {
			content := fmt.Sprintf("%s 验证码：%s %s", prefix, code, suffix)
			extracted := ExtractVerificationCode(content)
			return extracted == code
		},
		numericCodeGen,
		randomTextGen,
		randomTextGen,
	))

	// Property 8.2: Numeric codes with English pattern are extracted
	properties.Property("numeric_code_with_english_pattern_extracted", prop.ForAll(
		func(code, prefix, suffix string) bool {
			content := fmt.Sprintf("%s Your verification code is: %s %s", prefix, code, suffix)
			extracted := ExtractVerificationCode(content)
			return extracted == code
		},
		numericCodeGen,
		randomTextGen,
		randomTextGen,
	))

	// Property 8.3: Alphanumeric codes are extracted
	properties.Property("alphanumeric_code_extracted", prop.ForAll(
		func(code, prefix, suffix string) bool {
			// Ensure code has at least one digit
			if !hasDigit(code) {
				code = code[:len(code)-1] + "1"
			}
			content := fmt.Sprintf("%s code: %s %s", prefix, code, suffix)
			extracted := ExtractVerificationCode(content)
			return extracted == code
		},
		alphanumericCodeGen,
		randomTextGen,
		randomTextGen,
	))

	properties.TestingRun(t)
}

// hasDigit checks if a string contains at least one digit
func hasDigit(s string) bool {
	for _, c := range s {
		if c >= '0' && c <= '9' {
			return true
		}
	}
	return false
}
