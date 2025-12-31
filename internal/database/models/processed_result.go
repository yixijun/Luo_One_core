package models

import (
	"time"
)

// ProcessedResult stores the result of email processing
type ProcessedResult struct {
	ID               uint      `gorm:"primaryKey" json:"id"`
	EmailID          uint      `gorm:"uniqueIndex;not null" json:"email_id"`
	VerificationCode string    `gorm:"size:50" json:"verification_code,omitempty"`
	IsAd             bool      `gorm:"default:false" json:"is_ad"`
	Summary          string    `gorm:"type:text" json:"summary,omitempty"`
	Importance       string    `gorm:"size:20;default:'medium'" json:"importance"` // low, medium, high, critical
	ProcessedBy      string    `gorm:"size:20" json:"processed_by"`                // ai, local
	ProcessedAt      time.Time `json:"processed_at"`
}

// ImportanceLevel represents the importance level of an email
type ImportanceLevel string

const (
	ImportanceLow      ImportanceLevel = "low"
	ImportanceMedium   ImportanceLevel = "medium"
	ImportanceHigh     ImportanceLevel = "high"
	ImportanceCritical ImportanceLevel = "critical"
)

// IsValid checks if the importance level is valid
func (i ImportanceLevel) IsValid() bool {
	switch i {
	case ImportanceLow, ImportanceMedium, ImportanceHigh, ImportanceCritical:
		return true
	}
	return false
}
