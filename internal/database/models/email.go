package models

import (
	"time"
)

// Email represents an email message
type Email struct {
	ID             uint      `gorm:"primaryKey" json:"id"`
	AccountID      uint      `gorm:"index;not null" json:"account_id"`
	MessageID      string    `gorm:"uniqueIndex;size:255;not null" json:"message_id"`
	Subject        string    `gorm:"size:500" json:"subject"`
	FromAddr       string    `gorm:"size:255" json:"from"`
	ToAddrs        string    `gorm:"type:text" json:"to"` // JSON array stored as string
	Date           time.Time `gorm:"index" json:"date"`
	Body           string    `gorm:"type:text" json:"body"`
	HTMLBody       string    `gorm:"type:text" json:"html_body"`
	HasAttachments bool      `gorm:"default:false" json:"has_attachments"`
	IsRead         bool      `gorm:"default:false" json:"is_read"`
	RawFilePath    string    `gorm:"size:500" json:"raw_file_path"`
	CreatedAt      time.Time `json:"created_at"`

	// Relations
	ProcessedResult *ProcessedResult `gorm:"foreignKey:EmailID" json:"processed_result,omitempty"`
}
