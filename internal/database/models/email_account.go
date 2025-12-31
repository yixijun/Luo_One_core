package models

import (
	"time"
)

// EmailAccount represents an email account configured by a user
type EmailAccount struct {
	ID                uint      `gorm:"primaryKey" json:"id"`
	UserID            uint      `gorm:"index;not null" json:"user_id"`
	Email             string    `gorm:"size:255;not null" json:"email"`
	DisplayName       string    `gorm:"size:100" json:"display_name"`
	IMAPHost          string    `gorm:"size:255;not null" json:"imap_host"`
	IMAPPort          int       `gorm:"not null" json:"imap_port"`
	SMTPHost          string    `gorm:"size:255;not null" json:"smtp_host"`
	SMTPPort          int       `gorm:"not null" json:"smtp_port"`
	Username          string    `gorm:"size:255;not null" json:"username"`
	PasswordEncrypted string    `gorm:"size:500;not null" json:"-"`
	UseSSL            bool      `gorm:"default:true" json:"use_ssl"`
	Enabled           bool      `gorm:"default:true" json:"enabled"`
	SyncDays          int       `gorm:"default:-1" json:"sync_days"` // Days to sync: -1=all, 0=incremental, >0=specific days
	LastSyncAt        time.Time `json:"last_sync_at"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`

	// Relations
	Emails []Email `gorm:"foreignKey:AccountID" json:"emails,omitempty"`
}
