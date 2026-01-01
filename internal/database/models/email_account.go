package models

import (
	"time"
)

// AuthType represents the authentication type for an email account
type AuthType string

const (
	AuthTypePassword AuthType = "password" // Traditional username/password
	AuthTypeOAuth2   AuthType = "oauth2"   // OAuth 2.0 (Gmail, Outlook)
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
	PasswordEncrypted string    `gorm:"size:500" json:"-"`
	UseSSL            bool      `gorm:"default:true" json:"use_ssl"`
	Enabled           bool      `gorm:"default:true" json:"enabled"`
	SyncDays          int       `gorm:"default:-1" json:"sync_days"` // Days to sync: -1=all, 0=incremental, >0=specific days
	LastSyncAt        time.Time `json:"last_sync_at"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`

	// OAuth 2.0 fields
	AuthType              AuthType  `gorm:"size:20;default:'password'" json:"auth_type"`
	OAuthProvider         string    `gorm:"size:50" json:"oauth_provider,omitempty"`          // google, microsoft, etc.
	OAuthAccessToken      string    `gorm:"size:2000" json:"-"`                               // Encrypted access token
	OAuthRefreshToken     string    `gorm:"size:2000" json:"-"`                               // Encrypted refresh token
	OAuthTokenExpiry      time.Time `json:"oauth_token_expiry,omitempty"`                     // Token expiry time

	// Relations
	Emails []Email `gorm:"foreignKey:AccountID" json:"emails,omitempty"`
}
