package models

import (
	"time"
)

// User represents a user in the system
type User struct {
	ID           uint      `gorm:"primaryKey" json:"id"`
	Username     string    `gorm:"uniqueIndex;size:50;not null" json:"username"`
	PasswordHash string    `gorm:"size:255;not null" json:"-"`
	Nickname     string    `gorm:"size:100" json:"nickname"`
	Avatar       string    `gorm:"size:500" json:"avatar"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`

	// Relations
	EmailAccounts []EmailAccount `gorm:"foreignKey:UserID" json:"email_accounts,omitempty"`
	Settings      *UserSettings  `gorm:"foreignKey:UserID" json:"settings,omitempty"`
}

// UserSettings stores user-specific settings
type UserSettings struct {
	ID              uint   `gorm:"primaryKey" json:"id"`
	UserID          uint   `gorm:"uniqueIndex;not null" json:"user_id"`
	AIEnabled       bool   `gorm:"default:false" json:"ai_enabled"`
	AIProvider      string `gorm:"size:50" json:"ai_provider"`
	AIAPIKey        string `gorm:"size:500" json:"ai_api_key"`
	AIModel         string `gorm:"size:100" json:"ai_model"`
	ExtractCode     bool   `gorm:"default:true" json:"extract_code"`
	DetectAd        bool   `gorm:"default:true" json:"detect_ad"`
	Summarize       bool   `gorm:"default:false" json:"summarize"`
	JudgeImportance bool   `gorm:"default:true" json:"judge_importance"`

	// Google OAuth 配置
	GoogleClientID     string `gorm:"size:500" json:"google_client_id"`
	GoogleClientSecret string `gorm:"size:500" json:"google_client_secret"`
	GoogleRedirectURL  string `gorm:"size:500" json:"google_redirect_url"`

	// 主题和字体配置
	Theme string `gorm:"size:50;default:'dark'" json:"theme"`
	Font  string `gorm:"size:50;default:'system'" json:"font"`
}
