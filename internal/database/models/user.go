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
	AIBaseURL       string `gorm:"size:500" json:"ai_base_url"` // AI API 地址
	AIModel         string `gorm:"size:100" json:"ai_model"`
	ExtractCode     bool   `gorm:"default:true" json:"extract_code"`
	DetectAd        bool   `gorm:"default:true" json:"detect_ad"`
	Summarize       bool   `gorm:"default:false" json:"summarize"`
	JudgeImportance bool   `gorm:"default:true" json:"judge_importance"`

	// 每个功能的处理模式: "local" 或 "ai"
	ExtractCodeMode     string `gorm:"size:20;default:'local'" json:"extract_code_mode"`
	DetectAdMode        string `gorm:"size:20;default:'local'" json:"detect_ad_mode"`
	SummarizeMode       string `gorm:"size:20;default:'local'" json:"summarize_mode"`
	JudgeImportanceMode string `gorm:"size:20;default:'local'" json:"judge_importance_mode"`

	// AI 提示词配置
	PromptExtractCode     string `gorm:"type:text" json:"prompt_extract_code"`
	PromptDetectAd        string `gorm:"type:text" json:"prompt_detect_ad"`
	PromptSummarize       string `gorm:"type:text" json:"prompt_summarize"`
	PromptJudgeImportance string `gorm:"type:text" json:"prompt_judge_importance"`

	// Google OAuth 配置
	GoogleClientID     string `gorm:"size:500" json:"google_client_id"`
	GoogleClientSecret string `gorm:"size:500" json:"google_client_secret"`
	GoogleRedirectURL  string `gorm:"size:500" json:"google_redirect_url"`

	// 主题和字体配置
	Theme string `gorm:"size:50;default:'dark'" json:"theme"`
	Font  string `gorm:"size:50;default:'system'" json:"font"`

	// 自动同步间隔（秒），0 表示使用默认值 120 秒
	SyncInterval int `gorm:"default:120" json:"sync_interval"`
}
