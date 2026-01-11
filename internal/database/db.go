package database

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/luo-one/core/internal/database/models"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Initialize creates and returns a database connection
func Initialize(dbPath string) (*gorm.DB, error) {
	// Ensure the directory exists
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}

	// Configure GORM logger
	gormConfig := &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
	}

	// Open SQLite database
	db, err := gorm.Open(sqlite.Open(dbPath), gormConfig)
	if err != nil {
		return nil, err
	}

	// Run migrations
	if err := runMigrations(db); err != nil {
		return nil, err
	}

	return db, nil
}

// runMigrations runs all database migrations
func runMigrations(db *gorm.DB) error {
	// Auto-migrate all models
	if err := db.AutoMigrate(
		&models.User{},
		&models.UserSettings{},
		&models.EmailAccount{},
		&models.Email{},
		&models.ProcessedResult{},
		&models.Log{},
	); err != nil {
		return err
	}

	// 确保 EmailAccount 的 OAuth 字段存在
	if db.Migrator().HasTable(&models.EmailAccount{}) {
		// 检查是否存在旧的 GORM 自动命名列（o_auth_*），如果存在则迁移数据
		var hasOldColumns bool
		var colInfo []struct {
			Name string `gorm:"column:name"`
		}
		db.Raw("PRAGMA table_info(email_accounts)").Scan(&colInfo)
		for _, col := range colInfo {
			if col.Name == "o_auth_access_token" {
				hasOldColumns = true
				break
			}
		}
		
		// 使用原生 SQL 添加列（SQLite 兼容）
		oauthColumns := []struct {
			name string
			def  string
		}{
			{"auth_type", "TEXT DEFAULT 'password'"},
			{"oauth_provider", "TEXT DEFAULT ''"},
			{"oauth_access_token", "TEXT DEFAULT ''"},
			{"oauth_refresh_token", "TEXT DEFAULT ''"},
			{"oauth_token_expiry", "DATETIME"},
		}
		
		for _, col := range oauthColumns {
			// 检查列是否已存在
			var exists bool
			for _, c := range colInfo {
				if c.Name == col.name {
					exists = true
					break
				}
			}
			if !exists {
				sql := fmt.Sprintf("ALTER TABLE email_accounts ADD COLUMN %s %s", col.name, col.def)
				if err := db.Exec(sql).Error; err != nil {
					// 忽略 "duplicate column" 错误
					if !strings.Contains(err.Error(), "duplicate column") {
						log.Printf("[Migration] Warning: Failed to add column %s: %v", col.name, err)
					}
				} else {
					log.Printf("[Migration] Added column %s to email_accounts", col.name)
				}
			}
		}
		
		// 如果存在旧列，迁移数据到新列
		if hasOldColumns {
			log.Printf("[Migration] Found old GORM column names (o_auth_*), migrating data...")
			db.Exec("UPDATE email_accounts SET oauth_access_token = o_auth_access_token WHERE oauth_access_token IS NULL OR oauth_access_token = ''")
			db.Exec("UPDATE email_accounts SET oauth_refresh_token = o_auth_refresh_token WHERE oauth_refresh_token IS NULL OR oauth_refresh_token = ''")
			db.Exec("UPDATE email_accounts SET oauth_token_expiry = o_auth_token_expiry WHERE oauth_token_expiry IS NULL")
			db.Exec("UPDATE email_accounts SET oauth_provider = o_auth_provider WHERE oauth_provider IS NULL OR oauth_provider = ''")
			log.Printf("[Migration] Data migration from old columns completed")
		}
		
		// 修复旧数据：如果有 oauth_refresh_token 但 auth_type 为空，设置为 oauth2
		db.Exec("UPDATE email_accounts SET auth_type = 'oauth2', oauth_provider = 'google' WHERE oauth_refresh_token IS NOT NULL AND oauth_refresh_token != '' AND (auth_type IS NULL OR auth_type = '' OR auth_type = 'password')")
	}

	// 确保 Google OAuth 字段存在（GORM AutoMigrate 应该会自动添加，但为了安全起见）
	if db.Migrator().HasTable(&models.UserSettings{}) {
		if !db.Migrator().HasColumn(&models.UserSettings{}, "google_client_id") {
			db.Migrator().AddColumn(&models.UserSettings{}, "google_client_id")
		}
		if !db.Migrator().HasColumn(&models.UserSettings{}, "google_client_secret") {
			db.Migrator().AddColumn(&models.UserSettings{}, "google_client_secret")
		}
		if !db.Migrator().HasColumn(&models.UserSettings{}, "google_redirect_url") {
			db.Migrator().AddColumn(&models.UserSettings{}, "google_redirect_url")
		}
		// 确保主题和字体字段存在
		if !db.Migrator().HasColumn(&models.UserSettings{}, "theme") {
			db.Migrator().AddColumn(&models.UserSettings{}, "theme")
		}
		if !db.Migrator().HasColumn(&models.UserSettings{}, "font") {
			db.Migrator().AddColumn(&models.UserSettings{}, "font")
		}
		// 确保 AI Base URL 字段存在
		if !db.Migrator().HasColumn(&models.UserSettings{}, "ai_base_url") {
			db.Migrator().AddColumn(&models.UserSettings{}, "ai_base_url")
		}
		// 确保处理模式字段存在
		if !db.Migrator().HasColumn(&models.UserSettings{}, "extract_code_mode") {
			db.Migrator().AddColumn(&models.UserSettings{}, "extract_code_mode")
		}
		if !db.Migrator().HasColumn(&models.UserSettings{}, "detect_ad_mode") {
			db.Migrator().AddColumn(&models.UserSettings{}, "detect_ad_mode")
		}
		if !db.Migrator().HasColumn(&models.UserSettings{}, "summarize_mode") {
			db.Migrator().AddColumn(&models.UserSettings{}, "summarize_mode")
		}
		if !db.Migrator().HasColumn(&models.UserSettings{}, "judge_importance_mode") {
			db.Migrator().AddColumn(&models.UserSettings{}, "judge_importance_mode")
		}
		// 确保提示词字段存在
		if !db.Migrator().HasColumn(&models.UserSettings{}, "prompt_extract_code") {
			db.Migrator().AddColumn(&models.UserSettings{}, "prompt_extract_code")
		}
		if !db.Migrator().HasColumn(&models.UserSettings{}, "prompt_detect_ad") {
			db.Migrator().AddColumn(&models.UserSettings{}, "prompt_detect_ad")
		}
		if !db.Migrator().HasColumn(&models.UserSettings{}, "prompt_summarize") {
			db.Migrator().AddColumn(&models.UserSettings{}, "prompt_summarize")
		}
		if !db.Migrator().HasColumn(&models.UserSettings{}, "prompt_judge_importance") {
			db.Migrator().AddColumn(&models.UserSettings{}, "prompt_judge_importance")
		}
	}

	_ = db.Migrator().DropIndex(&models.Email{}, "message_id")
	_ = db.Migrator().DropIndex(&models.Email{}, "idx_emails_message_id")

	// Update existing emails with empty folder to 'inbox'
	db.Model(&models.Email{}).Where("folder = '' OR folder IS NULL").Update("folder", models.FolderInbox)

	return nil
}

// GetDB returns the database instance (for testing purposes)
func GetDB(db *gorm.DB) *gorm.DB {
	return db
}
