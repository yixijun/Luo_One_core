package database

import (
	"os"
	"path/filepath"

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
