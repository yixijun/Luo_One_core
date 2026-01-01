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
