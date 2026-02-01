package main

import (
	"log"
	"os"

	"github.com/luo-one/core/internal/api"
	"github.com/luo-one/core/internal/cli"
	"github.com/luo-one/core/internal/config"
	"github.com/luo-one/core/internal/database"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Ensure data directory exists
	if err := ensureDataDir(cfg); err != nil {
		log.Fatalf("Failed to create data directory: %v", err)
	}

	// Initialize database
	db, err := database.Initialize(cfg.DatabasePath)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	// Check if running CLI command
	if len(os.Args) > 1 {
		cli.Execute(db, cfg)
		return
	}

	// Start API server
	router, authManager, err := api.SetupRouter(db, cfg)
	if err != nil {
		log.Fatalf("Failed to setup router: %v", err)
	}

	log.Printf("Starting Luo One server on port %s", cfg.APIPort)
	log.Printf("Data directory: %s", cfg.DataDir)
	if cfg.EmailsDir != "" {
		log.Printf("Emails directory: %s", cfg.EmailsDir)
	}
	log.Printf("Database path: %s", cfg.DatabasePath)
	log.Printf("API Key: %s", authManager.APIKeyManager.GetCurrentKey())
	if err := router.Run(":" + cfg.APIPort); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

// ensureDataDir creates the data directory and subdirectories if they don't exist
func ensureDataDir(cfg *config.Config) error {
	// Create data directory
	dirs := []string{
		cfg.DataDir,
	}
	
	// Create emails directory (separate or under data dir)
	emailsBaseDir := cfg.GetEmailsBaseDir()
	dirs = append(dirs, emailsBaseDir)
	
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}
	return nil
}
