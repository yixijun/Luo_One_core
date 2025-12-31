package config

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// Config holds the application configuration
type Config struct {
	DatabasePath string `json:"database_path"`
	APIPort      string `json:"api_port"`
	LogLevel     string `json:"log_level"`
	DataDir      string `json:"data_dir"`
	JWTSecret    string `json:"jwt_secret"`
}

// Default configuration values
const (
	DefaultDatabasePath = "data/luo_one.db"
	DefaultAPIPort      = "8080"
	DefaultLogLevel     = "INFO"
	DefaultDataDir      = "data"
	DefaultJWTSecret    = "luo-one-default-secret-change-in-production"
)

// Load loads configuration from environment variables and config file
// Priority: Environment variables > Config file > Default values
func Load() (*Config, error) {
	cfg := &Config{
		DatabasePath: DefaultDatabasePath,
		APIPort:      DefaultAPIPort,
		LogLevel:     DefaultLogLevel,
		DataDir:      DefaultDataDir,
		JWTSecret:    DefaultJWTSecret,
	}

	// Try to load from config file
	if err := cfg.loadFromFile(); err != nil {
		// Config file is optional, log but don't fail
		// In production, you might want to log this
	}

	// Override with environment variables
	cfg.loadFromEnv()

	return cfg, nil
}

// loadFromFile loads configuration from config.json file
func (c *Config) loadFromFile() error {
	// Look for config file in current directory and data directory
	configPaths := []string{
		"config.json",
		filepath.Join(c.DataDir, "config.json"),
	}

	for _, path := range configPaths {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		if err := json.Unmarshal(data, c); err != nil {
			return err
		}
		return nil
	}

	return nil
}

// loadFromEnv loads configuration from environment variables
func (c *Config) loadFromEnv() {
	if val := os.Getenv("LUO_ONE_DATABASE_PATH"); val != "" {
		c.DatabasePath = val
	}
	if val := os.Getenv("LUO_ONE_API_PORT"); val != "" {
		c.APIPort = val
	}
	if val := os.Getenv("LUO_ONE_LOG_LEVEL"); val != "" {
		c.LogLevel = val
	}
	if val := os.Getenv("LUO_ONE_DATA_DIR"); val != "" {
		c.DataDir = val
	}
	if val := os.Getenv("LUO_ONE_JWT_SECRET"); val != "" {
		c.JWTSecret = val
	}
}

// Save saves the current configuration to a file
func (c *Config) Save(path string) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
