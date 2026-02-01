package config

import (
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
)

// Config holds the application configuration
type Config struct {
	DatabasePath  string `json:"database_path"`
	APIPort       string `json:"api_port"`
	LogLevel      string `json:"log_level"`
	DataDir       string `json:"data_dir"`
	EmailsDir     string `json:"emails_dir"`     // 邮件存储目录（独立于数据目录）
	JWTSecret     string `json:"jwt_secret"`
	EncryptionKey string `json:"encryption_key"` // 独立的加密密钥（用于加密邮箱密码）
	CORSOrigins   string `json:"cors_origins"`   // CORS 允许的域名，逗号分隔，* 表示全部
}

// Default configuration values
const (
	DefaultDatabasePath  = "data/luo_one.db"
	DefaultAPIPort       = "8080"
	DefaultLogLevel      = "INFO"
	DefaultDataDir       = "data"
	DefaultEmailsDir     = "" // 空表示使用 DataDir/users
	DefaultJWTSecret     = "luo-one-default-secret-change-in-production"
	DefaultEncryptionKey = "" // 空表示从 JWTSecret 派生
	DefaultCORSOrigins   = "*"
)

// Load loads configuration from environment variables and config file
// Priority: Environment variables > Config file > Default values
func Load() (*Config, error) {
	cfg := &Config{
		DatabasePath:  DefaultDatabasePath,
		APIPort:       DefaultAPIPort,
		LogLevel:      DefaultLogLevel,
		DataDir:       DefaultDataDir,
		EmailsDir:     DefaultEmailsDir,
		JWTSecret:     DefaultJWTSecret,
		EncryptionKey: DefaultEncryptionKey,
		CORSOrigins:   DefaultCORSOrigins,
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
	if val := os.Getenv("LUO_ONE_EMAILS_DIR"); val != "" {
		c.EmailsDir = val
	}
	if val := os.Getenv("LUO_ONE_JWT_SECRET"); val != "" {
		c.JWTSecret = val
	}
	if val := os.Getenv("LUO_ONE_ENCRYPTION_KEY"); val != "" {
		c.EncryptionKey = val
	}
	if val := os.Getenv("LUO_ONE_CORS_ORIGINS"); val != "" {
		c.CORSOrigins = val
	}
}

// GetEmailsBaseDir returns the base directory for email storage
// If EmailsDir is set, use it; otherwise use DataDir/users
func (c *Config) GetEmailsBaseDir() string {
	if c.EmailsDir != "" {
		return c.EmailsDir
	}
	return filepath.Join(c.DataDir, "users")
}

// GetEncryptionKey returns the encryption key for password encryption
// If EncryptionKey is set, use it; otherwise derive from JWTSecret
func (c *Config) GetEncryptionKey() []byte {
	if c.EncryptionKey != "" {
		// 使用 SHA-256 确保密钥长度为 32 字节
		hash := sha256.Sum256([]byte(c.EncryptionKey))
		return hash[:]
	}
	// 从 JWTSecret 派生（向后兼容）
	hash := sha256.Sum256([]byte(c.JWTSecret + "-encryption"))
	return hash[:]
}

// Save saves the current configuration to a file
func (c *Config) Save(path string) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
