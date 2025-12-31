package models

import (
	"time"
)

// Log represents a system log entry
type Log struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	UserID    uint      `gorm:"index" json:"user_id"`
	Level     string    `gorm:"size:20;index" json:"level"` // DEBUG, INFO, WARN, ERROR
	Module    string    `gorm:"size:50;index" json:"module"`
	Action    string    `gorm:"size:100" json:"action"`
	Message   string    `gorm:"type:text" json:"message"`
	Details   string    `gorm:"type:text" json:"details"` // JSON string for additional details
	CreatedAt time.Time `gorm:"index" json:"created_at"`
}

// LogLevel represents the log level
type LogLevel string

const (
	LogLevelDebug LogLevel = "DEBUG"
	LogLevelInfo  LogLevel = "INFO"
	LogLevelWarn  LogLevel = "WARN"
	LogLevelError LogLevel = "ERROR"
)

// LogModule represents the module that generated the log
type LogModule string

const (
	LogModuleAuth    LogModule = "auth"
	LogModuleUser    LogModule = "user"
	LogModuleEmail   LogModule = "email"
	LogModuleAccount LogModule = "account"
	LogModuleProcess LogModule = "process"
	LogModuleAPI     LogModule = "api"
	LogModuleCLI     LogModule = "cli"
)
