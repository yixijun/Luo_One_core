package services

import (
	"log"
	"sync"
	"time"

	"github.com/luo-one/core/internal/database/models"
	"gorm.io/gorm"
)

// SyncScheduler handles automatic email synchronization
type SyncScheduler struct {
	db           *gorm.DB
	emailService *EmailService
	logService   *LogService
	interval     time.Duration
	stopChan     chan struct{}
	running      bool
	mu           sync.Mutex
}

// NewSyncScheduler creates a new sync scheduler
func NewSyncScheduler(db *gorm.DB, emailService *EmailService, logService *LogService, interval time.Duration) *SyncScheduler {
	return &SyncScheduler{
		db:           db,
		emailService: emailService,
		logService:   logService,
		interval:     interval,
		stopChan:     make(chan struct{}),
	}
}

// Start begins the automatic sync process
func (s *SyncScheduler) Start() {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return
	}
	s.running = true
	s.mu.Unlock()

	log.Printf("Starting email sync scheduler with interval: %v", s.interval)

	go func() {
		// 启动后等待一段时间再开始第一次同步
		time.Sleep(30 * time.Second)

		ticker := time.NewTicker(s.interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				s.syncAllAccounts()
			case <-s.stopChan:
				log.Println("Stopping email sync scheduler")
				return
			}
		}
	}()
}

// Stop stops the automatic sync process
func (s *SyncScheduler) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return
	}

	close(s.stopChan)
	s.running = false
}

// syncAllAccounts syncs all enabled accounts
func (s *SyncScheduler) syncAllAccounts() {
	// 获取所有启用的账户
	var accounts []models.EmailAccount
	if err := s.db.Where("enabled = ?", true).Find(&accounts).Error; err != nil {
		log.Printf("Failed to get accounts for sync: %v", err)
		return
	}

	if len(accounts) == 0 {
		return
	}

	log.Printf("Auto-sync: syncing %d accounts", len(accounts))

	for _, account := range accounts {
		// 获取账户所属用户
		var user models.User
		if err := s.db.First(&user, account.UserID).Error; err != nil {
			continue
		}

		// 同步邮件
		count, err := s.emailService.SyncAndSaveEmails(account.UserID, account.ID)
		if err != nil {
			s.logService.LogWarn(account.UserID, models.LogModuleEmail, "auto_sync", "Auto sync failed", map[string]interface{}{
				"account_id": account.ID,
				"error":      err.Error(),
			})
			continue
		}

		if count > 0 {
			s.logService.LogInfo(account.UserID, models.LogModuleEmail, "auto_sync", "Auto sync completed", map[string]interface{}{
				"account_id":  account.ID,
				"synced_count": count,
			})
		}
	}
}
