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

	log.Printf("[SyncScheduler] Starting with interval: %v", s.interval)

	go func() {
		// 启动后等待 10 秒再开始第一次同步
		log.Println("[SyncScheduler] Waiting 10 seconds before first sync...")
		time.Sleep(10 * time.Second)
		
		// 立即执行第一次同步
		log.Println("[SyncScheduler] Running first sync...")
		s.syncAllAccounts()

		ticker := time.NewTicker(s.interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				log.Println("[SyncScheduler] Running scheduled sync...")
				s.syncAllAccounts()
			case <-s.stopChan:
				log.Println("[SyncScheduler] Stopping")
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
		log.Printf("[SyncScheduler] Failed to get accounts: %v", err)
		return
	}

	if len(accounts) == 0 {
		log.Println("[SyncScheduler] No enabled accounts found")
		return
	}

	log.Printf("[SyncScheduler] Syncing %d accounts", len(accounts))

	for _, account := range accounts {
		log.Printf("[SyncScheduler] Syncing account %d (%s)", account.ID, account.Email)
		
		// 同步邮件
		count, err := s.emailService.SyncAndSaveEmails(account.UserID, account.ID)
		if err != nil {
			log.Printf("[SyncScheduler] Account %d sync failed: %v", account.ID, err)
			s.logService.LogWarn(account.UserID, models.LogModuleEmail, "auto_sync", "Auto sync failed", map[string]interface{}{
				"account_id": account.ID,
				"error":      err.Error(),
			})
			continue
		}

		log.Printf("[SyncScheduler] Account %d synced %d new emails", account.ID, count)
		if count > 0 {
			s.logService.LogInfo(account.UserID, models.LogModuleEmail, "auto_sync", "Auto sync completed", map[string]interface{}{
				"account_id":   account.ID,
				"synced_count": count,
			})
		}
	}
	
	log.Println("[SyncScheduler] Sync cycle completed")
}
