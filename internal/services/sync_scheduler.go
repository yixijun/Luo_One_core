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
	syncing      sync.Mutex // 防止同步周期重叠
	accountLocks sync.Map   // 每个账户独立锁，防止同一账户并发同步
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
		// 启动后等待 10 秒再执行第一次同步，让服务完全就绪
		select {
		case <-time.After(10 * time.Second):
			log.Println("[SyncScheduler] Running first sync...")
			s.syncAllAccounts()
		case <-s.stopChan:
			return
		}

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

// IsAccountSyncing 检查某个账户是否正在同步（供手动同步使用）
func (s *SyncScheduler) IsAccountSyncing(accountID uint) bool {
	_, loaded := s.accountLocks.Load(accountID)
	return loaded
}

// TryLockAccount 尝试锁定账户（供手动同步使用，防止与自动同步冲突）
func (s *SyncScheduler) TryLockAccount(accountID uint) bool {
	_, loaded := s.accountLocks.LoadOrStore(accountID, true)
	return !loaded // 返回 true 表示成功获取锁
}

// UnlockAccount 解锁账户
func (s *SyncScheduler) UnlockAccount(accountID uint) {
	s.accountLocks.Delete(accountID)
}

// syncAllAccounts syncs all enabled accounts
func (s *SyncScheduler) syncAllAccounts() {
	// 防止同步周期重叠：如果上一轮还没结束，跳过本轮
	if !s.syncing.TryLock() {
		log.Println("[SyncScheduler] Previous sync still running, skipping this cycle")
		return
	}
	defer s.syncing.Unlock()

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

	// 并发同步所有账户，每个账户独立，互不阻塞
	var wg sync.WaitGroup
	for _, account := range accounts {
		// 尝试获取账户锁，如果已被手动同步占用则跳过
		if !s.TryLockAccount(account.ID) {
			log.Printf("[SyncScheduler] Account %d (%s) is already syncing, skipping", account.ID, account.Email)
			continue
		}

		wg.Add(1)
		go func(acc models.EmailAccount) {
			defer wg.Done()
			defer s.UnlockAccount(acc.ID)

			s.syncOneAccount(acc)
		}(account)
	}
	wg.Wait()

	log.Println("[SyncScheduler] Sync cycle completed")
}

// syncOneAccount 同步单个账户，带重试
func (s *SyncScheduler) syncOneAccount(account models.EmailAccount) {
	const maxRetries = 2
	var lastErr error

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			// 指数退避：第1次重试等2秒，第2次等4秒
			backoff := time.Duration(1<<uint(attempt)) * time.Second
			log.Printf("[SyncScheduler] Account %d retry %d/%d after %v", account.ID, attempt, maxRetries, backoff)

			select {
			case <-time.After(backoff):
			case <-s.stopChan:
				return
			}
		}

		count, err := s.emailService.SyncAndSaveEmails(account.UserID, account.ID)
		if err == nil {
			if attempt > 0 {
				log.Printf("[SyncScheduler] Account %d (%s) synced after %d retries: %d new emails", account.ID, account.Email, attempt, count)
			} else if count > 0 {
				log.Printf("[SyncScheduler] Account %d (%s) synced %d new emails", account.ID, account.Email, count)
			}
			if count > 0 {
				s.logService.LogInfo(account.UserID, models.LogModuleEmail, "auto_sync", "Auto sync completed", map[string]interface{}{
					"account_id":   account.ID,
					"synced_count": count,
				})
			}
			return
		}

		lastErr = err
		log.Printf("[SyncScheduler] Account %d (%s) sync attempt %d failed: %v", account.ID, account.Email, attempt+1, err)
	}

	// 所有重试都失败
	log.Printf("[SyncScheduler] Account %d (%s) sync failed after %d attempts: %v", account.ID, account.Email, maxRetries+1, lastErr)
	s.logService.LogWarn(account.UserID, models.LogModuleEmail, "auto_sync", "Auto sync failed", map[string]interface{}{
		"account_id": account.ID,
		"error":      lastErr.Error(),
		"retries":    maxRetries,
	})
}
