package services

import (
	"log"
	"time"

	"github.com/luo-one/core/internal/database/models"
	"gorm.io/gorm"
)

// TokenScheduler handles automatic OAuth token refresh
type TokenScheduler struct {
	db             *gorm.DB
	emailService   *EmailService
	interval       time.Duration
	stopChan       chan struct{}
	running        bool
}

// NewTokenScheduler creates a new token scheduler
func NewTokenScheduler(db *gorm.DB, emailService *EmailService, interval time.Duration) *TokenScheduler {
	return &TokenScheduler{
		db:           db,
		emailService: emailService,
		interval:     interval,
		stopChan:     make(chan struct{}),
	}
}

// Start begins the token refresh scheduler
func (s *TokenScheduler) Start() {
	if s.running {
		return
	}
	s.running = true
	go s.run()
	log.Printf("[TokenScheduler] Started with interval %v", s.interval)
}

// Stop stops the token refresh scheduler
func (s *TokenScheduler) Stop() {
	if !s.running {
		return
	}
	close(s.stopChan)
	s.running = false
	log.Println("[TokenScheduler] Stopped")
}

func (s *TokenScheduler) run() {
	// Run immediately on start
	s.refreshExpiringTokens()

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.refreshExpiringTokens()
		case <-s.stopChan:
			return
		}
	}
}

// refreshExpiringTokens refreshes tokens that are about to expire
func (s *TokenScheduler) refreshExpiringTokens() {
	log.Println("[TokenScheduler] Checking for expiring tokens...")

	// Find OAuth accounts with tokens expiring in the next 10 minutes
	var accounts []models.EmailAccount
	threshold := time.Now().Add(10 * time.Minute)
	
	err := s.db.Where(
		"auth_type = ? AND oauth_provider = ? AND enabled = ? AND oauth_token_expiry < ?",
		models.AuthTypeOAuth2, "google", true, threshold,
	).Find(&accounts).Error

	if err != nil {
		log.Printf("[TokenScheduler] Error finding accounts: %v", err)
		return
	}

	if len(accounts) == 0 {
		log.Println("[TokenScheduler] No tokens need refresh")
		return
	}

	log.Printf("[TokenScheduler] Found %d accounts with expiring tokens", len(accounts))

	for _, account := range accounts {
		log.Printf("[TokenScheduler] Refreshing token for %s (expires at %v)", account.Email, account.OAuthTokenExpiry)
		
		_, err := s.emailService.refreshOAuthToken(&account)
		if err != nil {
			log.Printf("[TokenScheduler] Failed to refresh token for %s: %v", account.Email, err)
		} else {
			log.Printf("[TokenScheduler] Successfully refreshed token for %s", account.Email)
		}
	}

	log.Println("[TokenScheduler] Token refresh cycle completed")
}
