package services

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/mail"
	"net/smtp"
	"strings"
	"time"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/client"
	id "github.com/emersion/go-imap-id"
	"github.com/emersion/go-message"
	_ "github.com/emersion/go-message/charset"
	"github.com/luo-one/core/internal/database/models"
	"github.com/luo-one/core/internal/user"
	"gorm.io/gorm"
)

var (
	// ErrEmailNotFound indicates the email was not found
	ErrEmailNotFound = errors.New("email not found")
	// ErrIMAPConnectionFailed indicates IMAP connection failed
	ErrIMAPConnectionFailed = errors.New("IMAP connection failed")
	// ErrSMTPConnectionFailed indicates SMTP connection failed
	ErrSMTPConnectionFailed = errors.New("SMTP connection failed")
	// ErrEmailSendFailed indicates email sending failed
	ErrEmailSendFailed = errors.New("email send failed")
	// ErrAttachmentNotFound indicates attachment was not found
	ErrAttachmentNotFound = errors.New("attachment not found")
	// ErrInvalidEmailData indicates invalid email data
	ErrInvalidEmailData = errors.New("invalid email data")
)

// loginAuth implements smtp.Auth for LOGIN authentication
// Required for QQ Mail, 163 Mail and other Chinese email providers
type loginAuth struct {
	username, password string
}

func newLoginAuth(username, password string) smtp.Auth {
	return &loginAuth{username, password}
}

func (a *loginAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	return "LOGIN", []byte{}, nil
}

func (a *loginAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if more {
		switch string(fromServer) {
		case "Username:", "username:":
			return []byte(a.username), nil
		case "Password:", "password:":
			return []byte(a.password), nil
		default:
			// Some servers send base64 encoded prompts
			decoded, err := base64.StdEncoding.DecodeString(string(fromServer))
			if err == nil {
				switch strings.ToLower(string(decoded)) {
				case "username:", "username":
					return []byte(a.username), nil
				case "password:", "password":
					return []byte(a.password), nil
				}
			}
			return nil, fmt.Errorf("unexpected server challenge: %s", fromServer)
		}
	}
	return nil, nil
}

// EmailService handles email-related business logic
type EmailService struct {
	db             *gorm.DB
	accountService *AccountService
	userManager    *user.Manager
	userStorage    *user.Storage
	logService     *LogService
}

// NewEmailService creates a new EmailService instance
func NewEmailService(db *gorm.DB, accountService *AccountService, userManager *user.Manager) *EmailService {
	return &EmailService{
		db:             db,
		accountService: accountService,
		userManager:    userManager,
		userStorage:    user.NewStorage(userManager),
		logService:     NewLogService(db),
	}
}


// FetchedEmail represents an email fetched from IMAP
type FetchedEmail struct {
	UID            uint32
	MessageID      string
	Subject        string
	From           string
	To             []string
	Date           time.Time
	Body           string
	HTMLBody       string
	HasAttachments bool
	RawContent     []byte
	Attachments    []FetchedAttachment
}

// FetchedAttachment represents an attachment from a fetched email
type FetchedAttachment struct {
	Filename    string
	ContentType string
	Content     []byte
}

// connectIMAP establishes an IMAP connection to the email server
func (s *EmailService) connectIMAP(account *models.EmailAccount) (*client.Client, error) {
	password, err := s.accountService.GetDecryptedPassword(account)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrIMAPConnectionFailed, err)
	}

	addr := fmt.Sprintf("%s:%d", account.IMAPHost, account.IMAPPort)
	var c *client.Client

	if account.UseSSL {
		tlsConfig := &tls.Config{ServerName: account.IMAPHost}
		c, err = client.DialTLS(addr, tlsConfig)
	} else {
		c, err = client.Dial(addr)
	}

	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrIMAPConnectionFailed, err)
	}

	// Send IMAP ID command for servers that require client identification (e.g., 188.com, 163.com)
	// This must be done before login for some email providers
	if ok, _ := c.Support("ID"); ok {
		idClient := id.NewClient(c)
		_, err = idClient.ID(id.ID{
			id.FieldName:    "Luo One",
			id.FieldVersion: "1.0.0",
			id.FieldVendor:  "Luo One",
		})
		if err != nil {
			// Log but don't fail - some servers may not require ID
		}
	}

	if err := c.Login(account.Username, password); err != nil {
		c.Logout()
		return nil, fmt.Errorf("%w: login failed: %v", ErrIMAPConnectionFailed, err)
	}

	return c, nil
}

// FetchNewEmails fetches new emails from an account since the last sync
func (s *EmailService) FetchNewEmails(userID, accountID uint) ([]FetchedEmail, error) {
	return s.FetchNewEmailsWithDays(userID, accountID, 0)
}

// FetchNewEmailsWithDays fetches emails from an account within specified days (0 means use last sync time or default 30 days)
func (s *EmailService) FetchNewEmailsWithDays(userID, accountID uint, days int) ([]FetchedEmail, error) {
	account, err := s.accountService.GetAccountByIDAndUserID(accountID, userID)
	if err != nil {
		return nil, err
	}

	if !account.Enabled {
		return nil, errors.New("account is disabled")
	}

	c, err := s.connectIMAP(account)
	if err != nil {
		s.logService.LogError(userID, models.LogModuleEmail, "fetch", "IMAP connection failed", map[string]interface{}{
			"account_id": accountID,
			"error":      err.Error(),
		})
		return nil, err
	}
	defer c.Logout()

	// Select INBOX (read-only mode for safety)
	mbox, err := c.Select("INBOX", false)
	if err != nil {
		return nil, fmt.Errorf("failed to select INBOX: %v", err)
	}

	s.logService.LogInfo(userID, models.LogModuleEmail, "fetch", "INBOX selected", map[string]interface{}{
		"account_id":     accountID,
		"total_messages": mbox.Messages,
		"last_sync_at":   account.LastSyncAt,
		"fetch_days":     days,
	})

	if mbox.Messages == 0 {
		return []FetchedEmail{}, nil
	}

	// Determine search criteria based on days parameter
	// days == -1: fetch all emails (no criteria)
	// days == 0: incremental sync (use SINCE if has last sync)
	// days > 0: fetch emails from last N days
	criteria := imap.NewSearchCriteria()
	useSince := false
	
	if days == -1 {
		// Fetch all emails - no criteria needed
		s.logService.LogInfo(userID, models.LogModuleEmail, "fetch", "Fetching all emails (days=-1)", map[string]interface{}{
			"total": mbox.Messages,
		})
	} else if days == 0 {
		// Incremental sync - check if we have existing emails
		var existingCount int64
		_ = s.db.Model(&models.Email{}).Where("account_id = ?", accountID).Count(&existingCount).Error

		if existingCount > 0 && !account.LastSyncAt.IsZero() {
			// Use SINCE for incremental sync
			sinceDate := account.LastSyncAt.AddDate(0, 0, -1)
			criteria.Since = time.Date(sinceDate.Year(), sinceDate.Month(), sinceDate.Day(), 0, 0, 0, 0, time.UTC)
			useSince = true
			s.logService.LogInfo(userID, models.LogModuleEmail, "fetch", "Incremental sync with SINCE", map[string]interface{}{
				"since":          criteria.Since,
				"existing_count": existingCount,
			})
		} else {
			// First sync - fetch all
			s.logService.LogInfo(userID, models.LogModuleEmail, "fetch", "First sync, fetching all emails", map[string]interface{}{
				"total": mbox.Messages,
			})
		}
	} else {
		// Fetch emails from last N days
		sinceDate := time.Now().AddDate(0, 0, -days)
		criteria.Since = time.Date(sinceDate.Year(), sinceDate.Month(), sinceDate.Day(), 0, 0, 0, 0, time.UTC)
		useSince = true
		s.logService.LogInfo(userID, models.LogModuleEmail, "fetch", "Fetching emails by days", map[string]interface{}{
			"days":  days,
			"since": criteria.Since,
		})
	}

	// Use Search to get sequence numbers
	seqNums, err := c.Search(criteria)
	if err != nil {
		s.logService.LogWarn(userID, models.LogModuleEmail, "fetch", "Search failed", map[string]interface{}{
			"error": err.Error(),
		})
		// Fallback: use sequence range 1:*
		seqNums = make([]uint32, mbox.Messages)
		for i := uint32(1); i <= mbox.Messages; i++ {
			seqNums[i-1] = i
		}
	}

	s.logService.LogInfo(userID, models.LogModuleEmail, "fetch", "Search completed", map[string]interface{}{
		"account_id": accountID,
		"found_msgs": len(seqNums),
		"use_since":  useSince,
	})

	// If SINCE search returned 0 results but we expected some, fallback to all
	if len(seqNums) == 0 && useSince && mbox.Messages > 0 {
		s.logService.LogWarn(userID, models.LogModuleEmail, "fetch", "SINCE search returned 0, falling back to all messages", map[string]interface{}{
			"total_messages": mbox.Messages,
		})
		seqNums = make([]uint32, mbox.Messages)
		for i := uint32(1); i <= mbox.Messages; i++ {
			seqNums[i-1] = i
		}
	}

	if len(seqNums) == 0 {
		return []FetchedEmail{}, nil
	}

	// Build sequence set
	seqSet := new(imap.SeqSet)
	seqSet.AddNum(seqNums...)

	// Fetch messages
	items := []imap.FetchItem{imap.FetchUid, imap.FetchEnvelope, imap.FetchRFC822, imap.FetchBodyStructure, imap.FetchFlags}
	messages := make(chan *imap.Message, 10)
	done := make(chan error, 1)

	go func() {
		done <- c.Fetch(seqSet, items, messages)
	}()

	var fetchedEmails []FetchedEmail
	var parseErrors int
	var fallbackMessageIDs int
	for msg := range messages {
		if msg == nil {
			continue
		}
		email, err := s.parseIMAPMessage(msg)
		if err != nil {
			parseErrors++
			continue
		}
		if strings.HasPrefix(email.MessageID, "uid:") || strings.HasPrefix(email.MessageID, "sha256:") || strings.HasPrefix(email.MessageID, "gen:") {
			fallbackMessageIDs++
		}
		fetchedEmails = append(fetchedEmails, email)
	}

	if err := <-done; err != nil {
		return nil, fmt.Errorf("failed to fetch messages: %v", err)
	}

	s.logService.LogInfo(userID, models.LogModuleEmail, "fetch", "Fetch completed", map[string]interface{}{
		"account_id":    accountID,
		"fetched_count": len(fetchedEmails),
		"parse_errors":  parseErrors,
		"fallback_ids":  fallbackMessageIDs,
	})

	return fetchedEmails, nil
}


// parseIMAPMessage parses an IMAP message into a FetchedEmail
func (s *EmailService) parseIMAPMessage(msg *imap.Message) (FetchedEmail, error) {
	email := FetchedEmail{}
	email.UID = msg.Uid

	if msg.Envelope != nil {
		email.MessageID = msg.Envelope.MessageId
		email.Subject = msg.Envelope.Subject
		email.Date = msg.Envelope.Date

		if len(msg.Envelope.From) > 0 {
			email.From = formatAddress(msg.Envelope.From[0])
		}

		for _, addr := range msg.Envelope.To {
			email.To = append(email.To, formatAddress(addr))
		}
	}

	// Get raw content
	for _, literal := range msg.Body {
		content, err := io.ReadAll(literal)
		if err != nil {
			continue
		}
		email.RawContent = content

		// Parse the message body
		r := bytes.NewReader(content)
		entity, err := message.Read(r)
		if err != nil {
			// Try parsing as plain mail
			r.Seek(0, io.SeekStart)
			m, err := mail.ReadMessage(r)
			if err == nil {
				if email.MessageID == "" {
					messageID := strings.TrimSpace(m.Header.Get("Message-Id"))
					if messageID == "" {
						messageID = strings.TrimSpace(m.Header.Get("Message-ID"))
					}
					email.MessageID = messageID
				}
				body, _ := io.ReadAll(m.Body)
				email.Body = string(body)
			}
			continue
		}

		if email.MessageID == "" {
			messageID := strings.TrimSpace(entity.Header.Get("Message-Id"))
			if messageID == "" {
				messageID = strings.TrimSpace(entity.Header.Get("Message-ID"))
			}
			email.MessageID = messageID
		}

		s.parseMessageEntity(entity, &email)
	}

	if email.MessageID == "" {
		if email.UID != 0 {
			email.MessageID = fmt.Sprintf("uid:%d", email.UID)
		} else if len(email.RawContent) > 0 {
			sum := sha256.Sum256(email.RawContent)
			email.MessageID = "sha256:" + hex.EncodeToString(sum[:])
		} else {
			seed := fmt.Sprintf("%d|%s|%s|%s", email.Date.UnixNano(), email.Subject, email.From, strings.Join(email.To, ","))
			sum := sha256.Sum256([]byte(seed))
			email.MessageID = "gen:" + hex.EncodeToString(sum[:16])
		}
	}

	// Check for attachments from body structure
	if msg.BodyStructure != nil {
		email.HasAttachments = hasAttachments(msg.BodyStructure)
	}

	return email, nil
}

// parseMessageEntity recursively parses a message entity
func (s *EmailService) parseMessageEntity(entity *message.Entity, email *FetchedEmail) {
	mediaType, params, _ := entity.Header.ContentType()

	if strings.HasPrefix(mediaType, "multipart/") {
		mr := entity.MultipartReader()
		for {
			part, err := mr.NextPart()
			if err != nil {
				break
			}
			s.parseMessageEntity(part, email)
		}
	} else if mediaType == "text/plain" && email.Body == "" {
		body, _ := io.ReadAll(entity.Body)
		email.Body = string(body)
	} else if mediaType == "text/html" && email.HTMLBody == "" {
		body, _ := io.ReadAll(entity.Body)
		email.HTMLBody = string(body)
	} else if params["name"] != "" || entity.Header.Get("Content-Disposition") != "" {
		// This is an attachment
		content, _ := io.ReadAll(entity.Body)
		filename := params["name"]
		if filename == "" {
			filename = "attachment"
		}
		email.Attachments = append(email.Attachments, FetchedAttachment{
			Filename:    filename,
			ContentType: mediaType,
			Content:     content,
		})
		email.HasAttachments = true
	}
}

// formatAddress formats an IMAP address to a string
func formatAddress(addr *imap.Address) string {
	if addr.PersonalName != "" {
		return fmt.Sprintf("%s <%s@%s>", addr.PersonalName, addr.MailboxName, addr.HostName)
	}
	return fmt.Sprintf("%s@%s", addr.MailboxName, addr.HostName)
}

// hasAttachments checks if a body structure has attachments
func hasAttachments(bs *imap.BodyStructure) bool {
	if bs.Disposition == "attachment" {
		return true
	}
	for _, part := range bs.Parts {
		if hasAttachments(part) {
			return true
		}
	}
	return false
}


// SyncAndSaveEmails fetches new emails and saves them to the database and file system
// Uses the account's configured sync_days setting
func (s *EmailService) SyncAndSaveEmails(userID, accountID uint) (int, error) {
	// Get account to read sync_days setting
	account, err := s.accountService.GetAccountByIDAndUserID(accountID, userID)
	if err != nil {
		return 0, err
	}
	return s.SyncAndSaveEmailsWithDays(userID, accountID, account.SyncDays)
}

// SyncAndSaveEmailsWithDays fetches emails within specified days and saves them
func (s *EmailService) SyncAndSaveEmailsWithDays(userID, accountID uint, days int) (int, error) {
	syncStartedAt := time.Now()

	// Ensure account directories exist
	if err := s.userManager.CreateAccountDirectories(userID, accountID); err != nil {
		return 0, err
	}

	// Fetch new emails
	fetchedEmails, err := s.FetchNewEmailsWithDays(userID, accountID, days)
	if err != nil {
		return 0, err
	}

	savedCount := 0
	for _, fetched := range fetchedEmails {
		// Check if email already exists
		var existing models.Email
		if err := s.db.Where("account_id = ? AND message_id = ?", accountID, fetched.MessageID).First(&existing).Error; err == nil {
			continue // Email already exists
		}

		// Save raw email to file
		rawFilePath, err := s.userStorage.SaveRawEmail(userID, accountID, fetched.MessageID, fetched.RawContent)
		if err != nil {
			s.logService.LogError(userID, models.LogModuleEmail, "save_raw", "Failed to save raw email", map[string]interface{}{
				"message_id": fetched.MessageID,
				"error":      err.Error(),
			})
			continue
		}

		// Convert To addresses to JSON
		toAddrsJSON, _ := json.Marshal(fetched.To)

		// Create email record
		email := &models.Email{
			AccountID:      accountID,
			MessageID:      fetched.MessageID,
			Subject:        fetched.Subject,
			FromAddr:       fetched.From,
			ToAddrs:        string(toAddrsJSON),
			Date:           fetched.Date,
			Body:           fetched.Body,
			HTMLBody:       fetched.HTMLBody,
			HasAttachments: fetched.HasAttachments,
			IsRead:         false,
			Folder:         models.FolderInbox,
			RawFilePath:    rawFilePath,
		}

		if err := s.db.Create(email).Error; err != nil {
			s.logService.LogError(userID, models.LogModuleEmail, "save_db", "Failed to save email to database", map[string]interface{}{
				"message_id": fetched.MessageID,
				"error":      err.Error(),
			})
			continue
		}

		// Save attachments if any
		for _, att := range fetched.Attachments {
			_, err := s.userStorage.SaveAttachment(userID, email.ID, att.Filename, att.Content)
			if err != nil {
				s.logService.LogWarn(userID, models.LogModuleEmail, "save_attachment", "Failed to save attachment", map[string]interface{}{
					"email_id": email.ID,
					"filename": att.Filename,
					"error":    err.Error(),
				})
			}
		}

		savedCount++
	}

	// Update last sync time
	s.db.Model(&models.EmailAccount{}).Where("id = ?", accountID).Update("last_sync_at", syncStartedAt)

	// Log sync completion
	s.logService.LogInfo(userID, models.LogModuleEmail, "sync", "Email sync completed", map[string]interface{}{
		"account_id":  accountID,
		"saved_count": savedCount,
	})

	return savedCount, nil
}

// GetEmailByID retrieves an email by ID
func (s *EmailService) GetEmailByID(id uint) (*models.Email, error) {
	var email models.Email
	if err := s.db.Preload("ProcessedResult").First(&email, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrEmailNotFound
		}
		return nil, err
	}
	return &email, nil
}

// GetEmailByIDAndUserID retrieves an email by ID and verifies user ownership through account
func (s *EmailService) GetEmailByIDAndUserID(id, userID uint) (*models.Email, error) {
	var email models.Email
	if err := s.db.Preload("ProcessedResult").First(&email, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrEmailNotFound
		}
		return nil, err
	}

	// Verify user owns the account
	_, err := s.accountService.GetAccountByIDAndUserID(email.AccountID, userID)
	if err != nil {
		return nil, ErrEmailNotFound
	}

	return &email, nil
}


// EmailListOptions represents options for listing emails
type EmailListOptions struct {
	AccountID uint
	Folder    string // inbox, sent, trash, all
	Page      int
	Limit     int
	SortBy    string // "date" or "from"
	SortOrder string // "asc" or "desc"
	Search    string
}

// EmailListResult represents the result of listing emails
type EmailListResult struct {
	Total  int64          `json:"total"`
	Page   int            `json:"page"`
	Limit  int            `json:"limit"`
	Emails []models.Email `json:"emails"`
}

// ListEmails lists emails with pagination and filtering
func (s *EmailService) ListEmails(userID uint, opts EmailListOptions) (*EmailListResult, error) {
	// Verify user owns the account
	if opts.AccountID > 0 {
		_, err := s.accountService.GetAccountByIDAndUserID(opts.AccountID, userID)
		if err != nil {
			return nil, err
		}
	}

	// Set defaults
	if opts.Page < 1 {
		opts.Page = 1
	}
	if opts.Limit < 1 || opts.Limit > 100 {
		opts.Limit = 20
	}
	if opts.SortBy == "" {
		opts.SortBy = "date"
	}
	if opts.SortOrder == "" {
		opts.SortOrder = "desc"
	}

	// Build query
	query := s.db.Model(&models.Email{}).Preload("ProcessedResult")

	// Filter by account if specified
	if opts.AccountID > 0 {
		query = query.Where("account_id = ?", opts.AccountID)
	} else {
		// Get all accounts for user
		accounts, err := s.accountService.GetAccountsByUserID(userID)
		if err != nil {
			return nil, err
		}
		var accountIDs []uint
		for _, acc := range accounts {
			accountIDs = append(accountIDs, acc.ID)
		}
		if len(accountIDs) > 0 {
			query = query.Where("account_id IN ?", accountIDs)
		} else {
			return &EmailListResult{
				Total:  0,
				Page:   opts.Page,
				Limit:  opts.Limit,
				Emails: []models.Email{},
			}, nil
		}
	}

	// Filter by folder
	if opts.Folder != "" && opts.Folder != "all" {
		query = query.Where("folder = ?", opts.Folder)
	}

	// Search filter
	if opts.Search != "" {
		searchPattern := "%" + opts.Search + "%"
		query = query.Where("subject LIKE ? OR from_addr LIKE ? OR body LIKE ?", searchPattern, searchPattern, searchPattern)
	}

	// Count total
	var total int64
	query.Count(&total)

	// Sort
	orderClause := "date DESC"
	if opts.SortBy == "from" {
		if opts.SortOrder == "asc" {
			orderClause = "from_addr ASC"
		} else {
			orderClause = "from_addr DESC"
		}
	} else {
		if opts.SortOrder == "asc" {
			orderClause = "date ASC"
		} else {
			orderClause = "date DESC"
		}
	}
	query = query.Order(orderClause)

	// Pagination
	offset := (opts.Page - 1) * opts.Limit
	query = query.Offset(offset).Limit(opts.Limit)

	// Execute query
	var emails []models.Email
	if err := query.Find(&emails).Error; err != nil {
		return nil, err
	}

	return &EmailListResult{
		Total:  total,
		Page:   opts.Page,
		Limit:  opts.Limit,
		Emails: emails,
	}, nil
}

// MarkEmailAsRead marks an email as read
func (s *EmailService) MarkEmailAsRead(id, userID uint) error {
	email, err := s.GetEmailByIDAndUserID(id, userID)
	if err != nil {
		return err
	}

	return s.db.Model(email).Update("is_read", true).Error
}

// MoveToTrash moves an email to trash folder
func (s *EmailService) MoveToTrash(id, userID uint) error {
	email, err := s.GetEmailByIDAndUserID(id, userID)
	if err != nil {
		return err
	}

	return s.db.Model(email).Update("folder", models.FolderTrash).Error
}

// DeleteEmail permanently deletes an email (only from trash)
func (s *EmailService) DeleteEmail(id, userID uint) error {
	// Verify user owns the email first
	email, err := s.GetEmailByIDAndUserID(id, userID)
	if err != nil {
		return err
	}

	// Only allow permanent deletion from trash
	if email.Folder != models.FolderTrash {
		// If not in trash, move to trash instead
		return s.db.Model(email).Update("folder", models.FolderTrash).Error
	}

	// Use transaction to ensure both deletions succeed or fail together
	return s.db.Transaction(func(tx *gorm.DB) error {
		// Delete processed result if exists (hard delete)
		if err := tx.Unscoped().Where("email_id = ?", id).Delete(&models.ProcessedResult{}).Error; err != nil {
			return err
		}

		// Delete email record (hard delete by ID)
		if err := tx.Unscoped().Delete(&models.Email{}, id).Error; err != nil {
			return err
		}

		return nil
	})
}


// SendEmailRequest represents a request to send an email
type SendEmailRequest struct {
	AccountID   uint     `json:"account_id"`
	To          []string `json:"to"`
	Cc          []string `json:"cc"`
	Bcc         []string `json:"bcc"`
	Subject     string   `json:"subject"`
	Body        string   `json:"body"`
	HTMLBody    string   `json:"html_body"`
	Attachments []string `json:"attachments"` // Attachment filenames
}

// SendEmailResult represents the result of sending an email
type SendEmailResult struct {
	Success   bool   `json:"success"`
	MessageID string `json:"message_id,omitempty"`
	Error     string `json:"error,omitempty"`
}

// SendEmail sends an email through the specified account
func (s *EmailService) SendEmail(userID uint, req SendEmailRequest) (*SendEmailResult, error) {
	// Validate request
	if req.AccountID == 0 {
		return nil, ErrInvalidEmailData
	}
	if len(req.To) == 0 {
		return nil, errors.New("at least one recipient is required")
	}
	if req.Subject == "" {
		return nil, errors.New("subject is required")
	}
	if req.Body == "" && req.HTMLBody == "" {
		return nil, errors.New("body is required")
	}

	// Get account
	account, err := s.accountService.GetAccountByIDAndUserID(req.AccountID, userID)
	if err != nil {
		return nil, err
	}

	if !account.Enabled {
		return nil, errors.New("account is disabled")
	}

	// Get decrypted password
	password, err := s.accountService.GetDecryptedPassword(account)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSMTPConnectionFailed, err)
	}

	// Build email message
	messageID := generateMessageID(account.Email)
	emailContent := s.buildEmailContent(account, req, messageID)

	// Connect and send
	err = s.sendViaSMTP(account, password, req, emailContent)
	if err != nil {
		// Log the failure
		s.logService.LogError(userID, models.LogModuleEmail, "send", "Email send failed", map[string]interface{}{
			"account_id": req.AccountID,
			"to":         req.To,
			"subject":    req.Subject,
			"error":      err.Error(),
		})
		return &SendEmailResult{
			Success: false,
			Error:   err.Error(),
		}, nil
	}

	// Log success
	s.logService.LogInfo(userID, models.LogModuleEmail, "send", "Email sent successfully", map[string]interface{}{
		"account_id": req.AccountID,
		"to":         req.To,
		"subject":    req.Subject,
		"message_id": messageID,
	})

	// Save sent email to database
	toAddrsJSON, _ := json.Marshal(req.To)
	sentEmail := &models.Email{
		AccountID:      req.AccountID,
		MessageID:      messageID,
		Subject:        req.Subject,
		FromAddr:       account.Email,
		ToAddrs:        string(toAddrsJSON),
		Date:           time.Now(),
		Body:           req.Body,
		HTMLBody:       req.HTMLBody,
		HasAttachments: len(req.Attachments) > 0,
		IsRead:         true,
		Folder:         models.FolderSent,
	}
	s.db.Create(sentEmail)

	return &SendEmailResult{
		Success:   true,
		MessageID: messageID,
	}, nil
}

// buildEmailContent builds the email content string
func (s *EmailService) buildEmailContent(account *models.EmailAccount, req SendEmailRequest, messageID string) string {
	var buf bytes.Buffer

	// Headers
	buf.WriteString(fmt.Sprintf("From: %s <%s>\r\n", account.DisplayName, account.Email))
	buf.WriteString(fmt.Sprintf("To: %s\r\n", strings.Join(req.To, ", ")))
	if len(req.Cc) > 0 {
		buf.WriteString(fmt.Sprintf("Cc: %s\r\n", strings.Join(req.Cc, ", ")))
	}
	buf.WriteString(fmt.Sprintf("Subject: %s\r\n", req.Subject))
	buf.WriteString(fmt.Sprintf("Message-ID: %s\r\n", messageID))
	buf.WriteString(fmt.Sprintf("Date: %s\r\n", time.Now().Format(time.RFC1123Z)))
	buf.WriteString("MIME-Version: 1.0\r\n")

	if req.HTMLBody != "" {
		// Multipart message with both plain text and HTML
		boundary := generateBoundary()
		buf.WriteString(fmt.Sprintf("Content-Type: multipart/alternative; boundary=\"%s\"\r\n", boundary))
		buf.WriteString("\r\n")

		// Plain text part
		buf.WriteString(fmt.Sprintf("--%s\r\n", boundary))
		buf.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
		buf.WriteString("Content-Transfer-Encoding: quoted-printable\r\n")
		buf.WriteString("\r\n")
		buf.WriteString(req.Body)
		buf.WriteString("\r\n")

		// HTML part
		buf.WriteString(fmt.Sprintf("--%s\r\n", boundary))
		buf.WriteString("Content-Type: text/html; charset=utf-8\r\n")
		buf.WriteString("Content-Transfer-Encoding: quoted-printable\r\n")
		buf.WriteString("\r\n")
		buf.WriteString(req.HTMLBody)
		buf.WriteString("\r\n")

		buf.WriteString(fmt.Sprintf("--%s--\r\n", boundary))
	} else {
		// Plain text only
		buf.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
		buf.WriteString("\r\n")
		buf.WriteString(req.Body)
	}

	return buf.String()
}

// sendViaSMTP sends the email via SMTP
func (s *EmailService) sendViaSMTP(account *models.EmailAccount, password string, req SendEmailRequest, content string) error {
	addr := fmt.Sprintf("%s:%d", account.SMTPHost, account.SMTPPort)

	// Collect all recipients
	var recipients []string
	recipients = append(recipients, req.To...)
	recipients = append(recipients, req.Cc...)
	recipients = append(recipients, req.Bcc...)

	// Determine auth method based on host
	// QQ Mail, 163 Mail, and other Chinese providers require LOGIN auth
	useLoginAuth := strings.Contains(account.SMTPHost, "qq.com") ||
		strings.Contains(account.SMTPHost, "163.com") ||
		strings.Contains(account.SMTPHost, "126.com") ||
		strings.Contains(account.SMTPHost, "yeah.net") ||
		strings.Contains(account.SMTPHost, "sina.com") ||
		strings.Contains(account.SMTPHost, "sohu.com") ||
		strings.Contains(account.SMTPHost, "aliyun.com") ||
		strings.Contains(account.SMTPHost, "188.com")

	if account.UseSSL {
		// Connect with TLS (SMTPS)
		tlsConfig := &tls.Config{
			ServerName: account.SMTPHost,
		}
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: connectionTimeout}, "tcp", addr, tlsConfig)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrSMTPConnectionFailed, err)
		}
		defer conn.Close()

		client, err := smtp.NewClient(conn, account.SMTPHost)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrSMTPConnectionFailed, err)
		}
		defer client.Close()

		// Authenticate - try LOGIN auth first for Chinese providers, fallback to PLAIN
		var auth smtp.Auth
		if useLoginAuth {
			auth = newLoginAuth(account.Username, password)
		} else {
			auth = smtp.PlainAuth("", account.Username, password, account.SMTPHost)
		}
		
		if err := client.Auth(auth); err != nil {
			// If LOGIN auth failed, try PLAIN auth as fallback
			if useLoginAuth {
				auth = smtp.PlainAuth("", account.Username, password, account.SMTPHost)
				if err2 := client.Auth(auth); err2 != nil {
					return fmt.Errorf("authentication failed (tried LOGIN and PLAIN): %v", err)
				}
			} else {
				// If PLAIN auth failed, try LOGIN auth as fallback
				auth = newLoginAuth(account.Username, password)
				if err2 := client.Auth(auth); err2 != nil {
					return fmt.Errorf("authentication failed (tried PLAIN and LOGIN): %v", err)
				}
			}
		}

		// Send email
		if err := client.Mail(account.Email); err != nil {
			return fmt.Errorf("MAIL FROM failed: %v", err)
		}

		for _, rcpt := range recipients {
			if err := client.Rcpt(rcpt); err != nil {
				return fmt.Errorf("RCPT TO failed for %s: %v", rcpt, err)
			}
		}

		w, err := client.Data()
		if err != nil {
			return fmt.Errorf("DATA failed: %v", err)
		}

		_, err = w.Write([]byte(content))
		if err != nil {
			return fmt.Errorf("write failed: %v", err)
		}

		err = w.Close()
		if err != nil {
			return fmt.Errorf("close failed: %v", err)
		}

		return client.Quit()
	}

	// Non-SSL connection with optional STARTTLS
	client, err := smtp.Dial(addr)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrSMTPConnectionFailed, err)
	}
	defer client.Close()

	// Try STARTTLS if available
	if ok, _ := client.Extension("STARTTLS"); ok {
		tlsConfig := &tls.Config{ServerName: account.SMTPHost}
		if err := client.StartTLS(tlsConfig); err != nil {
			// Continue without TLS if STARTTLS fails
		}
	}

	// Authenticate - try LOGIN auth first for Chinese providers, fallback to PLAIN
	var auth smtp.Auth
	if useLoginAuth {
		auth = newLoginAuth(account.Username, password)
	} else {
		auth = smtp.PlainAuth("", account.Username, password, account.SMTPHost)
	}
	
	if err := client.Auth(auth); err != nil {
		// If LOGIN auth failed, try PLAIN auth as fallback
		if useLoginAuth {
			auth = smtp.PlainAuth("", account.Username, password, account.SMTPHost)
			if err2 := client.Auth(auth); err2 != nil {
				return fmt.Errorf("authentication failed (tried LOGIN and PLAIN): %v", err)
			}
		} else {
			// If PLAIN auth failed, try LOGIN auth as fallback
			auth = newLoginAuth(account.Username, password)
			if err2 := client.Auth(auth); err2 != nil {
				return fmt.Errorf("authentication failed (tried PLAIN and LOGIN): %v", err)
			}
		}
	}

	// Send email
	if err := client.Mail(account.Email); err != nil {
		return fmt.Errorf("MAIL FROM failed: %v", err)
	}

	for _, rcpt := range recipients {
		if err := client.Rcpt(rcpt); err != nil {
			return fmt.Errorf("RCPT TO failed for %s: %v", rcpt, err)
		}
	}

	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("DATA failed: %v", err)
	}

	_, err = w.Write([]byte(content))
	if err != nil {
		return fmt.Errorf("write failed: %v", err)
	}

	err = w.Close()
	if err != nil {
		return fmt.Errorf("close failed: %v", err)
	}

	return client.Quit()
}

// generateMessageID generates a unique message ID
func generateMessageID(email string) string {
	timestamp := time.Now().UnixNano()
	domain := "localhost"
	parts := strings.Split(email, "@")
	if len(parts) == 2 {
		domain = parts[1]
	}
	return fmt.Sprintf("<%d.%s@%s>", timestamp, randomString(8), domain)
}

// generateBoundary generates a MIME boundary
func generateBoundary() string {
	return fmt.Sprintf("----=_Part_%d_%s", time.Now().UnixNano(), randomString(16))
}

// randomString generates a random alphanumeric string
func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[time.Now().UnixNano()%int64(len(letters))]
		time.Sleep(time.Nanosecond)
	}
	return string(b)
}


// AttachmentInfo represents information about an attachment
type AttachmentInfo struct {
	Filename string `json:"filename"`
	Size     int64  `json:"size"`
	Path     string `json:"path"`
}

// UploadAttachment uploads an attachment for an email
func (s *EmailService) UploadAttachment(userID, emailID uint, filename string, content []byte) (*AttachmentInfo, error) {
	// Verify user owns the email
	email, err := s.GetEmailByIDAndUserID(emailID, userID)
	if err != nil {
		return nil, err
	}

	// Save attachment
	path, err := s.userStorage.SaveAttachment(userID, emailID, filename, content)
	if err != nil {
		s.logService.LogError(userID, models.LogModuleEmail, "upload_attachment", "Failed to upload attachment", map[string]interface{}{
			"email_id": emailID,
			"filename": filename,
			"error":    err.Error(),
		})
		return nil, err
	}

	// Update email has_attachments flag
	if !email.HasAttachments {
		s.db.Model(email).Update("has_attachments", true)
	}

	s.logService.LogInfo(userID, models.LogModuleEmail, "upload_attachment", "Attachment uploaded", map[string]interface{}{
		"email_id": emailID,
		"filename": filename,
		"size":     len(content),
	})

	return &AttachmentInfo{
		Filename: filename,
		Size:     int64(len(content)),
		Path:     path,
	}, nil
}

// DownloadAttachment downloads an attachment
func (s *EmailService) DownloadAttachment(userID, emailID uint, filename string) ([]byte, error) {
	// Verify user owns the email
	_, err := s.GetEmailByIDAndUserID(emailID, userID)
	if err != nil {
		return nil, err
	}

	// Get attachment
	content, err := s.userStorage.GetAttachment(userID, emailID, filename)
	if err != nil {
		if errors.Is(err, user.ErrFileNotFound) {
			return nil, ErrAttachmentNotFound
		}
		return nil, err
	}

	return content, nil
}

// ListAttachments lists all attachments for an email
func (s *EmailService) ListAttachments(userID, emailID uint) ([]AttachmentInfo, error) {
	// Verify user owns the email
	_, err := s.GetEmailByIDAndUserID(emailID, userID)
	if err != nil {
		return nil, err
	}

	// List attachments
	filenames, err := s.userStorage.ListAttachments(userID, emailID)
	if err != nil {
		return nil, err
	}

	var attachments []AttachmentInfo
	for _, filename := range filenames {
		content, err := s.userStorage.GetAttachment(userID, emailID, filename)
		if err != nil {
			continue
		}
		attachments = append(attachments, AttachmentInfo{
			Filename: filename,
			Size:     int64(len(content)),
		})
	}

	return attachments, nil
}

// DeleteAttachment deletes an attachment
func (s *EmailService) DeleteAttachment(userID, emailID uint, filename string) error {
	// Verify user owns the email
	_, err := s.GetEmailByIDAndUserID(emailID, userID)
	if err != nil {
		return err
	}

	// Delete attachment
	err = s.userStorage.DeleteAttachment(userID, emailID, filename)
	if err != nil {
		return err
	}

	// Check if there are any remaining attachments
	remaining, err := s.userStorage.ListAttachments(userID, emailID)
	if err == nil && len(remaining) == 0 {
		s.db.Model(&models.Email{}).Where("id = ?", emailID).Update("has_attachments", false)
	}

	s.logService.LogInfo(userID, models.LogModuleEmail, "delete_attachment", "Attachment deleted", map[string]interface{}{
		"email_id": emailID,
		"filename": filename,
	})

	return nil
}

// GetRawEmail retrieves the raw email content
func (s *EmailService) GetRawEmail(userID, emailID uint) ([]byte, error) {
	email, err := s.GetEmailByIDAndUserID(emailID, userID)
	if err != nil {
		return nil, err
	}

	// Get account to determine the account ID
	return s.userStorage.GetRawEmail(userID, email.AccountID, email.MessageID)
}
