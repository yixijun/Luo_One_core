package services

import (
	"bytes"
	cryptoRand "crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/client"
	id "github.com/emersion/go-imap-id"
	"github.com/emersion/go-message"
	_ "github.com/emersion/go-message/charset"
	"github.com/luo-one/core/internal/database/models"
	"github.com/luo-one/core/internal/functions"
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
	processor      *functions.Processor
}

// NewEmailService creates a new EmailService instance
func NewEmailService(db *gorm.DB, accountService *AccountService, userManager *user.Manager) *EmailService {
	return &EmailService{
		db:             db,
		accountService: accountService,
		userManager:    userManager,
		userStorage:    user.NewStorage(userManager),
		logService:     NewLogService(db),
		processor:      functions.NewProcessor(db, userManager),
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
	addr := fmt.Sprintf("%s:%d", account.IMAPHost, account.IMAPPort)
	var c *client.Client

	// 设置连接超时为 10 秒
	dialer := &net.Dialer{Timeout: 10 * time.Second}

	if account.UseSSL {
		tlsConfig := &tls.Config{ServerName: account.IMAPHost}
		conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrIMAPConnectionFailed, err)
		}
		c, err = client.New(conn)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("%w: %v", ErrIMAPConnectionFailed, err)
		}
	} else {
		conn, err := dialer.Dial("tcp", addr)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrIMAPConnectionFailed, err)
		}
		c, err = client.New(conn)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("%w: %v", ErrIMAPConnectionFailed, err)
		}
	}

	// 设置命令超时为 5 分钟（全量同步需要更长时间）
	c.Timeout = 5 * time.Minute

	// Send IMAP ID command for servers that require client identification (e.g., 188.com, 163.com)
	// This must be done before login for some email providers
	if ok, _ := c.Support("ID"); ok {
		idClient := id.NewClient(c)
		_, err := idClient.ID(id.ID{
			id.FieldName:    "Luo One",
			id.FieldVersion: "1.0.0",
			id.FieldVendor:  "Luo One",
		})
		if err != nil {
			// Log but don't fail - some servers may not require ID
		}
	}

	// Authenticate based on auth type
	if account.AuthType == models.AuthTypeOAuth2 {
		// Use XOAUTH2 authentication
		accessToken, _, err := s.accountService.GetDecryptedOAuthTokens(account)
		if err != nil {
			c.Logout()
			return nil, fmt.Errorf("%w: failed to get OAuth tokens: %v", ErrIMAPConnectionFailed, err)
		}

		// Check if token needs refresh
		if account.OAuthTokenExpiry.Before(time.Now()) {
			accessToken, err = s.refreshOAuthToken(account)
			if err != nil {
				c.Logout()
				return nil, fmt.Errorf("%w: failed to refresh OAuth token: %v", ErrIMAPConnectionFailed, err)
			}
		}

		// XOAUTH2 authentication
		saslClient := NewXOAuth2Client(account.Username, accessToken)
		if err := c.Authenticate(saslClient); err != nil {
			c.Logout()
			return nil, fmt.Errorf("%w: XOAUTH2 authentication failed: %v", ErrIMAPConnectionFailed, err)
		}
	} else {
		// Traditional password authentication
		password, err := s.accountService.GetDecryptedPassword(account)
		if err != nil {
			c.Logout()
			return nil, fmt.Errorf("%w: %v", ErrIMAPConnectionFailed, err)
		}

		if err := c.Login(account.Username, password); err != nil {
			c.Logout()
			return nil, fmt.Errorf("%w: login failed: %v", ErrIMAPConnectionFailed, err)
		}
	}

	return c, nil
}

// XOAuth2Client implements the SASL XOAUTH2 mechanism
type XOAuth2Client struct {
	Username    string
	AccessToken string
}

// NewXOAuth2Client creates a new XOAUTH2 SASL client
func NewXOAuth2Client(username, accessToken string) *XOAuth2Client {
	return &XOAuth2Client{
		Username:    username,
		AccessToken: accessToken,
	}
}

// Start begins the XOAUTH2 authentication
func (c *XOAuth2Client) Start() (mech string, ir []byte, err error) {
	// XOAUTH2 initial response format: "user=" + user + "\x01auth=Bearer " + token + "\x01\x01"
	ir = []byte(fmt.Sprintf("user=%s\x01auth=Bearer %s\x01\x01", c.Username, c.AccessToken))
	return "XOAUTH2", ir, nil
}

// Next handles server challenges (XOAUTH2 doesn't have additional challenges)
func (c *XOAuth2Client) Next(challenge []byte) (response []byte, err error) {
	// XOAUTH2 doesn't have additional challenges, return empty response
	return nil, nil
}

// refreshOAuthToken refreshes the OAuth access token using the refresh token
func (s *EmailService) refreshOAuthToken(account *models.EmailAccount) (string, error) {
	_, refreshToken, err := s.accountService.GetDecryptedOAuthTokens(account)
	if err != nil {
		return "", err
	}

	if refreshToken == "" {
		return "", fmt.Errorf("no refresh token available")
	}

	// For Google OAuth
	if account.OAuthProvider == "google" {
		return s.refreshGoogleToken(account, refreshToken)
	}

	return "", fmt.Errorf("unsupported OAuth provider: %s", account.OAuthProvider)
}

// refreshGoogleToken refreshes a Google OAuth token
func (s *EmailService) refreshGoogleToken(account *models.EmailAccount, refreshToken string) (string, error) {
	// 首先尝试从数据库读取用户的 OAuth 配置
	var settings models.UserSettings
	if err := s.db.Where("user_id = ?", account.UserID).First(&settings).Error; err == nil {
		// 从数据库获取配置
		if settings.GoogleClientID != "" && settings.GoogleClientSecret != "" {
			return s.doGoogleTokenRefresh(account, settings.GoogleClientID, settings.GoogleClientSecret, refreshToken)
		}
	}

	// 回退到环境变量
	clientID := os.Getenv("GOOGLE_CLIENT_ID")
	clientSecret := os.Getenv("GOOGLE_CLIENT_SECRET")

	if clientID == "" || clientSecret == "" {
		return "", fmt.Errorf("Google OAuth credentials not configured")
	}

	return s.doGoogleTokenRefresh(account, clientID, clientSecret, refreshToken)
}

// doGoogleTokenRefresh performs the actual token refresh request
func (s *EmailService) doGoogleTokenRefresh(account *models.EmailAccount, clientID, clientSecret, refreshToken string) (string, error) {

	// Make token refresh request
	resp, err := http.PostForm("https://oauth2.googleapis.com/token", map[string][]string{
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"refresh_token": {refreshToken},
		"grant_type":    {"refresh_token"},
	})
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token refresh failed with status %d", resp.StatusCode)
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", err
	}

	// Update the token in database
	expiry := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	if err := s.accountService.UpdateOAuthTokens(account.ID, tokenResp.AccessToken, "", expiry); err != nil {
		return "", err
	}

	return tokenResp.AccessToken, nil
}

// FetchNewEmails fetches new emails from an account since the last sync
func (s *EmailService) FetchNewEmails(userID, accountID uint) ([]FetchedEmail, error) {
	return s.FetchNewEmailsWithDays(userID, accountID, 0)
}

// FetchNewEmailsWithDays fetches emails from an account within specified days (0 means use last sync time or default 30 days)
func (s *EmailService) FetchNewEmailsWithDays(userID, accountID uint, days int) ([]FetchedEmail, error) {
	return s.FetchNewEmailsWithOptions(userID, accountID, days, false)
}

// FetchNewEmailsWithOptions fetches emails with more control options
// noLimit: if true, don't limit the number of emails fetched (for full sync)
// 使用单连接顺序获取，更可靠
func (s *EmailService) FetchNewEmailsWithOptions(userID, accountID uint, days int, noLimit bool) ([]FetchedEmail, error) {
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

	// Select INBOX
	mbox, err := c.Select("INBOX", false)
	if err != nil {
		return nil, fmt.Errorf("failed to select INBOX: %v", err)
	}

	s.logService.LogInfo(userID, models.LogModuleEmail, "fetch", "INBOX selected", map[string]interface{}{
		"account_id":     accountID,
		"total_messages": mbox.Messages,
	})

	if mbox.Messages == 0 {
		return []FetchedEmail{}, nil
	}

	// Determine search criteria
	criteria := imap.NewSearchCriteria()
	if days == -1 {
		// Fetch all emails - no criteria
	} else if days == 0 {
		var existingCount int64
		s.db.Model(&models.Email{}).Where("account_id = ?", accountID).Count(&existingCount)
		if existingCount > 0 && !account.LastSyncAt.IsZero() {
			sinceDate := account.LastSyncAt.AddDate(0, 0, -1)
			criteria.Since = time.Date(sinceDate.Year(), sinceDate.Month(), sinceDate.Day(), 0, 0, 0, 0, time.UTC)
		}
	} else {
		sinceDate := time.Now().AddDate(0, 0, -days)
		criteria.Since = time.Date(sinceDate.Year(), sinceDate.Month(), sinceDate.Day(), 0, 0, 0, 0, time.UTC)
	}

	// Search for messages
	seqNums, err := c.Search(criteria)
	if err != nil || len(seqNums) == 0 {
		seqNums = make([]uint32, mbox.Messages)
		for i := uint32(1); i <= mbox.Messages; i++ {
			seqNums[i-1] = i
		}
	}

	s.logService.LogInfo(userID, models.LogModuleEmail, "fetch", "Search completed", map[string]interface{}{
		"found_msgs": len(seqNums),
	})

	if len(seqNums) == 0 {
		return []FetchedEmail{}, nil
	}

	// Limit sync count
	const maxSyncEmails = 200
	if !noLimit && len(seqNums) > maxSyncEmails {
		seqNums = seqNums[len(seqNums)-maxSyncEmails:]
	}

	// 使用单连接获取邮件
	const batchSize = 10
	var fetchedEmails []FetchedEmail

	s.logService.LogInfo(userID, models.LogModuleEmail, "fetch", "Fetching emails", map[string]interface{}{
		"count": len(seqNums),
	})

	// Step 1: 获取所有邮件的 UID 和 MessageID
	type msgMeta struct {
		uid       uint32
		messageID string
		envelope  *imap.Envelope
	}
	var allMetas []msgMeta

	for i := 0; i < len(seqNums); i += batchSize {
		batchEnd := i + batchSize
		if batchEnd > len(seqNums) {
			batchEnd = len(seqNums)
		}
		batch := seqNums[i:batchEnd]

		seqSet := new(imap.SeqSet)
		seqSet.AddNum(batch...)

		items := []imap.FetchItem{imap.FetchUid, imap.FetchEnvelope}
		messages := make(chan *imap.Message, batchSize)
		done := make(chan error, 1)

		go func() {
			done <- c.Fetch(seqSet, items, messages)
		}()

		for msg := range messages {
			if msg == nil || msg.Envelope == nil {
				continue
			}
			messageID := msg.Envelope.MessageId
			if messageID == "" {
				messageID = fmt.Sprintf("uid:%d", msg.Uid)
			}
			allMetas = append(allMetas, msgMeta{
				uid:       msg.Uid,
				messageID: messageID,
				envelope:  msg.Envelope,
			})
		}
		<-done
	}

	s.logService.LogInfo(userID, models.LogModuleEmail, "fetch", "Got envelopes", map[string]interface{}{
		"count": len(allMetas),
	})

	// Step 2: 过滤已存在的邮件
	var allMessageIDs []string
	for _, meta := range allMetas {
		allMessageIDs = append(allMessageIDs, meta.messageID)
	}

	existingIDs := make(map[string]bool)
	const dbBatchSize = 500
	for i := 0; i < len(allMessageIDs); i += dbBatchSize {
		end := i + dbBatchSize
		if end > len(allMessageIDs) {
			end = len(allMessageIDs)
		}
		var existingEmails []models.Email
		s.db.Select("message_id").Where("account_id = ? AND message_id IN ?", accountID, allMessageIDs[i:end]).Find(&existingEmails)
		for _, e := range existingEmails {
			existingIDs[e.MessageID] = true
		}
	}

	var newMetas []msgMeta
	for _, meta := range allMetas {
		if !existingIDs[meta.messageID] {
			newMetas = append(newMetas, meta)
		}
	}

	s.logService.LogInfo(userID, models.LogModuleEmail, "fetch", "Filtered new emails", map[string]interface{}{
		"total":   len(allMetas),
		"new":     len(newMetas),
		"skipped": len(allMetas) - len(newMetas),
	})

	if len(newMetas) == 0 {
		return []FetchedEmail{}, nil
	}

	// Limit body fetch
	const maxBodyFetch = 50
	if !noLimit && len(newMetas) > maxBodyFetch {
		newMetas = newMetas[len(newMetas)-maxBodyFetch:]
	}

	// Step 3: 获取新邮件的 body（使用同一连接）
	var uidsToFetch []uint32
	uidToMeta := make(map[uint32]msgMeta)
	for _, meta := range newMetas {
		uidsToFetch = append(uidsToFetch, meta.uid)
		uidToMeta[meta.uid] = meta
	}

	s.logService.LogInfo(userID, models.LogModuleEmail, "fetch", "Fetching bodies", map[string]interface{}{
		"count": len(uidsToFetch),
	})

	section := &imap.BodySectionName{Peek: true}
	uidToBody := make(map[uint32][]byte)

	for i := 0; i < len(uidsToFetch); i += batchSize {
		batchEnd := i + batchSize
		if batchEnd > len(uidsToFetch) {
			batchEnd = len(uidsToFetch)
		}
		batch := uidsToFetch[i:batchEnd]

		uidSet := new(imap.SeqSet)
		uidSet.AddNum(batch...)

		items := []imap.FetchItem{imap.FetchUid, section.FetchItem()}
		messages := make(chan *imap.Message, batchSize)
		done := make(chan error, 1)

		go func() {
			done <- c.UidFetch(uidSet, items, messages)
		}()

		for msg := range messages {
			if msg == nil {
				continue
			}
			for _, literal := range msg.Body {
				content, err := io.ReadAll(literal)
				if err == nil && len(content) > 0 {
					uidToBody[msg.Uid] = content
				}
			}
		}

		if err := <-done; err != nil {
			s.logService.LogWarn(userID, models.LogModuleEmail, "fetch", "UidFetch error", map[string]interface{}{
				"error": err.Error(),
			})
		}
	}

	s.logService.LogInfo(userID, models.LogModuleEmail, "fetch", "Bodies fetched", map[string]interface{}{
		"requested": len(uidsToFetch),
		"fetched":   len(uidToBody),
	})

	// Step 4: 构建邮件列表
	var parseErrors, bodyMissing int

	for _, meta := range newMetas {
		email := FetchedEmail{
			UID:       meta.uid,
			MessageID: meta.messageID,
			Subject:   meta.envelope.Subject,
			Date:      meta.envelope.Date,
		}

		if len(meta.envelope.From) > 0 {
			email.From = formatAddress(meta.envelope.From[0])
		}

		for _, addr := range meta.envelope.To {
			email.To = append(email.To, formatAddress(addr))
		}

		// 解析 body
		if body, ok := uidToBody[meta.uid]; ok && len(body) > 0 {
			email.RawContent = body

			r := bytes.NewReader(body)
			entity, err := message.Read(r)
			if err != nil {
				r.Seek(0, io.SeekStart)
				m, err := mail.ReadMessage(r)
				if err == nil {
					b, _ := io.ReadAll(m.Body)
					email.Body = string(b)
				} else {
					parseErrors++
				}
			} else {
				s.parseMessageEntity(entity, &email)
			}
		} else {
			bodyMissing++
		}

		fetchedEmails = append(fetchedEmails, email)
	}

	s.logService.LogInfo(userID, models.LogModuleEmail, "fetch", "Fetch completed", map[string]interface{}{
		"account_id":    accountID,
		"fetched_count": len(fetchedEmails),
		"parse_errors":  parseErrors,
		"body_missing":  bodyMissing,
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
	} else {
		// 检查是否是附件
		disposition := entity.Header.Get("Content-Disposition")
		isAttachment := false
		var filename string
		
		// 解析 Content-Disposition 头
		if disposition != "" {
			dispType, dispParams, err := mime.ParseMediaType(disposition)
			if err == nil {
				// attachment 或 inline 带文件名都视为附件
				if dispType == "attachment" || (dispType == "inline" && dispParams["filename"] != "") {
					isAttachment = true
					filename = dispParams["filename"]
				}
			}
		}
		
		// 如果 Content-Type 有 name 参数，也视为附件
		if params["name"] != "" {
			isAttachment = true
			if filename == "" {
				filename = params["name"]
			}
		}
		
		// 解码 MIME 编码的文件名 (如 =?utf-8?B?...?=)
		if filename != "" {
			dec := new(mime.WordDecoder)
			if decoded, err := dec.DecodeHeader(filename); err == nil {
				filename = decoded
			}
		}
		
		// 非文本类型且有内容的也可能是附件（如图片等）
		if !isAttachment && !strings.HasPrefix(mediaType, "text/") && mediaType != "" {
			isAttachment = true
		}
		
		if isAttachment {
			content, _ := io.ReadAll(entity.Body)
			if len(content) > 0 {
				if filename == "" {
					// 根据 MIME 类型生成默认文件名
					ext := ".bin"
					if strings.HasPrefix(mediaType, "image/") {
						ext = "." + strings.TrimPrefix(mediaType, "image/")
					} else if strings.HasPrefix(mediaType, "application/pdf") {
						ext = ".pdf"
					}
					filename = "attachment" + ext
				}
				
				email.Attachments = append(email.Attachments, FetchedAttachment{
					Filename:    filename,
					ContentType: mediaType,
					Content:     content,
				})
				email.HasAttachments = true
			}
		}
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
	s.logService.LogInfo(userID, models.LogModuleEmail, "sync", "Starting sync with account settings", map[string]interface{}{
		"account_id": accountID,
		"sync_days":  account.SyncDays,
		"email":      account.Email,
	})
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
	skippedCount := 0
	for _, fetched := range fetchedEmails {
		// Check if email already exists
		var existing models.Email
		if err := s.db.Where("account_id = ? AND message_id = ?", accountID, fetched.MessageID).First(&existing).Error; err == nil {
			skippedCount++
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

		// 记录邮件保存信息（包含附件详情）
		s.logService.LogInfo(userID, models.LogModuleEmail, "sync_save", "Email saved to database", map[string]interface{}{
			"email_id":         email.ID,
			"message_id":       fetched.MessageID,
			"has_attachments":  fetched.HasAttachments,
			"attachment_count": len(fetched.Attachments),
			"raw_content_size": len(fetched.RawContent),
			"raw_file_path":    rawFilePath,
		})

		// Save attachments if any
		attachmentsSaved := 0
		for _, att := range fetched.Attachments {
			s.logService.LogInfo(userID, models.LogModuleEmail, "sync_attachment", "Saving attachment", map[string]interface{}{
				"email_id":     email.ID,
				"filename":     att.Filename,
				"content_type": att.ContentType,
				"size":         len(att.Content),
			})
			_, err := s.userStorage.SaveAttachment(userID, email.ID, att.Filename, att.Content)
			if err != nil {
				s.logService.LogWarn(userID, models.LogModuleEmail, "sync_attachment", "Failed to save attachment", map[string]interface{}{
					"email_id": email.ID,
					"filename": att.Filename,
					"error":    err.Error(),
				})
			} else {
				attachmentsSaved++
			}
		}
		
		if fetched.HasAttachments {
			s.logService.LogInfo(userID, models.LogModuleEmail, "sync_attachment_summary", "Attachment save summary", map[string]interface{}{
				"email_id":          email.ID,
				"expected":          len(fetched.Attachments),
				"saved":             attachmentsSaved,
				"has_attachments":   fetched.HasAttachments,
			})
		}

		// 处理邮件（提取验证码、检测广告等）
		go func(userID, accountID uint, email *models.Email) {
			if _, err := s.processor.ProcessAndSaveEmail(userID, accountID, email); err != nil {
				s.logService.LogWarn(userID, models.LogModuleEmail, "process_email", "Failed to process email", map[string]interface{}{
					"email_id": email.ID,
					"error":    err.Error(),
				})
			}
		}(userID, accountID, email)

		savedCount++
	}

	// Update last sync time
	s.db.Model(&models.EmailAccount{}).Where("id = ?", accountID).Update("last_sync_at", syncStartedAt)

	// Log sync completion
	s.logService.LogInfo(userID, models.LogModuleEmail, "sync", "Email sync completed", map[string]interface{}{
		"account_id":    accountID,
		"fetched_count": len(fetchedEmails),
		"saved_count":   savedCount,
		"skipped_count": skippedCount,
		"days":          days,
	})

	return savedCount, nil
}

// SyncAllEmails 全量同步所有邮件，分批处理避免超时
// FullSyncProgress 全量同步进度
type FullSyncProgress struct {
	AccountID     uint   `json:"account_id"`
	Status        string `json:"status"` // "idle", "running", "completed", "failed"
	TotalMessages uint32 `json:"total_messages"`
	Processed     uint32 `json:"processed"`
	Saved         int    `json:"saved"`
	Skipped       int    `json:"skipped"`
	CurrentBatch  int    `json:"current_batch"`
	TotalBatches  int    `json:"total_batches"`
	Error         string `json:"error,omitempty"`
}

// 全量同步进度存储（内存中）
var fullSyncProgressMap = make(map[uint]*FullSyncProgress)
var fullSyncProgressMutex sync.RWMutex

// GetFullSyncProgress 获取全量同步进度
func (s *EmailService) GetFullSyncProgress(accountID uint) *FullSyncProgress {
	fullSyncProgressMutex.RLock()
	defer fullSyncProgressMutex.RUnlock()
	if progress, ok := fullSyncProgressMap[accountID]; ok {
		return progress
	}
	return &FullSyncProgress{AccountID: accountID, Status: "idle"}
}

// SyncAllEmails 全量同步所有邮件，使用并发快速同步
func (s *EmailService) SyncAllEmails(userID, accountID uint) (int, error) {
	account, err := s.accountService.GetAccountByIDAndUserID(accountID, userID)
	if err != nil {
		return 0, err
	}

	// 初始化进度
	progress := &FullSyncProgress{
		AccountID: accountID,
		Status:    "running",
	}
	fullSyncProgressMutex.Lock()
	fullSyncProgressMap[accountID] = progress
	fullSyncProgressMutex.Unlock()

	s.logService.LogInfo(userID, models.LogModuleEmail, "full_sync", "Starting full sync (fast mode)", map[string]interface{}{
		"account_id": accountID,
		"email":      account.Email,
	})

	// 连接 IMAP 获取总邮件数
	c, err := s.connectIMAP(account)
	if err != nil {
		progress.Status = "failed"
		progress.Error = err.Error()
		return 0, err
	}

	mbox, err := c.Select("INBOX", true)
	if err != nil {
		c.Logout()
		progress.Status = "failed"
		progress.Error = err.Error()
		return 0, err
	}

	progress.TotalMessages = mbox.Messages
	progress.TotalBatches = 3 // 分3个阶段：获取envelope、过滤、保存

	s.logService.LogInfo(userID, models.LogModuleEmail, "full_sync", "Full sync plan", map[string]interface{}{
		"total_messages": mbox.Messages,
	})

	// 确保目录存在
	if err := s.userManager.CreateAccountDirectories(userID, accountID); err != nil {
		c.Logout()
		progress.Status = "failed"
		progress.Error = err.Error()
		return 0, err
	}

	// 阶段1：快速获取所有 envelope（只获取元数据，不获取 body）
	progress.CurrentBatch = 1
	s.logService.LogInfo(userID, models.LogModuleEmail, "full_sync", "Phase 1: Fetching envelopes", nil)

	seqSet := new(imap.SeqSet)
	seqSet.AddRange(1, mbox.Messages)

	// 只获取 envelope，速度很快
	items := []imap.FetchItem{imap.FetchUid, imap.FetchEnvelope}
	messages := make(chan *imap.Message, 500)
	done := make(chan error, 1)

	go func() {
		done <- c.Fetch(seqSet, items, messages)
	}()

	type emailMeta struct {
		UID       uint32
		MessageID string
		Subject   string
		From      string
		To        []string
		Date      time.Time
	}

	var allMetas []emailMeta
	var allMessageIDs []string
	processed := uint32(0)

	for msg := range messages {
		if msg == nil || msg.Envelope == nil {
			continue
		}
		processed++
		progress.Processed = processed

		messageID := msg.Envelope.MessageId
		if messageID == "" {
			messageID = fmt.Sprintf("uid:%d", msg.Uid)
		}

		meta := emailMeta{
			UID:       msg.Uid,
			MessageID: messageID,
			Subject:   msg.Envelope.Subject,
			Date:      msg.Envelope.Date,
		}

		if len(msg.Envelope.From) > 0 {
			meta.From = formatAddress(msg.Envelope.From[0])
		}
		for _, addr := range msg.Envelope.To {
			meta.To = append(meta.To, formatAddress(addr))
		}

		allMetas = append(allMetas, meta)
		allMessageIDs = append(allMessageIDs, messageID)
	}

	<-done
	c.Logout()

	s.logService.LogInfo(userID, models.LogModuleEmail, "full_sync", "Phase 1 completed", map[string]interface{}{
		"total_envelopes": len(allMetas),
	})

	// 阶段2：批量查询已存在的邮件
	progress.CurrentBatch = 2
	s.logService.LogInfo(userID, models.LogModuleEmail, "full_sync", "Phase 2: Filtering existing", nil)

	existingIDs := make(map[string]bool)
	const dbBatchSize = 500
	for i := 0; i < len(allMessageIDs); i += dbBatchSize {
		end := i + dbBatchSize
		if end > len(allMessageIDs) {
			end = len(allMessageIDs)
		}
		batch := allMessageIDs[i:end]

		var existingEmails []models.Email
		s.db.Select("message_id").Where("account_id = ? AND message_id IN ?", accountID, batch).Find(&existingEmails)
		for _, e := range existingEmails {
			existingIDs[e.MessageID] = true
		}
	}

	// 过滤出新邮件
	var newMetas []emailMeta
	for _, meta := range allMetas {
		if !existingIDs[meta.MessageID] {
			newMetas = append(newMetas, meta)
		}
	}

	progress.Skipped = len(allMetas) - len(newMetas)
	s.logService.LogInfo(userID, models.LogModuleEmail, "full_sync", "Phase 2 completed", map[string]interface{}{
		"new_emails": len(newMetas),
		"skipped":    progress.Skipped,
	})

	if len(newMetas) == 0 {
		progress.Status = "completed"
		s.db.Model(&models.EmailAccount{}).Where("id = ?", accountID).Update("last_sync_at", time.Now())
		return 0, nil
	}

	// 阶段3：批量保存新邮件（只保存元数据，不获取 body）
	progress.CurrentBatch = 3
	s.logService.LogInfo(userID, models.LogModuleEmail, "full_sync", "Phase 3: Saving emails", map[string]interface{}{
		"count": len(newMetas),
	})

	var emailsToSave []*models.Email
	for _, meta := range newMetas {
		toAddrsJSON, _ := json.Marshal(meta.To)
		emailRecord := &models.Email{
			AccountID:      accountID,
			MessageID:      meta.MessageID,
			Subject:        meta.Subject,
			FromAddr:       meta.From,
			ToAddrs:        string(toAddrsJSON),
			Date:           meta.Date,
			Body:           "", // 暂不获取 body，后续按需加载
			HTMLBody:       "",
			HasAttachments: false,
			IsRead:         false,
			Folder:         models.FolderInbox,
			RawFilePath:    "",
		}
		emailsToSave = append(emailsToSave, emailRecord)
	}

	// 批量插入
	if err := s.db.CreateInBatches(emailsToSave, 100).Error; err != nil {
		progress.Status = "failed"
		progress.Error = err.Error()
		return 0, err
	}

	progress.Saved = len(emailsToSave)
	progress.Status = "completed"

	// 更新最后同步时间
	s.db.Model(&models.EmailAccount{}).Where("id = ?", accountID).Update("last_sync_at", time.Now())

	s.logService.LogInfo(userID, models.LogModuleEmail, "full_sync", "Full sync completed", map[string]interface{}{
		"total_saved":   progress.Saved,
		"total_skipped": progress.Skipped,
	})

	return progress.Saved, nil
}

// syncBatchEmails 同步一批邮件（批量处理）
func (s *EmailService) syncBatchEmails(userID, accountID uint, account *models.EmailAccount, startSeq, endSeq uint32) (saved, skipped int, err error) {
	c, err := s.connectIMAP(account)
	if err != nil {
		return 0, 0, err
	}
	defer c.Logout()

	_, err = c.Select("INBOX", false)
	if err != nil {
		return 0, 0, err
	}

	// 构建序号集合
	seqSet := new(imap.SeqSet)
	seqSet.AddRange(startSeq, endSeq)

	// 获取 envelope 和 body
	section := &imap.BodySectionName{Peek: true}
	items := []imap.FetchItem{imap.FetchUid, imap.FetchEnvelope, section.FetchItem()}

	messages := make(chan *imap.Message, 50)
	done := make(chan error, 1)

	go func() {
		done <- c.Fetch(seqSet, items, messages)
	}()

	// 收集所有邮件
	var fetchedEmails []FetchedEmail
	var messageIDs []string

	for msg := range messages {
		if msg == nil || msg.Envelope == nil {
			continue
		}

		// 获取 MessageID
		messageID := msg.Envelope.MessageId
		if messageID == "" {
			messageID = fmt.Sprintf("uid:%d", msg.Uid)
		}

		// 解析邮件内容
		email := FetchedEmail{
			UID:       msg.Uid,
			MessageID: messageID,
			Subject:   msg.Envelope.Subject,
			Date:      msg.Envelope.Date,
		}

		if len(msg.Envelope.From) > 0 {
			email.From = formatAddress(msg.Envelope.From[0])
		}
		for _, addr := range msg.Envelope.To {
			email.To = append(email.To, formatAddress(addr))
		}

		// 获取 body
		for _, literal := range msg.Body {
			content, err := io.ReadAll(literal)
			if err == nil {
				email.RawContent = content
				r := bytes.NewReader(content)
				entity, err := message.Read(r)
				if err == nil {
					s.parseMessageEntity(entity, &email)
				} else {
					r.Seek(0, io.SeekStart)
					m, err := mail.ReadMessage(r)
					if err == nil {
						b, _ := io.ReadAll(m.Body)
						email.Body = string(b)
					}
				}
			}
		}

		fetchedEmails = append(fetchedEmails, email)
		messageIDs = append(messageIDs, messageID)
	}

	<-done

	if len(fetchedEmails) == 0 {
		return 0, 0, nil
	}

	// 批量查询已存在的邮件
	existingIDs := make(map[string]bool)
	var existingEmails []models.Email
	s.db.Select("message_id").Where("account_id = ? AND message_id IN ?", accountID, messageIDs).Find(&existingEmails)
	for _, e := range existingEmails {
		existingIDs[e.MessageID] = true
	}

	// 批量保存新邮件
	var emailsToSave []*models.Email
	for _, email := range fetchedEmails {
		if existingIDs[email.MessageID] {
			skipped++
			continue
		}

		// 保存原始邮件文件
		rawFilePath, err := s.userStorage.SaveRawEmail(userID, accountID, email.MessageID, email.RawContent)
		if err != nil {
			continue
		}

		toAddrsJSON, _ := json.Marshal(email.To)
		emailRecord := &models.Email{
			AccountID:      accountID,
			MessageID:      email.MessageID,
			Subject:        email.Subject,
			FromAddr:       email.From,
			ToAddrs:        string(toAddrsJSON),
			Date:           email.Date,
			Body:           email.Body,
			HTMLBody:       email.HTMLBody,
			HasAttachments: email.HasAttachments,
			IsRead:         false,
			Folder:         models.FolderInbox,
			RawFilePath:    rawFilePath,
		}
		emailsToSave = append(emailsToSave, emailRecord)
	}

	// 批量插入数据库
	if len(emailsToSave) > 0 {
		if err := s.db.CreateInBatches(emailsToSave, 100).Error; err != nil {
			return 0, skipped, err
		}
		saved = len(emailsToSave)
	}

	return saved, skipped, nil
}

// SyncAndSaveEmailsNoLimit 全量同步，不限制邮件数量
func (s *EmailService) SyncAndSaveEmailsNoLimit(userID, accountID uint) (int, error) {
	syncStartedAt := time.Now()

	// Ensure account directories exist
	if err := s.userManager.CreateAccountDirectories(userID, accountID); err != nil {
		return 0, err
	}

	// 使用 noLimit=true 获取所有邮件
	fetchedEmails, err := s.FetchNewEmailsWithOptions(userID, accountID, -1, true)
	if err != nil {
		return 0, err
	}

	s.logService.LogInfo(userID, models.LogModuleEmail, "full_sync", "Fetched emails for full sync", map[string]interface{}{
		"account_id": accountID,
		"count":      len(fetchedEmails),
	})

	savedCount := 0
	skippedCount := 0
	for _, fetched := range fetchedEmails {
		// Check if email already exists
		var existing models.Email
		if err := s.db.Where("account_id = ? AND message_id = ?", accountID, fetched.MessageID).First(&existing).Error; err == nil {
			skippedCount++
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

		// 处理邮件（提取验证码、检测广告等）
		go func(userID, accountID uint, email *models.Email) {
			if _, err := s.processor.ProcessAndSaveEmail(userID, accountID, email); err != nil {
				s.logService.LogWarn(userID, models.LogModuleEmail, "process_email", "Failed to process email", map[string]interface{}{
					"email_id": email.ID,
					"error":    err.Error(),
				})
			}
		}(userID, accountID, email)

		savedCount++
	}

	// Update last sync time
	s.db.Model(&models.EmailAccount{}).Where("id = ?", accountID).Update("last_sync_at", syncStartedAt)

	s.logService.LogInfo(userID, models.LogModuleEmail, "full_sync", "Full sync completed", map[string]interface{}{
		"account_id":    accountID,
		"fetched_count": len(fetchedEmails),
		"saved_count":   savedCount,
		"skipped_count": skippedCount,
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
// If the email body is empty, it will fetch from IMAP
func (s *EmailService) GetEmailByIDAndUserID(id, userID uint) (*models.Email, error) {
	var email models.Email
	if err := s.db.Preload("ProcessedResult").First(&email, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrEmailNotFound
		}
		return nil, err
	}

	// Verify user owns the account
	account, err := s.accountService.GetAccountByIDAndUserID(email.AccountID, userID)
	if err != nil {
		return nil, ErrEmailNotFound
	}

	// If body is empty, fetch from IMAP
	if email.Body == "" && email.HTMLBody == "" {
		s.logService.LogInfo(userID, models.LogModuleEmail, "fetch_body", "Fetching body from IMAP", map[string]interface{}{
			"email_id":   id,
			"message_id": email.MessageID,
		})
		body, htmlBody, err := s.fetchEmailBodyFromIMAP(account, email.MessageID)
		if err != nil {
			s.logService.LogWarn(userID, models.LogModuleEmail, "fetch_body", "Failed to fetch body", map[string]interface{}{
				"email_id": id,
				"error":    err.Error(),
			})
		} else if body != "" || htmlBody != "" {
			email.Body = body
			email.HTMLBody = htmlBody
			// Update in database
			s.db.Model(&email).Updates(map[string]interface{}{
				"body":      body,
				"html_body": htmlBody,
			})
			s.logService.LogInfo(userID, models.LogModuleEmail, "fetch_body", "Body fetched and saved", map[string]interface{}{
				"email_id":  id,
				"body_len":  len(body),
				"html_len":  len(htmlBody),
			})
		}
	}

	return &email, nil
}

// fetchEmailBodyFromIMAP fetches email body from IMAP server by message ID
func (s *EmailService) fetchEmailBodyFromIMAP(account *models.EmailAccount, messageID string) (string, string, error) {
	c, err := s.connectIMAP(account)
	if err != nil {
		return "", "", err
	}
	defer c.Logout()

	_, err = c.Select("INBOX", false)
	if err != nil {
		return "", "", err
	}

	var seqNums []uint32

	// Check if messageID is a UID fallback (uid:xxx format)
	if strings.HasPrefix(messageID, "uid:") {
		uidStr := strings.TrimPrefix(messageID, "uid:")
		uid, err := strconv.ParseUint(uidStr, 10, 32)
		if err == nil {
			// Directly use UidFetch for uid:xxx format
			seqSet := new(imap.SeqSet)
			seqSet.AddNum(uint32(uid))
			
			section := &imap.BodySectionName{Peek: true}
			items := []imap.FetchItem{section.FetchItem()}
			
			messages := make(chan *imap.Message, 1)
			done := make(chan error, 1)
			
			go func() {
				done <- c.UidFetch(seqSet, items, messages)
			}()
			
			var body, htmlBody string
			for msg := range messages {
				if msg == nil {
					continue
				}
				for _, literal := range msg.Body {
					content, err := io.ReadAll(literal)
					if err != nil {
						continue
					}
					r := bytes.NewReader(content)
					entity, err := message.Read(r)
					if err != nil {
						r.Seek(0, io.SeekStart)
						m, err := mail.ReadMessage(r)
						if err == nil {
							b, _ := io.ReadAll(m.Body)
							body = string(b)
						}
						continue
					}
					fetched := &FetchedEmail{}
					s.parseMessageEntity(entity, fetched)
					body = fetched.Body
					htmlBody = fetched.HTMLBody
				}
			}
			<-done
			return body, htmlBody, nil
		}
	}

	// Search by message ID header
	criteria := imap.NewSearchCriteria()
	criteria.Header.Add("Message-Id", messageID)
	seqNums, err = c.Search(criteria)
	if err != nil || len(seqNums) == 0 {
		// Try without angle brackets
		if strings.HasPrefix(messageID, "<") {
			criteria = imap.NewSearchCriteria()
			criteria.Header.Add("Message-Id", strings.Trim(messageID, "<>"))
			seqNums, err = c.Search(criteria)
		}
		if err != nil || len(seqNums) == 0 {
			return "", "", fmt.Errorf("message not found: %s", messageID)
		}
	}

	seqSet := new(imap.SeqSet)
	seqSet.AddNum(seqNums[0])

	section := &imap.BodySectionName{Peek: true}
	items := []imap.FetchItem{section.FetchItem()}

	messages := make(chan *imap.Message, 1)
	done := make(chan error, 1)

	go func() {
		done <- c.Fetch(seqSet, items, messages)
	}()

	var body, htmlBody string
	for msg := range messages {
		if msg == nil {
			continue
		}
		for _, literal := range msg.Body {
			content, err := io.ReadAll(literal)
			if err != nil {
				continue
			}

			r := bytes.NewReader(content)
			entity, err := message.Read(r)
			if err != nil {
				r.Seek(0, io.SeekStart)
				m, err := mail.ReadMessage(r)
				if err == nil {
					b, _ := io.ReadAll(m.Body)
					body = string(b)
				}
				continue
			}

			// Parse the message
			fetched := &FetchedEmail{}
			s.parseMessageEntity(entity, fetched)
			body = fetched.Body
			htmlBody = fetched.HTMLBody
		}
	}

	<-done
	return body, htmlBody, nil
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
	// limit=-1 表示不限制，limit=0 或未设置时使用默认值 20
	if opts.Limit == 0 {
		opts.Limit = 20
	}
	// 正数时最大1000
	if opts.Limit > 1000 {
		opts.Limit = 1000
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

	// Pagination - limit=-1 means no limit
	if opts.Limit > 0 {
		offset := (opts.Page - 1) * opts.Limit
		query = query.Offset(offset).Limit(opts.Limit)
	}
	// If limit <= 0, no pagination applied (fetch all)

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

// MarkAllAsRead marks all emails as read for a user (optionally filtered by account)
func (s *EmailService) MarkAllAsRead(userID uint, accountID uint) (int64, error) {
	// 先获取用户的所有账户 ID
	var accountIDs []uint
	accountQuery := s.db.Model(&models.EmailAccount{}).Where("user_id = ?", userID)
	if accountID > 0 {
		accountQuery = accountQuery.Where("id = ?", accountID)
	}
	if err := accountQuery.Pluck("id", &accountIDs).Error; err != nil {
		return 0, err
	}

	if len(accountIDs) == 0 {
		return 0, nil
	}

	// 更新这些账户下的所有未读邮件
	result := s.db.Model(&models.Email{}).
		Where("account_id IN ?", accountIDs).
		Where("is_read = ?", false).
		Update("is_read", true)

	return result.RowsAffected, result.Error
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
	AccountID   uint              `json:"account_id"`
	To          []string          `json:"to"`
	Cc          []string          `json:"cc"`
	Bcc         []string          `json:"bcc"`
	Subject     string            `json:"subject"`
	Body        string            `json:"body"`
	HTMLBody    string            `json:"html_body"`
	Attachments []AttachmentData  `json:"attachments"`
}

// AttachmentData represents attachment data for sending
type AttachmentData struct {
	Filename    string `json:"filename"`
	Content     string `json:"content"`      // Base64 encoded content
	ContentType string `json:"content_type"`
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
	buf.WriteString(fmt.Sprintf("Subject: =?UTF-8?B?%s?=\r\n", base64.StdEncoding.EncodeToString([]byte(req.Subject))))
	buf.WriteString(fmt.Sprintf("Message-ID: %s\r\n", messageID))
	buf.WriteString(fmt.Sprintf("Date: %s\r\n", time.Now().Format(time.RFC1123Z)))
	buf.WriteString("MIME-Version: 1.0\r\n")

	hasAttachments := len(req.Attachments) > 0

	if hasAttachments {
		// Multipart mixed for attachments
		mixedBoundary := generateBoundary()
		buf.WriteString(fmt.Sprintf("Content-Type: multipart/mixed; boundary=\"%s\"\r\n", mixedBoundary))
		buf.WriteString("\r\n")

		// Text/HTML part
		buf.WriteString(fmt.Sprintf("--%s\r\n", mixedBoundary))
		
		if req.HTMLBody != "" {
			// Multipart alternative for text and HTML
			altBoundary := generateBoundary()
			buf.WriteString(fmt.Sprintf("Content-Type: multipart/alternative; boundary=\"%s\"\r\n", altBoundary))
			buf.WriteString("\r\n")

			// Plain text part
			buf.WriteString(fmt.Sprintf("--%s\r\n", altBoundary))
			buf.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
			buf.WriteString("Content-Transfer-Encoding: base64\r\n")
			buf.WriteString("\r\n")
			buf.WriteString(wrapBase64(base64.StdEncoding.EncodeToString([]byte(req.Body))))
			buf.WriteString("\r\n")

			// HTML part
			buf.WriteString(fmt.Sprintf("--%s\r\n", altBoundary))
			buf.WriteString("Content-Type: text/html; charset=utf-8\r\n")
			buf.WriteString("Content-Transfer-Encoding: base64\r\n")
			buf.WriteString("\r\n")
			buf.WriteString(wrapBase64(base64.StdEncoding.EncodeToString([]byte(req.HTMLBody))))
			buf.WriteString("\r\n")

			buf.WriteString(fmt.Sprintf("--%s--\r\n", altBoundary))
		} else {
			// Plain text only
			buf.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
			buf.WriteString("Content-Transfer-Encoding: base64\r\n")
			buf.WriteString("\r\n")
			buf.WriteString(wrapBase64(base64.StdEncoding.EncodeToString([]byte(req.Body))))
			buf.WriteString("\r\n")
		}

		// Attachments
		for _, att := range req.Attachments {
			buf.WriteString(fmt.Sprintf("--%s\r\n", mixedBoundary))
			contentType := att.ContentType
			if contentType == "" {
				contentType = "application/octet-stream"
			}
			// Encode filename for non-ASCII characters
			encodedFilename := fmt.Sprintf("=?UTF-8?B?%s?=", base64.StdEncoding.EncodeToString([]byte(att.Filename)))
			buf.WriteString(fmt.Sprintf("Content-Type: %s; name=\"%s\"\r\n", contentType, encodedFilename))
			buf.WriteString("Content-Transfer-Encoding: base64\r\n")
			buf.WriteString(fmt.Sprintf("Content-Disposition: attachment; filename=\"%s\"\r\n", encodedFilename))
			buf.WriteString("\r\n")
			// Content is already base64 encoded from frontend, wrap to 76 chars per line
			buf.WriteString(wrapBase64(att.Content))
			buf.WriteString("\r\n")
		}

		buf.WriteString(fmt.Sprintf("--%s--\r\n", mixedBoundary))
	} else if req.HTMLBody != "" {
		// Multipart message with both plain text and HTML (no attachments)
		boundary := generateBoundary()
		buf.WriteString(fmt.Sprintf("Content-Type: multipart/alternative; boundary=\"%s\"\r\n", boundary))
		buf.WriteString("\r\n")

		// Plain text part
		buf.WriteString(fmt.Sprintf("--%s\r\n", boundary))
		buf.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
		buf.WriteString("Content-Transfer-Encoding: base64\r\n")
		buf.WriteString("\r\n")
		buf.WriteString(wrapBase64(base64.StdEncoding.EncodeToString([]byte(req.Body))))
		buf.WriteString("\r\n")

		// HTML part
		buf.WriteString(fmt.Sprintf("--%s\r\n", boundary))
		buf.WriteString("Content-Type: text/html; charset=utf-8\r\n")
		buf.WriteString("Content-Transfer-Encoding: base64\r\n")
		buf.WriteString("\r\n")
		buf.WriteString(wrapBase64(base64.StdEncoding.EncodeToString([]byte(req.HTMLBody))))
		buf.WriteString("\r\n")

		buf.WriteString(fmt.Sprintf("--%s--\r\n", boundary))
	} else {
		// Plain text only
		buf.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
		buf.WriteString("Content-Transfer-Encoding: base64\r\n")
		buf.WriteString("\r\n")
		buf.WriteString(wrapBase64(base64.StdEncoding.EncodeToString([]byte(req.Body))))
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

		// 邮件已发送成功，忽略 Quit 的错误
		// 某些 SMTP 服务器在关闭连接时可能返回异常响应
		client.Quit()
		return nil
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

	// 邮件已发送成功，忽略 Quit 的错误
	client.Quit()
	return nil
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

// wrapBase64 wraps base64 content to 76 characters per line (MIME standard)
func wrapBase64(content string) string {
	// First, clean the base64 content by removing any existing whitespace/newlines
	// This handles cases where the input already has line breaks
	cleaned := strings.Map(func(r rune) rune {
		if r == ' ' || r == '\n' || r == '\r' || r == '\t' {
			return -1 // Remove whitespace
		}
		return r
	}, content)
	
	const lineLength = 76
	var result strings.Builder
	for i := 0; i < len(cleaned); i += lineLength {
		end := i + lineLength
		if end > len(cleaned) {
			end = len(cleaned)
		}
		result.WriteString(cleaned[i:end])
		if end < len(cleaned) {
			result.WriteString("\r\n")
		}
	}
	return result.String()
}

// randomString generates a random alphanumeric string
func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	// Use crypto/rand for better randomness
	randBytes := make([]byte, n)
	_, err := io.ReadFull(cryptoRand.Reader, randBytes)
	if err != nil {
		// Fallback to time-based if crypto/rand fails
		for i := range b {
			b[i] = letters[(time.Now().UnixNano()+int64(i))%int64(len(letters))]
		}
		return string(b)
	}
	for i := range b {
		b[i] = letters[int(randBytes[i])%len(letters)]
	}
	return string(b)
}


// AttachmentInfo represents information about an attachment
type AttachmentInfo struct {
	Filename     string `json:"filename"`      // 解码后的显示名称
	RawFilename  string `json:"raw_filename"`  // 原始文件名（用于下载）
	Size         int64  `json:"size"`
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
	email, err := s.GetEmailByIDAndUserID(emailID, userID)
	if err != nil {
		return nil, err
	}

	s.logService.LogInfo(userID, models.LogModuleEmail, "download_attachment", "Attempting to download attachment", map[string]interface{}{
		"email_id":  emailID,
		"filename":  filename,
		"raw_path":  email.RawFilePath,
	})

	// Get attachment
	content, err := s.userStorage.GetAttachment(userID, emailID, filename)
	if err != nil {
		s.logService.LogError(userID, models.LogModuleEmail, "download_attachment", "Failed to get attachment", map[string]interface{}{
			"email_id": emailID,
			"filename": filename,
			"error":    err.Error(),
		})
		if errors.Is(err, user.ErrFileNotFound) {
			return nil, ErrAttachmentNotFound
		}
		return nil, err
	}

	s.logService.LogInfo(userID, models.LogModuleEmail, "download_attachment", "Successfully downloaded attachment", map[string]interface{}{
		"email_id": emailID,
		"filename": filename,
		"size":     len(content),
	})

	return content, nil
}

// ListAttachments lists all attachments for an email
func (s *EmailService) ListAttachments(userID, emailID uint) ([]AttachmentInfo, error) {
	// Verify user owns the email
	email, err := s.GetEmailByIDAndUserID(emailID, userID)
	if err != nil {
		return nil, err
	}

	s.logService.LogInfo(userID, models.LogModuleEmail, "list_attachments", "Starting to list attachments", map[string]interface{}{
		"email_id":        emailID,
		"has_attachments": email.HasAttachments,
		"raw_file_path":   email.RawFilePath,
	})

	// List attachments from file system
	filenames, err := s.userStorage.ListAttachments(userID, emailID)
	if err != nil {
		s.logService.LogWarn(userID, models.LogModuleEmail, "list_attachments", "Failed to list attachments from storage", map[string]interface{}{
			"email_id": emailID,
			"error":    err.Error(),
		})
		// 目录不存在等错误，返回空列表
		filenames = []string{}
	}

	s.logService.LogInfo(userID, models.LogModuleEmail, "list_attachments", "Found attachments in storage", map[string]interface{}{
		"email_id": emailID,
		"count":    len(filenames),
	})

	// 如果文件系统中有附件，直接返回
	if len(filenames) > 0 {
		var attachments []AttachmentInfo
		for _, filename := range filenames {
			content, err := s.userStorage.GetAttachment(userID, emailID, filename)
			if err != nil {
				continue
			}
			// 解码 MIME 编码的文件名用于显示
			displayName := filename
			dec := new(mime.WordDecoder)
			if decoded, err := dec.DecodeHeader(filename); err == nil {
				displayName = decoded
			}
			attachments = append(attachments, AttachmentInfo{
				Filename:    displayName,
				RawFilename: filename,
				Size:        int64(len(content)),
			})
		}
		return attachments, nil
	}

	// 如果邮件标记有附件但文件系统中没有，尝试从原始邮件解析
	if email.HasAttachments {
		s.logService.LogInfo(userID, models.LogModuleEmail, "list_attachments", "Trying to parse attachments from raw email", map[string]interface{}{
			"email_id":      emailID,
			"raw_file_path": email.RawFilePath,
		})
		
		// 尝试从原始邮件解析附件
		attachments, parseErr := s.ParseAndSaveAttachments(userID, emailID)
		if parseErr != nil {
			// 解析失败，记录日志但不返回错误
			s.logService.LogWarn(userID, models.LogModuleEmail, "list_attachments", "Failed to parse attachments from raw email", map[string]interface{}{
				"email_id": emailID,
				"error":    parseErr.Error(),
			})
			// 如果原始邮件不存在，更新 has_attachments 为 false
			if email.RawFilePath == "" {
				s.db.Model(&models.Email{}).Where("id = ?", emailID).Update("has_attachments", false)
			}
			return []AttachmentInfo{}, nil
		}
		return attachments, nil
	}

	return []AttachmentInfo{}, nil
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

// ParseAndSaveAttachments 从原始邮件中解析并保存附件
// 用于修复已存在但附件未保存的邮件
func (s *EmailService) ParseAndSaveAttachments(userID, emailID uint) ([]AttachmentInfo, error) {
	// 获取邮件信息
	email, err := s.GetEmailByIDAndUserID(emailID, userID)
	if err != nil {
		return nil, err
	}

	// 检查是否已有附件
	existingAttachments, _ := s.userStorage.ListAttachments(userID, emailID)
	if len(existingAttachments) > 0 {
		// 已有附件，直接返回
		var result []AttachmentInfo
		for _, filename := range existingAttachments {
			content, err := s.userStorage.GetAttachment(userID, emailID, filename)
			if err == nil {
				// 解码 MIME 编码的文件名用于显示
				displayName := filename
				dec := new(mime.WordDecoder)
				if decoded, err := dec.DecodeHeader(filename); err == nil {
					displayName = decoded
				}
				result = append(result, AttachmentInfo{
					Filename:    displayName,
					RawFilename: filename,
					Size:        int64(len(content)),
				})
			}
		}
		return result, nil
	}

	// 获取原始邮件内容
	rawContent, err := s.userStorage.GetRawEmail(userID, email.AccountID, email.MessageID)
	if err != nil {
		return nil, fmt.Errorf("failed to get raw email: %w", err)
	}

	if len(rawContent) == 0 {
		return nil, fmt.Errorf("raw email content is empty")
	}

	// 解析邮件
	r := bytes.NewReader(rawContent)
	entity, err := message.Read(r)
	if err != nil {
		return nil, fmt.Errorf("failed to parse email: %w", err)
	}

	// 解析附件
	var fetchedEmail FetchedEmail
	s.parseMessageEntity(entity, &fetchedEmail)

	// 保存附件
	var result []AttachmentInfo
	for _, att := range fetchedEmail.Attachments {
		_, err := s.userStorage.SaveAttachment(userID, emailID, att.Filename, att.Content)
		if err != nil {
			s.logService.LogWarn(userID, models.LogModuleEmail, "parse_attachment", "Failed to save attachment", map[string]interface{}{
				"email_id": emailID,
				"filename": att.Filename,
				"error":    err.Error(),
			})
			continue
		}
		result = append(result, AttachmentInfo{
			Filename:    att.Filename,
			RawFilename: att.Filename,
			Size:        int64(len(att.Content)),
		})
	}

	// 更新邮件的 has_attachments 字段
	if len(result) > 0 {
		s.db.Model(&models.Email{}).Where("id = ?", emailID).Update("has_attachments", true)
	}

	s.logService.LogInfo(userID, models.LogModuleEmail, "parse_attachment", "Attachments parsed and saved", map[string]interface{}{
		"email_id":         emailID,
		"attachment_count": len(result),
	})

	return result, nil
}

// ProcessAccountEmails processes all emails for an account (reprocesses even if already processed)
// Returns the number of emails processed
func (s *EmailService) ProcessAccountEmails(userID, accountID uint) (int, error) {
	// Verify user owns the account
	_, err := s.accountService.GetAccountByIDAndUserID(accountID, userID)
	if err != nil {
		return 0, err
	}

	// Get all emails for this account
	var emails []models.Email
	if err := s.db.Where("account_id = ?", accountID).Find(&emails).Error; err != nil {
		return 0, err
	}

	totalEmails := len(emails)
	s.logService.LogInfo(userID, models.LogModuleEmail, "process_account", "Starting batch processing (reprocess all)", map[string]interface{}{
		"account_id":  accountID,
		"email_count": totalEmails,
	})

	// Use worker pool for concurrent processing
	const workerCount = 10 // Number of concurrent workers
	emailChan := make(chan models.Email, totalEmails)
	resultChan := make(chan bool, totalEmails)

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for email := range emailChan {
				emailCopy := email
				if _, err := s.processor.ProcessAndSaveEmail(userID, accountID, &emailCopy); err != nil {
					s.logService.LogWarn(userID, models.LogModuleEmail, "process_email", "Failed to process email", map[string]interface{}{
						"email_id": email.ID,
						"error":    err.Error(),
					})
					resultChan <- false
				} else {
					resultChan <- true
				}
			}
		}()
	}

	// Send emails to workers
	go func() {
		for _, email := range emails {
			emailChan <- email
		}
		close(emailChan)
	}()

	// Wait for all workers to finish
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Count results
	processedCount := 0
	for success := range resultChan {
		if success {
			processedCount++
		}
	}

	s.logService.LogInfo(userID, models.LogModuleEmail, "process_account", "Batch processing completed", map[string]interface{}{
		"account_id":      accountID,
		"total_emails":    totalEmails,
		"processed_count": processedCount,
	})

	return processedCount, nil
}

// ProcessSingleEmail processes a single email
func (s *EmailService) ProcessSingleEmail(userID, emailID uint) error {
	// Get the email
	var email models.Email
	if err := s.db.First(&email, emailID).Error; err != nil {
		return ErrEmailNotFound
	}

	// Verify user owns the email's account
	_, err := s.accountService.GetAccountByIDAndUserID(email.AccountID, userID)
	if err != nil {
		return ErrEmailNotFound
	}

	s.logService.LogInfo(userID, models.LogModuleEmail, "process_single", "Processing single email", map[string]interface{}{
		"email_id": emailID,
	})

	// Process the email
	_, err = s.processor.ProcessAndSaveEmail(userID, email.AccountID, &email)
	if err != nil {
		s.logService.LogError(userID, models.LogModuleEmail, "process_single", "Failed to process email", map[string]interface{}{
			"email_id": emailID,
			"error":    err.Error(),
		})
		return err
	}

	s.logService.LogInfo(userID, models.LogModuleEmail, "process_single", "Email processed successfully", map[string]interface{}{
		"email_id": emailID,
	})

	return nil
}

// DeleteProcessedResult deletes the processed result for an email
func (s *EmailService) DeleteProcessedResult(userID, emailID uint) error {
	// Get the email
	var email models.Email
	if err := s.db.First(&email, emailID).Error; err != nil {
		return ErrEmailNotFound
	}

	// Verify user owns the email's account
	_, err := s.accountService.GetAccountByIDAndUserID(email.AccountID, userID)
	if err != nil {
		return ErrEmailNotFound
	}

	s.logService.LogInfo(userID, models.LogModuleEmail, "delete_result", "Deleting processed result", map[string]interface{}{
		"email_id": emailID,
	})

	// Delete the processed result
	if err := s.db.Where("email_id = ?", emailID).Delete(&models.ProcessedResult{}).Error; err != nil {
		s.logService.LogError(userID, models.LogModuleEmail, "delete_result", "Failed to delete processed result", map[string]interface{}{
			"email_id": emailID,
			"error":    err.Error(),
		})
		return err
	}

	s.logService.LogInfo(userID, models.LogModuleEmail, "delete_result", "Processed result deleted", map[string]interface{}{
		"email_id": emailID,
	})

	return nil
}

// UpdateEmailImportance updates the importance of an email's processed result
func (s *EmailService) UpdateEmailImportance(userID, emailID uint, importance string) error {
	// Get the email
	var email models.Email
	if err := s.db.First(&email, emailID).Error; err != nil {
		return ErrEmailNotFound
	}

	// Verify user owns the email's account
	_, err := s.accountService.GetAccountByIDAndUserID(email.AccountID, userID)
	if err != nil {
		return ErrEmailNotFound
	}

	// Update the processed result's importance
	result := s.db.Model(&models.ProcessedResult{}).Where("email_id = ?", emailID).Update("importance", importance)
	if result.Error != nil {
		return result.Error
	}

	// If no processed result exists, create one
	if result.RowsAffected == 0 {
		processedResult := &models.ProcessedResult{
			EmailID:    emailID,
			Importance: importance,
		}
		if err := s.db.Create(processedResult).Error; err != nil {
			return err
		}
	}

	return nil
}
