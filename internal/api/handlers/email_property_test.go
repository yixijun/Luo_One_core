package handlers

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
	"github.com/luo-one/core/internal/database"
	"github.com/luo-one/core/internal/database/models"
	"github.com/luo-one/core/internal/services"
	"github.com/luo-one/core/internal/user"
)

// Feature: luo-one-email-manager, Property 14: 邮件列表排序正确性
// For any email list query, when sorted by time, emails should be in descending
// order by date; when sorted by sender, emails should be in alphabetical order
// by sender address.
// Validates: Requirements 8.3

func TestProperty_EmailListSorting(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 20
	properties := gopter.NewProperties(parameters)

	// Generator for email subjects
	subjectGen := gen.SliceOfN(10, gen.AlphaChar()).Map(func(chars []rune) string {
		return string(chars)
	})

	// Generator for email addresses
	emailAddrGen := gen.SliceOfN(6, gen.AlphaLowerChar()).Map(func(chars []rune) string {
		return string(chars) + "@test.com"
	})

	// Generator for number of emails (2-10)
	emailCountGen := gen.IntRange(2, 10)

	// Property 14.1: Emails sorted by date should be in descending order
	properties.Property("emails_sorted_by_date_descending", prop.ForAll(
		func(emailCount int, subjects []string, senders []string) bool {
			// Create a fresh temp directory and database for each test
			tempDir, err := os.MkdirTemp("", "luo_one_email_sort_test_*")
			if err != nil {
				return false
			}
			defer os.RemoveAll(tempDir)

			dbPath := filepath.Join(tempDir, "test.db")
			db, err := database.Initialize(dbPath)
			if err != nil {
				return false
			}
			// Close database connection when done
			sqlDB, _ := db.DB()
			defer sqlDB.Close()

			userManager := user.NewManager(tempDir)
			userService := services.NewUserService(db, userManager)

			// Create a test user
			testUser, err := userService.CreateUser("testuser", "password123", "Test User")
			if err != nil {
				return false
			}

			// Create encryption key and account service
			encryptionKey := []byte("test-encryption-key-32-bytes!!")
			accountService := services.NewAccountService(db, encryptionKey)

			// Create a test email account
			account, err := accountService.CreateAccount(services.CreateAccountInput{
				UserID:   testUser.ID,
				Email:    "test@example.com",
				IMAPHost: "imap.example.com",
				IMAPPort: 993,
				SMTPHost: "smtp.example.com",
				SMTPPort: 587,
				Username: "test@example.com",
				Password: "testpassword",
				UseSSL:   true,
			})
			if err != nil {
				return false
			}

			// Create emails with different dates
			baseTime := time.Now()
			for i := 0; i < emailCount && i < len(subjects) && i < len(senders); i++ {
				email := &models.Email{
					AccountID: account.ID,
					MessageID: subjects[i] + "@test.com",
					Subject:   subjects[i],
					FromAddr:  senders[i],
					Date:      baseTime.Add(time.Duration(i) * time.Hour), // Different times
					Body:      "Test body",
				}
				if err := db.Create(email).Error; err != nil {
					return false
				}
			}

			// Create email service and list emails sorted by date desc
			emailService := services.NewEmailService(db, accountService, userManager)
			result, err := emailService.ListEmails(testUser.ID, services.EmailListOptions{
				AccountID: account.ID,
				SortBy:    "date",
				SortOrder: "desc",
				Limit:     100,
			})
			if err != nil {
				return false
			}

			// Verify emails are sorted by date in descending order
			for i := 1; i < len(result.Emails); i++ {
				if result.Emails[i-1].Date.Before(result.Emails[i].Date) {
					return false // Previous email should have later or equal date
				}
			}

			return true
		},
		emailCountGen,
		gen.SliceOfN(10, subjectGen),
		gen.SliceOfN(10, emailAddrGen),
	))

	// Property 14.2: Emails sorted by date ascending should be in ascending order
	properties.Property("emails_sorted_by_date_ascending", prop.ForAll(
		func(emailCount int, subjects []string, senders []string) bool {
			// Create a fresh temp directory and database for each test
			tempDir, err := os.MkdirTemp("", "luo_one_email_sort_asc_test_*")
			if err != nil {
				return false
			}
			defer os.RemoveAll(tempDir)

			dbPath := filepath.Join(tempDir, "test.db")
			db, err := database.Initialize(dbPath)
			if err != nil {
				return false
			}
			// Close database connection when done
			sqlDB, _ := db.DB()
			defer sqlDB.Close()

			userManager := user.NewManager(tempDir)
			userService := services.NewUserService(db, userManager)

			// Create a test user
			testUser, err := userService.CreateUser("testuser", "password123", "Test User")
			if err != nil {
				return false
			}

			// Create encryption key and account service
			encryptionKey := []byte("test-encryption-key-32-bytes!!")
			accountService := services.NewAccountService(db, encryptionKey)

			// Create a test email account
			account, err := accountService.CreateAccount(services.CreateAccountInput{
				UserID:   testUser.ID,
				Email:    "test@example.com",
				IMAPHost: "imap.example.com",
				IMAPPort: 993,
				SMTPHost: "smtp.example.com",
				SMTPPort: 587,
				Username: "test@example.com",
				Password: "testpassword",
				UseSSL:   true,
			})
			if err != nil {
				return false
			}

			// Create emails with different dates
			baseTime := time.Now()
			for i := 0; i < emailCount && i < len(subjects) && i < len(senders); i++ {
				email := &models.Email{
					AccountID: account.ID,
					MessageID: subjects[i] + "@test.com",
					Subject:   subjects[i],
					FromAddr:  senders[i],
					Date:      baseTime.Add(time.Duration(i) * time.Hour),
					Body:      "Test body",
				}
				if err := db.Create(email).Error; err != nil {
					return false
				}
			}

			// Create email service and list emails sorted by date asc
			emailService := services.NewEmailService(db, accountService, userManager)
			result, err := emailService.ListEmails(testUser.ID, services.EmailListOptions{
				AccountID: account.ID,
				SortBy:    "date",
				SortOrder: "asc",
				Limit:     100,
			})
			if err != nil {
				return false
			}

			// Verify emails are sorted by date in ascending order
			for i := 1; i < len(result.Emails); i++ {
				if result.Emails[i-1].Date.After(result.Emails[i].Date) {
					return false // Previous email should have earlier or equal date
				}
			}

			return true
		},
		emailCountGen,
		gen.SliceOfN(10, subjectGen),
		gen.SliceOfN(10, emailAddrGen),
	))

	// Property 14.3: Emails sorted by sender should be in alphabetical order
	properties.Property("emails_sorted_by_sender_alphabetically", prop.ForAll(
		func(emailCount int, subjects []string, senders []string) bool {
			// Create a fresh temp directory and database for each test
			tempDir, err := os.MkdirTemp("", "luo_one_email_sort_sender_test_*")
			if err != nil {
				return false
			}
			defer os.RemoveAll(tempDir)

			dbPath := filepath.Join(tempDir, "test.db")
			db, err := database.Initialize(dbPath)
			if err != nil {
				return false
			}
			// Close database connection when done
			sqlDB, _ := db.DB()
			defer sqlDB.Close()

			userManager := user.NewManager(tempDir)
			userService := services.NewUserService(db, userManager)

			// Create a test user
			testUser, err := userService.CreateUser("testuser", "password123", "Test User")
			if err != nil {
				return false
			}

			// Create encryption key and account service
			encryptionKey := []byte("test-encryption-key-32-bytes!!")
			accountService := services.NewAccountService(db, encryptionKey)

			// Create a test email account
			account, err := accountService.CreateAccount(services.CreateAccountInput{
				UserID:   testUser.ID,
				Email:    "test@example.com",
				IMAPHost: "imap.example.com",
				IMAPPort: 993,
				SMTPHost: "smtp.example.com",
				SMTPPort: 587,
				Username: "test@example.com",
				Password: "testpassword",
				UseSSL:   true,
			})
			if err != nil {
				return false
			}

			// Create emails with different senders
			baseTime := time.Now()
			for i := 0; i < emailCount && i < len(subjects) && i < len(senders); i++ {
				email := &models.Email{
					AccountID: account.ID,
					MessageID: subjects[i] + "@test.com",
					Subject:   subjects[i],
					FromAddr:  senders[i],
					Date:      baseTime.Add(time.Duration(i) * time.Hour),
					Body:      "Test body",
				}
				if err := db.Create(email).Error; err != nil {
					return false
				}
			}

			// Create email service and list emails sorted by sender asc
			emailService := services.NewEmailService(db, accountService, userManager)
			result, err := emailService.ListEmails(testUser.ID, services.EmailListOptions{
				AccountID: account.ID,
				SortBy:    "from",
				SortOrder: "asc",
				Limit:     100,
			})
			if err != nil {
				return false
			}

			// Verify emails are sorted by sender in ascending alphabetical order
			senderList := make([]string, len(result.Emails))
			for i, email := range result.Emails {
				senderList[i] = email.FromAddr
			}

			return sort.StringsAreSorted(senderList)
		},
		emailCountGen,
		gen.SliceOfN(10, subjectGen),
		gen.SliceOfN(10, emailAddrGen),
	))

	properties.TestingRun(t)
}
