package services

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"
)

const (
	connectionTimeout = 10 * time.Second
)

// buildAddress builds a host:port address string
func buildAddress(host string, port int) string {
	return fmt.Sprintf("%s:%d", host, port)
}

// connLoginAuth implements smtp.Auth for LOGIN authentication (for connection testing)
type connLoginAuth struct {
	username, password string
}

func newConnLoginAuth(username, password string) smtp.Auth {
	return &connLoginAuth{username, password}
}

func (a *connLoginAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	return "LOGIN", []byte{}, nil
}

func (a *connLoginAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if more {
		switch string(fromServer) {
		case "Username:", "username:":
			return []byte(a.username), nil
		case "Password:", "password:":
			return []byte(a.password), nil
		default:
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

// isChineseMailProvider checks if the host is a Chinese email provider
func isChineseMailProvider(host string) bool {
	return strings.Contains(host, "qq.com") ||
		strings.Contains(host, "163.com") ||
		strings.Contains(host, "126.com") ||
		strings.Contains(host, "yeah.net") ||
		strings.Contains(host, "sina.com") ||
		strings.Contains(host, "sohu.com") ||
		strings.Contains(host, "aliyun.com") ||
		strings.Contains(host, "188.com")
}

// testIMAPConnectionInternal tests an IMAP connection
func testIMAPConnectionInternal(addr, username, password string, useSSL bool) ConnectionTestResult {
	var conn net.Conn
	var err error

	// Set up dialer with timeout
	dialer := &net.Dialer{
		Timeout: connectionTimeout,
	}

	if useSSL {
		// Connect with TLS
		tlsConfig := &tls.Config{
			InsecureSkipVerify: false,
		}
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
	} else {
		// Connect without TLS
		conn, err = dialer.Dial("tcp", addr)
	}

	if err != nil {
		return ConnectionTestResult{
			Success: false,
			Message: fmt.Sprintf("Failed to connect to IMAP server: %v", err),
		}
	}
	defer conn.Close()

	// Set read deadline
	conn.SetReadDeadline(time.Now().Add(connectionTimeout))

	// Read server greeting
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return ConnectionTestResult{
			Success: false,
			Message: fmt.Sprintf("Failed to read IMAP greeting: %v", err),
		}
	}

	greeting := string(buf[:n])
	if len(greeting) < 4 || greeting[:4] != "* OK" {
		return ConnectionTestResult{
			Success: false,
			Message: "Invalid IMAP server response",
		}
	}

	// Try to login
	loginCmd := fmt.Sprintf("A001 LOGIN %s %s\r\n", username, password)
	_, err = conn.Write([]byte(loginCmd))
	if err != nil {
		return ConnectionTestResult{
			Success: false,
			Message: fmt.Sprintf("Failed to send login command: %v", err),
		}
	}

	// Read login response
	conn.SetReadDeadline(time.Now().Add(connectionTimeout))
	n, err = conn.Read(buf)
	if err != nil {
		return ConnectionTestResult{
			Success: false,
			Message: fmt.Sprintf("Failed to read login response: %v", err),
		}
	}

	response := string(buf[:n])
	// Check if response contains "A001 OK" - indicates successful login
	// Response format: "A001 OK LOGIN completed" or similar
	if strings.Contains(response, "A001 OK") {
		// Logout
		conn.Write([]byte("A002 LOGOUT\r\n"))
		return ConnectionTestResult{
			Success: true,
			Message: "IMAP connection and authentication successful",
		}
	}

	// Check for explicit failure responses
	if strings.Contains(response, "A001 NO") || strings.Contains(response, "A001 BAD") {
		return ConnectionTestResult{
			Success: false,
			Message: "IMAP authentication failed: " + strings.TrimSpace(response),
		}
	}

	return ConnectionTestResult{
		Success: false,
		Message: "IMAP authentication failed: " + strings.TrimSpace(response),
	}
}

// testSMTPConnectionInternal tests an SMTP connection
func testSMTPConnectionInternal(addr, username, password string, useSSL bool) ConnectionTestResult {
	var client *smtp.Client
	var err error

	host, _, _ := net.SplitHostPort(addr)
	useLoginAuth := isChineseMailProvider(host)

	if useSSL {
		// Connect with TLS (SMTPS)
		tlsConfig := &tls.Config{
			InsecureSkipVerify: false,
			ServerName:         host,
		}
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: connectionTimeout}, "tcp", addr, tlsConfig)
		if err != nil {
			return ConnectionTestResult{
				Success: false,
				Message: fmt.Sprintf("Failed to connect to SMTP server: %v", err),
			}
		}
		defer conn.Close()

		client, err = smtp.NewClient(conn, host)
		if err != nil {
			return ConnectionTestResult{
				Success: false,
				Message: fmt.Sprintf("Failed to create SMTP client: %v", err),
			}
		}
	} else {
		// Connect without TLS, may use STARTTLS
		client, err = smtp.Dial(addr)
		if err != nil {
			return ConnectionTestResult{
				Success: false,
				Message: fmt.Sprintf("Failed to connect to SMTP server: %v", err),
			}
		}

		// Try STARTTLS if available
		if ok, _ := client.Extension("STARTTLS"); ok {
			tlsConfig := &tls.Config{
				InsecureSkipVerify: false,
				ServerName:         host,
			}
			if err := client.StartTLS(tlsConfig); err != nil {
				// STARTTLS failed, but we can continue without it
			}
		}
	}
	defer client.Close()

	// Try to authenticate with appropriate method
	var auth smtp.Auth
	if useLoginAuth {
		auth = newConnLoginAuth(username, password)
	} else {
		auth = smtp.PlainAuth("", username, password, host)
	}

	if err := client.Auth(auth); err != nil {
		// Try fallback auth method
		if useLoginAuth {
			auth = smtp.PlainAuth("", username, password, host)
		} else {
			auth = newConnLoginAuth(username, password)
		}
		if err2 := client.Auth(auth); err2 != nil {
			return ConnectionTestResult{
				Success: false,
				Message: fmt.Sprintf("SMTP authentication failed: %v", err),
			}
		}
	}

	return ConnectionTestResult{
		Success: true,
		Message: "SMTP connection and authentication successful",
	}
}
