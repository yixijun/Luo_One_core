package services

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"time"
)

const (
	connectionTimeout = 10 * time.Second
)

// buildAddress builds a host:port address string
func buildAddress(host string, port int) string {
	return fmt.Sprintf("%s:%d", host, port)
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
	if len(response) >= 6 && response[:6] == "A001 OK" {
		// Logout
		conn.Write([]byte("A002 LOGOUT\r\n"))
		return ConnectionTestResult{
			Success: true,
			Message: "IMAP connection and authentication successful",
		}
	}

	return ConnectionTestResult{
		Success: false,
		Message: "IMAP authentication failed: " + response,
	}
}

// testSMTPConnectionInternal tests an SMTP connection
func testSMTPConnectionInternal(addr, username, password string, useSSL bool) ConnectionTestResult {
	var client *smtp.Client
	var err error

	if useSSL {
		// Connect with TLS (SMTPS)
		tlsConfig := &tls.Config{
			InsecureSkipVerify: false,
		}
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: connectionTimeout}, "tcp", addr, tlsConfig)
		if err != nil {
			return ConnectionTestResult{
				Success: false,
				Message: fmt.Sprintf("Failed to connect to SMTP server: %v", err),
			}
		}
		defer conn.Close()

		// Extract host from address
		host, _, _ := net.SplitHostPort(addr)
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
			}
			if err := client.StartTLS(tlsConfig); err != nil {
				// STARTTLS failed, but we can continue without it
			}
		}
	}
	defer client.Close()

	// Try to authenticate
	host, _, _ := net.SplitHostPort(addr)
	auth := smtp.PlainAuth("", username, password, host)
	if err := client.Auth(auth); err != nil {
		return ConnectionTestResult{
			Success: false,
			Message: fmt.Sprintf("SMTP authentication failed: %v", err),
		}
	}

	return ConnectionTestResult{
		Success: true,
		Message: "SMTP connection and authentication successful",
	}
}
