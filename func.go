package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/yumusb/go-smtp"
	"gopkg.in/yaml.v2"
)

func GetEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}
func LoadConfig(filePath string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}
	err = yaml.Unmarshal(data, &CONFIG)
	if err != nil {
		return err
	}
	return nil
}
func isValidEmail(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}
func extractEmails(str string) string {
	str = strings.TrimSpace(str)
	address, err := mail.ParseAddress(str)
	if err != nil {
		return str
	}
	return address.Address
}
func removeEmailHeaders(emailData []byte) ([]byte, error) {
	msg, err := mail.ReadMessage(bytes.NewReader(emailData))
	if err != nil {
		return nil, err
	}
	// Read the original email headers
	headers := make(map[string]string)
	for k, v := range msg.Header {
		headers[strings.ToLower(k)] = strings.Join(v, ", ") // Store headers in lowercase
	}
	// Create regex patterns from the headersToRemove
	patterns := make([]*regexp.Regexp, len(headersToRemove))
	for i, header := range headersToRemove {
		// Convert wildcard '*' to regex pattern
		regexPattern := "^" + regexp.QuoteMeta(strings.ToLower(header)) + "$"
		regexPattern = strings.ReplaceAll(regexPattern, "\\*.", ".*") // Match anything after the wildcard
		regexPattern = strings.ReplaceAll(regexPattern, "\\*", ".*")  // Match anything with wildcard
		patterns[i] = regexp.MustCompile(regexPattern)
	}
	// Remove specified headers
	for k := range headers {
		for _, pattern := range patterns {
			if pattern.MatchString(k) {
				delete(headers, k)
				break
			}
		}
	}

	// Build the new email content without the removed headers
	var buf bytes.Buffer
	for k, v := range headers {
		fmt.Fprintf(&buf, "%s: %s\r\n", k, v)
	}
	buf.WriteString("\r\n")

	// Append the original email body
	body, err := io.ReadAll(msg.Body)
	if err != nil {
		return nil, err
	}
	buf.Write(body)

	return buf.Bytes(), nil
}
func addEmailHeaders(emailData []byte, headersToAdd map[string]string) ([]byte, error) {
	msg, err := mail.ReadMessage(bytes.NewReader(emailData))
	if err != nil {
		return nil, err
	}

	// Read the original email headers
	headers := make(map[string]string)
	for k, v := range msg.Header {
		headers[k] = strings.Join(v, ", ") // Store headers with original casing
	}

	// Add the specified headers with the prefix and uppercase keys
	for header, value := range headersToAdd {
		upperHeader := strings.ToUpper(headerPrefix + header) // Add prefix and convert to uppercase
		if existingValue, exists := headers[upperHeader]; exists {
			// If the header already exists, append the new value
			headers[upperHeader] = existingValue + ", " + value
		} else {
			headers[upperHeader] = value
		}
	}

	// Build the new email content with added headers
	var buf bytes.Buffer
	for k, v := range headers {
		fmt.Fprintf(&buf, "%s: %s\r\n", k, v)
	}
	buf.WriteString("\r\n")

	// Append the original email body
	body, err := io.ReadAll(msg.Body)
	if err != nil {
		return nil, err
	}
	buf.Write(body)

	return buf.Bytes(), nil
}

func modifyEmailHeaders(emailData []byte, newSender, newRecipient string) ([]byte, error) {
	msg, err := mail.ReadMessage(bytes.NewReader(emailData))
	if err != nil {
		return nil, err
	}
	// Read the original email headers
	headers := make(map[string]string)
	for k, v := range msg.Header {
		headers[k] = strings.Join(v, ", ")
	}
	// Modify the 'From' header
	if newSender != "" {
		headers["From"] = newSender
	}
	// Modify the 'To' header
	if newRecipient != "" {
		headers["To"] = newRecipient
	}
	// Build the new email content
	var buf bytes.Buffer
	for k, v := range headers {
		fmt.Fprintf(&buf, "%s: %s\r\n", k, v)
	}
	buf.WriteString("\r\n")
	// Append the original email body
	body, err := io.ReadAll(msg.Body)
	if err != nil {
		return nil, err
	}
	buf.Write(body)
	return buf.Bytes(), nil
}
func smtpResponse(statusCode int, message string) error {
	return fmt.Errorf("%d: %s", statusCode, message)
}
func checkDomain(email, domain string) bool {
	return strings.HasSuffix(strings.ToLower(email), "@"+strings.ToLower(domain))
}
func getDomainFromEmail(email string) string {
	address, err := mail.ParseAddress(email)
	if err != nil {
		return ""
	}
	at := strings.LastIndex(address.Address, "@")
	if at == -1 {
		return ""
	}
	return address.Address[at+1:]
}
func parseEmails(input string) (string, string) {
	lastUnderscoreIndex := strings.LastIndex(input, "_")
	if lastUnderscoreIndex == -1 {
		return "", ""
	}
	secondEmail := input[lastUnderscoreIndex+1:]
	firstPart := input[:lastUnderscoreIndex]
	firstEmail := strings.ReplaceAll(firstPart, "_at_", "@")
	firstEmail = strings.ReplaceAll(firstEmail, "_", ".")
	return firstEmail, secondEmail
}

func getSMTPServer(domain string) (string, error) {
	mxRecords, err := net.LookupMX(domain)
	if err != nil {
		return "", fmt.Errorf("failed to lookup MX records: %v", err)
	}
	if len(mxRecords) == 0 {
		return "", fmt.Errorf("no MX records found for domain: %s", domain)
	}
	return mxRecords[0].Host, nil
}
func isCertInvalidError(err error) bool {
	if err == nil {
		return false
	}
	// Check if the error contains information about an invalid certificate
	if strings.Contains(err.Error(), "x509: certificate signed by unknown authority") ||
		strings.Contains(err.Error(), "certificate is not trusted") ||
		strings.Contains(err.Error(), "tls: failed to verify certificate") {
		return true
	}
	return false
}
func (s *Session) Reset() {}

func (s *Session) Logout() error {
	return nil
}
func (bkd *Backend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	remoteIP := c.Conn().RemoteAddr().String()
	localIP := c.Conn().LocalAddr().String()
	clientHostname := c.Hostname()
	session := &Session{
		remoteIP:       remoteIP,
		localIP:        localIP,
		clientHostname: clientHostname,
	}
	return session, nil
}

func (s *Session) Mail(from string, opts *smtp.MailOptions) error {
	if !isValidEmail(from) {
		return errors.New("invalid email address format")
	}
	s.from = from
	return nil
}
func (s *Session) Rcpt(to string, opts *smtp.RcptOptions) error {
	if !isValidEmail(to) {
		return errors.New("invalid email address format")
	}
	s.to = append(s.to, to)
	return nil
}
func sendToTelegramBot(message string) {
	botToken := CONFIG.Telegram.BotToken
	chatID := CONFIG.Telegram.ChatID
	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", botToken)
	payload := map[string]interface{}{
		"chat_id": chatID,
		"text":    message,
	}
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		logrus.Errorf("Failed to marshal JSON payload: %v", err)
		return
	}
	resp, err := http.Post(apiURL, "application/json", bytes.NewBuffer(jsonPayload))
	if err != nil {
		logrus.Errorf("Failed to send message to Telegram bot: %v", err)
		return
	}
	defer resp.Body.Close()
	logrus.Infof("Message sent to Telegram bot. Response: %s", resp.Status)
	if resp.StatusCode != 200 {
		logrus.Warn("Non-200 response from Telegram bot")
	}
}

func sendRawEMLToTelegram(emailData []byte, subject string) {
	botToken := CONFIG.Telegram.BotToken
	chatID := CONFIG.Telegram.ChatID
	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendDocument", botToken)
	tmpFile, err := os.CreateTemp("", "email-*.eml")
	if err != nil {
		logrus.Errorf("Failed to create temporary file: %v", err)
		return
	}
	defer func() {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
	}()

	_, err = tmpFile.Write(emailData)
	if err != nil {
		logrus.Errorf("Failed to write email data to file: %v", err)
		return
	}

	// 使用安全的文件权限
	err = os.Chmod(tmpFile.Name(), 0600)
	if err != nil {
		logrus.Errorf("Failed to set file permissions: %v", err)
		return
	}

	tmpFile.Seek(0, 0)
	file, err := os.Open(tmpFile.Name())
	if err != nil {
		logrus.Errorf("Failed to open temporary file: %v", err)
		return
	}
	defer file.Close()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("document", tmpFile.Name())
	if err != nil {
		logrus.Errorf("Failed to create form file: %v", err)
		return
	}
	_, err = io.Copy(part, file)
	if err != nil {
		logrus.Errorf("Failed to copy file data: %v", err)
		return
	}

	_ = writer.WriteField("chat_id", chatID)
	_ = writer.WriteField("caption", subject)
	err = writer.Close()
	if err != nil {
		logrus.Errorf("Failed to close writer: %v", err)
		return
	}

	req, err := http.NewRequest("POST", apiURL, body)
	if err != nil {
		logrus.Errorf("Failed to create HTTP request: %v", err)
		return
	}
	req.Header.Add("Content-Type", writer.FormDataContentType())
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		logrus.Errorf("Failed to send email as EML to Telegram: %v", err)
		return
	}
	defer resp.Body.Close()
	logrus.Infof("Raw EML sent to Telegram bot. Response: %s", resp.Status)
}
func forwardEmailToTargetAddress(emailData []byte, formattedSender string, targetAddress string, s *Session) {
	logrus.Infof("Preparing to forward email from [%s] to [%s]", formattedSender, targetAddress)
	if formattedSender == "" || targetAddress == "" {
		logrus.Warn("Address error: either sender or recipient address is empty")
		return
	}
	privateDomain := strings.SplitN(targetAddress, "@", 2)[1]
	smtpServer, err := getSMTPServer(privateDomain)
	if err != nil {
		logrus.Errorf("Error retrieving SMTP server for domain [%s]: %v", privateDomain, err)
		return
	}

	// Attempt to connect to SMTP server using plain connection on port 25
	conn, err := tryDialSMTPPlain(smtpServer, 25)
	if err != nil {
		logrus.Errorf("Failed to establish connection on port 25: %v", err)
		return
	}
	defer conn.Close()

	// Attempt to initiate STARTTLS for secure email transmission
	tlsConfig := &tls.Config{
		ServerName: smtpServer,
	}
	client, err := smtp.NewClientStartTLSWithLocalName(conn, tlsConfig, getDomainFromEmail(formattedSender))
	if err != nil {
		logrus.Errorf("Failed to establish STARTTLS: %v", err)
		// Downgrade to plain SMTP (non-TLS) because STARTTLS negotiation failed
		logrus.Warn("Downgrading to plain SMTP due to failed STARTTLS handshake.")
		conn.Close()
		conn, err = tryDialSMTPPlain(smtpServer, 25)
		if err != nil {
			logrus.Errorf("Failed to reconnect on port 25 for plain SMTP: %v", err)
			return
		}
		defer conn.Close()
		client = smtp.NewClientWithLocalName(conn, getDomainFromEmail(formattedSender)) // Re-create the SMTP client without encryption
	} else {
		logrus.Infof("STARTTLS connection established successfully with [%s]", smtpServer)
	}

	// Ensure the client connection is properly closed
	defer func() {
		if client != nil {
			client.Quit()
			client.Close()
		}
	}()

	// Set the MAIL FROM command with the sender address
	err = client.Mail(formattedSender, &smtp.MailOptions{})
	if err != nil {
		// If there's a certificate validation issue, downgrade to non-TLS
		if isCertInvalidError(err) {
			logrus.Errorf("TLS certificate validation failed: %v", err)
			logrus.Warn("Falling back to plain SMTP as certificate verification failed.")
			conn.Close()
			conn, err = tryDialSMTPPlain(smtpServer, 25)
			if err != nil {
				logrus.Errorf("Failed to reconnect on port 25 for plain SMTP after TLS failure: %v", err)
				return
			}
			defer conn.Close()
			client = smtp.NewClientWithLocalName(conn, getDomainFromEmail(formattedSender)) // Restart the client after failing TLS
			if err := client.Mail(formattedSender, &smtp.MailOptions{}); err != nil {
				logrus.Errorf("Error setting MAIL FROM on plain SMTP: %v", err)
				return
			}
		} else {
			logrus.Errorf("Error setting MAIL FROM: %v", err)
			return
		}
	}
	if err := client.Rcpt(targetAddress, &smtp.RcptOptions{}); err != nil {
		logrus.Errorf("Error setting RCPT TO: %v", err)
		return
	}
	w, err := client.Data()
	if err != nil {
		logrus.Errorf("Error initiating email data transfer: %v", err)
		return
	}
	var modifiedEmailData []byte
	if strings.EqualFold(targetAddress, CONFIG.SMTP.PrivateEmail) {
		// If the email is being forwarded to a private address, add custom headers
		modifiedEmailData, _ = modifyEmailHeaders(emailData, formattedSender, "")
		headersToAdd := map[string]string{
			"Original-From":   s.from,
			"Original-To":     strings.Join(s.to, ","),
			"Original-Server": s.remoteIP,
			"SPF-RESULT":      s.spfResult.String(),
		}
		modifiedEmailData, _ = addEmailHeaders(modifiedEmailData, headersToAdd)
	} else {
		// Otherwise, just modify headers to adjust sender/recipient as needed
		modifiedEmailData, _ = modifyEmailHeaders(emailData, formattedSender, targetAddress)
		modifiedEmailData, _ = removeEmailHeaders(modifiedEmailData) // Optionally remove unwanted headers
	}

	// Write the modified email data to the server
	_, err = w.Write(modifiedEmailData)
	if err != nil {
		logrus.Errorf("Error writing email data: %v", err)
	}

	// Close the data writer, finalizing the email transmission
	err = w.Close()
	if err != nil {
		logrus.Errorf("Error finalizing email data transfer: %v", err)
	}

	logrus.Infof("Email successfully forwarded to [%s]", targetAddress)
}

func tryDialSMTPPlain(smtpServer string, port int) (net.Conn, error) {
	dialer := net.Dialer{
		Timeout:   5 * time.Second,  // Connection timeout
		KeepAlive: 30 * time.Second, // Keep alive interval
	}
	address := fmt.Sprintf("%s:%d", smtpServer, port)
	conn, err := dialer.Dial("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("failed to dial SMTP server on port %d: %v", port, err)
	}
	logrus.Infof("Successfully connected to SMTP server on port %d without TLS", port)
	return conn, nil
}
func getPrimaryContentType(contentType string) string {
	// Split the Content-Type by semicolon and return the first part
	parts := strings.Split(contentType, ";")
	return strings.TrimSpace(parts[0])
}
func sendWebhook(config WebhookConfig, title, content string) (*http.Response, error) {
	if !config.Enabled {
		return nil, fmt.Errorf("webhook is disabled")
	}
	var requestBody []byte
	var err error
	if config.BodyType == "json" {
		body := make(map[string]string)
		for key, value := range config.Body {
			formattedValue := strings.ReplaceAll(value, "{{.Title}}", title)
			formattedValue = strings.ReplaceAll(formattedValue, "{{.Content}}", content)
			body[key] = formattedValue
		}
		requestBody, err = json.Marshal(body)
		if err != nil {
			return nil, err
		}
	} else if config.BodyType == "form" {
		form := url.Values{}
		for key, value := range config.Body {
			formattedValue := strings.ReplaceAll(value, "{{.Title}}", title)
			formattedValue = strings.ReplaceAll(formattedValue, "{{.Content}}", content)
			form.Add(key, formattedValue)
		}
		requestBody = []byte(form.Encode())
	}
	req, err := http.NewRequest(config.Method, config.URL, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, err
	}
	for key, value := range config.Headers {
		req.Header.Set(key, value)
	}
	if config.BodyType == "json" {
		req.Header.Set("Content-Type", "application/json")
	} else if config.BodyType == "form" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	logrus.Infof("Webhook response status: %s", resp.Status)
	return resp, nil
}
func getFirstMatchingEmail(recipients []string) string {
	// Loop through all recipients
	for _, recipient := range recipients {
		recipientEmail := extractEmails(recipient)
		for _, domain := range CONFIG.SMTP.AllowedDomains {
			if checkDomain(recipientEmail, domain) {
				return recipientEmail
			}
		}
	}
	return ""
}
func shouldForwardEmail(recipients []string) bool {
	// Loop through all recipients
	for _, recipient := range recipients {
		recipientEmail := extractEmails(recipient)
		for _, domain := range CONFIG.SMTP.AllowedDomains {
			if checkDomain(recipientEmail, domain) {
				return true // Forward if recipient matches allowed domain
			}
		}
	}
	return false // No matching domains, no forwarding
}
