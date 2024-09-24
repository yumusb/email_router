package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/mail"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/emersion/go-smtp"
	"github.com/jhillyerd/enmime"
	"gopkg.in/yaml.v2"
)

var headersToRemove = []string{"x-*", "x-spam-*", "x-mailer", "x-originating-*", "x-qq-*", "dkim-*", "x-google-*", "x-cm-*", "x-coremail-*", "x-bq-*"}
var CONFIG Config

type Config struct {
	SMTP     SMTPConfig     `yaml:"smtp"`
	Telegram TelegramConfig `yaml:"telegram"`
}

type SMTPConfig struct {
	ListenAddress    string   `yaml:"listen_address"`
	ListenAddressTls string   `yaml:"listen_address_tls"`
	AllowedDomains   []string `yaml:"allowed_domains"`
	PrivateEmail     string   `yaml:"private_email"`
	CertFile         string   `yaml:"cert_file"` // Certificate file path
	KeyFile          string   `yaml:"key_file"`  // Private key file path
}

type TelegramConfig struct {
	BotToken string `yaml:"bot_token"`
	ChatID   string `yaml:"chat_id"`
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
func GetEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}
func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	err := LoadConfig("config.yml")
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}
	log.Printf("Telegram Chat ID: %s\n", CONFIG.Telegram.ChatID)

	be := &Backend{}

	// Plain SMTP server with STARTTLS support
	plainServer := smtp.NewServer(be)
	plainServer.Addr = CONFIG.SMTP.ListenAddress
	plainServer.Domain = GetEnv("MXDOMAIN", "localhost")
	plainServer.WriteTimeout = 10 * time.Second
	plainServer.ReadTimeout = 10 * time.Second
	plainServer.MaxMessageBytes = 1024 * 1024
	plainServer.MaxRecipients = 50
	plainServer.AllowInsecureAuth = false // Change to true if you want to allow plain auth before STARTTLS (not recommended)

	// Attempt to load TLS configuration for STARTTLS and SMTPS
	cer, err := tls.LoadX509KeyPair(CONFIG.SMTP.CertFile, CONFIG.SMTP.KeyFile)
	if err != nil {
		log.Printf("Loading TLS certificate failed: %v", err)
		log.Printf("Starting plainServer only at %s\n", CONFIG.SMTP.ListenAddress)

		// Start only the plain SMTP server with STARTTLS in a new goroutine
		if err := plainServer.ListenAndServe(); err != nil {
			log.Fatal(err)
		}
	} else {
		// Certificate loaded successfully, configure STARTTLS
		plainServer.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cer}}

		// SMTPS server (TLS only)
		tlsServer := smtp.NewServer(be)
		tlsServer.Addr = CONFIG.SMTP.ListenAddressTls
		tlsServer.Domain = GetEnv("MXDOMAIN", "localhost")
		tlsServer.WriteTimeout = 10 * time.Second
		tlsServer.ReadTimeout = 10 * time.Second
		tlsServer.MaxMessageBytes = 1024 * 1024
		tlsServer.MaxRecipients = 50
		tlsServer.AllowInsecureAuth = false
		tlsServer.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cer}}

		// Start the plain SMTP server with STARTTLS in a new goroutine
		go func() {
			log.Printf("Starting plainServer at %s\n", CONFIG.SMTP.ListenAddress)
			if err := plainServer.ListenAndServe(); err != nil {
				log.Fatal(err)
			}
		}()

		// Start the SMTPS server (TLS only)
		log.Printf("Starting tlsServer at %s\n", CONFIG.SMTP.ListenAddressTls)
		if err := tlsServer.ListenAndServeTLS(); err != nil {
			log.Fatal(err)
		}
	}
}

type Backend struct{}

func (bkd *Backend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	return &Session{}, nil
}

type Session struct {
	from     string
	to       []string
	remoteIP string // Add a field to store the remote IP
	localIP  string // Add a field to store the local IP
}

func (s *Session) Mail(from string, opts *smtp.MailOptions) error {
	if !isValidEmail(from) {
		return errors.New("invalid email address format")
	}
	log.Println("Mail from:", from)
	s.from = from
	return nil
}
func (s *Session) Rcpt(to string, opts *smtp.RcptOptions) error {
	if !isValidEmail(to) {
		return errors.New("invalid email address format")
	}
	log.Println("Rcpt to:", to)
	s.to = append(s.to, to)
	return nil
}

func extractEmails(str string) string {
	str = strings.TrimSpace(str)
	startIndex := strings.LastIndex(str, "<")
	endIndex := strings.LastIndex(str, ">")
	if startIndex == -1 || endIndex == -1 || startIndex >= endIndex {
		return str
	}
	email := str[startIndex+1 : endIndex]
	return email
}
func isValidEmail(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}
func (s *Session) Data(r io.Reader) error {
	buf := new(bytes.Buffer)
	_, err := buf.ReadFrom(r)
	if err != nil {
		return fmt.Errorf("error reading data: %v", err)
	}
	data := buf.Bytes()
	log.Printf("Received email: From=%s To=%s RemoteIP=%s LocalIP=%s", s.from, s.to, s.remoteIP, s.localIP)
	env, err := enmime.ReadEnvelope(bytes.NewReader(data))
	if err != nil {
		log.Printf("Failed to parse email: %v", err)
		return err
	}
	var attachments []string
	for _, attachment := range env.Attachments {
		disposition := attachment.Header.Get("Content-Disposition")
		if disposition != "" {
			_, params, _ := mime.ParseMediaType(disposition)
			if filename, ok := params["filename"]; ok {
				attachments = append(attachments, filename)
			}
		}
	}
	parsedContent := fmt.Sprintf(
		"Received email:\n\n"+
			"From: %s\n"+
			"To: %s\n"+
			"Subject: %s\n"+
			"Date: %s\n"+
			"Content-Type: %s\n\n"+
			"Body:\n%s\n\n"+
			"Attachments:\n%s",
		s.from,
		strings.Join(s.to, ", "),
		env.GetHeader("Subject"),
		env.GetHeader("Date"),
		env.GetHeader("Content-Type"),
		env.Text, // 过滤敏感信息
		strings.Join(attachments, "\n"),
	)
	log.Println("parsed success")
	for _, recipient := range s.to {
		recipient = extractEmails(recipient)
		sender := extractEmails(env.GetHeader("From"))
		for _, domain := range CONFIG.SMTP.AllowedDomains {
			if checkDomain(recipient, domain) {
				log.Println("收件人是允许的收件域，需要进一步处理")
				if !strings.EqualFold(sender, CONFIG.SMTP.PrivateEmail) && !strings.Contains(recipient, "_at_") && !regexp.MustCompile(`^(\w|-)+@.+$`).MatchString(recipient) {
					log.Println("不符合规则的收件人，需要是random@qq.com、ran-dom@qq.com，当前为", recipient)
					break
				}
				if CONFIG.Telegram.ChatID != "" {
					go sendToTelegramBot(parsedContent)
					go sendRawEMLToTelegram(data, env.GetHeader("Subject"))
				} else {
					log.Println("没配置TG转发")
				}
				if CONFIG.SMTP.PrivateEmail != "" {
					formattedSender := ""
					targetAddress := ""
					if strings.EqualFold(sender, CONFIG.SMTP.PrivateEmail) && strings.Contains(recipient, "_at_") {
						originsenderEmail, selfsenderEmail := parseEmails(recipient)
						targetAddress = originsenderEmail
						formattedSender = selfsenderEmail
					} else if strings.EqualFold(sender, CONFIG.SMTP.PrivateEmail) && !strings.Contains(recipient, "_at_") {
						log.Println("not need forward", sender, recipient)
						break
					} else {
						formattedSender = fmt.Sprintf("%s_%s@%s",
							strings.ReplaceAll(strings.ReplaceAll(sender, "@", "_at_"), ".", "_"),
							strings.Split(recipient, "@")[0],
							domain)
						targetAddress = CONFIG.SMTP.PrivateEmail
					}
					go forwardEmailToTargetAddress(data, formattedSender, targetAddress)
				} else {
					log.Println("没配置邮件转发")
				}
				break
			} else {
				log.Println("收件人不是允许的收件域，不需要处理", recipient)
			}
		}
	}
	return nil
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
func forwardEmailToTargetAddress(emailData []byte, formattedSender string, targetAddress string) {
	log.Printf("Preparing to forward email from [%s] to [%s]", formattedSender, targetAddress)
	if formattedSender == "" || targetAddress == "" {
		log.Println("address error")
		return
	}

	privateDomain := strings.SplitN(targetAddress, "@", 2)[1]
	smtpServer, err := getSMTPServer(privateDomain)
	if err != nil {
		log.Printf("Error getting SMTP server: %v", err)
		return
	}

	conn, err := tryDialSMTPPlain(smtpServer, 25)
	if err != nil {
		log.Printf("Failed to connect on port 25: %v", err)
		return
	}
	defer conn.Close()

	tlsConfig := &tls.Config{
		ServerName: smtpServer,
	}
	client, err := smtp.NewClientStartTLS(conn, tlsConfig)
	if err != nil {
		log.Printf("Failed to init StartTlS,%v", err)
		return
	} else {
		log.Printf("Send Mail to %v using StartTlS", smtpServer)
	}
	// Ensure the client is closed properly
	defer func() {
		if client != nil {
			client.Quit()
			client.Close()
		}
	}()

	// Set the sender
	if err := client.Mail(formattedSender, &smtp.MailOptions{}); err != nil {
		log.Printf("Error setting sender: %v", err)
		return
	}

	// Set the recipient
	if err := client.Rcpt(targetAddress, &smtp.RcptOptions{}); err != nil {
		log.Printf("Error setting recipient: %v", err)
		return
	}

	// Get the Data writer and write the email content
	w, err := client.Data()
	if err != nil {
		log.Printf("Error getting Data writer: %v", err)
		return
	}

	// Modify email headers if necessary
	var modifiedEmailData []byte
	if strings.EqualFold(targetAddress, CONFIG.SMTP.PrivateEmail) {
		modifiedEmailData, _ = modifyEmailHeaders(emailData, formattedSender, "")
	} else {
		modifiedEmailData, _ = modifyEmailHeaders(emailData, formattedSender, targetAddress)
		modifiedEmailData, _ = removeEmailHeaders(modifiedEmailData)
	}

	_, err = w.Write(modifiedEmailData)
	if err != nil {
		log.Printf("Error writing email data: %v", err)
	}

	err = w.Close()
	if err != nil {
		log.Printf("Error closing Data writer: %v", err)
	}

	log.Printf("Email successfully forwarded to %s", targetAddress)
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
	log.Printf("Successfully connected to SMTP server on port %d without TLS", port)
	return conn, nil
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
		log.Printf("Failed to marshal JSON payload: %v", err)
		return
	}
	resp, err := http.Post(apiURL, "application/json", bytes.NewBuffer(jsonPayload))
	if err != nil {
		log.Printf("Failed to send message to Telegram bot: %v", err)
		return
	}
	defer resp.Body.Close()
	log.Printf("Message sent to Telegram bot. Response: %s", resp.Status)
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
func sendRawEMLToTelegram(emailData []byte, subject string) {
	botToken := CONFIG.Telegram.BotToken
	chatID := CONFIG.Telegram.ChatID
	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendDocument", botToken)
	tmpFile, err := os.CreateTemp("", "email-*.eml")
	if err != nil {
		log.Printf("Failed to create temporary file: %v", err)
		return
	}
	defer func() {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
	}()

	_, err = tmpFile.Write(emailData)
	if err != nil {
		log.Printf("Failed to write email data to file: %v", err)
		return
	}

	// 使用安全的文件权限
	err = os.Chmod(tmpFile.Name(), 0600)
	if err != nil {
		log.Printf("Failed to set file permissions: %v", err)
		return
	}

	tmpFile.Seek(0, 0)
	file, err := os.Open(tmpFile.Name())
	if err != nil {
		log.Printf("Failed to open temporary file: %v", err)
		return
	}
	defer file.Close()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("document", tmpFile.Name())
	if err != nil {
		log.Printf("Failed to create form file: %v", err)
		return
	}

	_, err = io.Copy(part, file)
	if err != nil {
		log.Printf("Failed to copy file data: %v", err)
		return
	}

	_ = writer.WriteField("chat_id", chatID)
	_ = writer.WriteField("caption", subject)
	err = writer.Close()
	if err != nil {
		log.Printf("Failed to close writer: %v", err)
		return
	}

	req, err := http.NewRequest("POST", apiURL, body)
	if err != nil {
		log.Printf("Failed to create HTTP request: %v", err)
		return
	}

	req.Header.Add("Content-Type", writer.FormDataContentType())

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Failed to send email as EML to Telegram: %v", err)
		return
	}
	defer resp.Body.Close()
	log.Printf("Raw EML sent to Telegram bot. Response: %s", resp.Status)
}

func checkDomain(email, domain string) bool {
	return strings.HasSuffix(strings.ToLower(email), "@"+strings.ToLower(domain))
}

func (s *Session) Reset() {}

func (s *Session) Logout() error {
	return nil
}
