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
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/jhillyerd/enmime"
	"github.com/mileusna/spf"
	"github.com/yumusb/go-smtp"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	err := LoadConfig("config.yml")
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}
	log.Printf("Telegram Chat ID: %s\n", CONFIG.Telegram.ChatID)
	spf.DNSServer = "1.1.1.1:53"
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
	log.Println(resp.Status)
	return resp, nil
}
func (s *Session) Data(r io.Reader) error {
	buf := new(bytes.Buffer)
	_, err := buf.ReadFrom(r)
	if err != nil {
		return fmt.Errorf("error reading data: %v", err)
	}
	data := buf.Bytes()
	log.Printf("Received email: From=%s To=%s RemoteIP=%s LocalIP=%s clientHostname=%s", s.from, s.to, s.remoteIP, s.localIP, s.clientHostname)
	remote_host, _, err := net.SplitHostPort(s.remoteIP)
	if err != nil {
		log.Println("parse remote addr failed")
	}
	remote_ip := net.ParseIP(remote_host)
	s.spfResult = spf.CheckHost(remote_ip, getDomainFromEmail(s.from), s.from, s.clientHostname)
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
	switch s.spfResult {
	case spf.None:
		log.Printf("SPF Result: NONE - No SPF record found for domain %s. Rejecting email.", getDomainFromEmail(s.from))
		// Stop further processing if there's no SPF record
		return fmt.Errorf("SPF validation failed: no SPF record found")
	case spf.Neutral:
		log.Printf("SPF Result: NEUTRAL - Domain %s neither permits nor denies sending mail from IP %s", getDomainFromEmail(s.from), s.remoteIP)
		// Continue processing the email
	case spf.Pass:
		log.Printf("SPF Result: PASS - SPF check passed for domain %s, email is legitimate", getDomainFromEmail(s.from))
		// Continue processing the email
	case spf.Fail:
		log.Printf("SPF Result: FAIL - SPF check failed for domain %s, mail from IP %s is unauthorized", getDomainFromEmail(s.from), s.remoteIP)
		// Stop further processing
		return fmt.Errorf("SPF validation failed: unauthorized sender")
	case spf.Softfail:
		log.Printf("SPF Result: SOFTFAIL - SPF check soft failed for domain %s, email is suspicious", getDomainFromEmail(s.from))
		// Continue processing the email, but treat it with suspicion
	case spf.TempError:
		log.Printf("SPF Result: TEMPERROR - Temporary SPF error occurred for domain %s, retry might succeed", getDomainFromEmail(s.from))
		// Continue processing the email (or decide to retry later)
	case spf.PermError:
		log.Printf("SPF Result: PERMERROR - Permanent SPF error for domain %s, SPF record is invalid", getDomainFromEmail(s.from))
		// Continue processing or decide to reject based on policy
	}

	parsedContent := fmt.Sprintf(
		"Received email:\n\n"+
			"From: %s\n"+
			"To: %s\n"+
			"SpfStatus: %s\n"+
			"Subject: %s\n"+
			"Date: %s\n"+
			"Content-Type: %s\n\n"+
			"Body:\n%s\n\n"+
			"Attachments:\n%s",
		s.from,
		strings.Join(s.to, ", "),
		s.spfResult.String(),
		env.GetHeader("Subject"),
		env.GetHeader("Date"),
		env.GetHeader("Content-Type"),
		env.Text, // 过滤敏感信息
		strings.Join(attachments, "\n"),
	)
	parsedTitle := env.GetHeader("Subject")

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
					if CONFIG.Telegram.SendEML {
						go sendRawEMLToTelegram(data, env.GetHeader("Subject"))
					} else {
						log.Println("不发送EML原文")
					}
				} else {
					log.Println("没配置TG转发")
				}
				if CONFIG.Webhook.Enabled {
					go sendWebhook(CONFIG.Webhook, parsedTitle, parsedContent)
				} else {
					log.Println("Webhook is disabled.")
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
					go forwardEmailToTargetAddress(data, formattedSender, targetAddress, s)
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

func forwardEmailToTargetAddress(emailData []byte, formattedSender string, targetAddress string, s *Session) {
	log.Printf("Preparing to forward email from [%s] to [%s]", formattedSender, targetAddress)
	if formattedSender == "" || targetAddress == "" {
		log.Println("Address error: either sender or recipient address is empty")
		return
	}
	privateDomain := strings.SplitN(targetAddress, "@", 2)[1]
	smtpServer, err := getSMTPServer(privateDomain)
	if err != nil {
		log.Printf("Error retrieving SMTP server for domain [%s]: %v", privateDomain, err)
		return
	}

	// Attempt to connect to SMTP server using plain connection on port 25
	conn, err := tryDialSMTPPlain(smtpServer, 25)
	if err != nil {
		log.Printf("Failed to establish connection on port 25: %v", err)
		return
	}
	defer conn.Close()

	// Attempt to initiate STARTTLS for secure email transmission
	tlsConfig := &tls.Config{
		ServerName: smtpServer,
	}
	client, err := smtp.NewClientStartTLSWithLocalName(conn, tlsConfig, getDomainFromEmail(formattedSender))
	if err != nil {
		log.Printf("Failed to establish STARTTLS: %v", err)
		// Downgrade to plain SMTP (non-TLS) because STARTTLS negotiation failed
		log.Println("Downgrading to plain SMTP due to failed STARTTLS handshake.")
		conn.Close()
		conn, err = tryDialSMTPPlain(smtpServer, 25)
		if err != nil {
			log.Printf("Failed to reconnect on port 25 for plain SMTP: %v", err)
			return
		}
		defer conn.Close()
		client = smtp.NewClient(conn) // Re-create the SMTP client without encryption
	} else {
		log.Printf("STARTTLS connection established successfully with [%s]", smtpServer)
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
			log.Printf("TLS certificate validation failed: %v", err)
			log.Println("Falling back to plain SMTP as certificate verification failed.")
			conn.Close()
			conn, err = tryDialSMTPPlain(smtpServer, 25)
			if err != nil {
				log.Printf("Failed to reconnect on port 25 for plain SMTP after TLS failure: %v", err)
				return
			}
			defer conn.Close()
			client = smtp.NewClient(conn) // Restart the client after failing TLS
			// Retry sending MAIL FROM after TLS failure
			if err := client.Mail(formattedSender, &smtp.MailOptions{}); err != nil {
				log.Printf("Error setting MAIL FROM on plain SMTP: %v", err)
				return
			}
		} else {
			log.Printf("Error setting MAIL FROM: %v", err)
			return
		}
	}

	// Set the RCPT TO command with the recipient address
	if err := client.Rcpt(targetAddress, &smtp.RcptOptions{}); err != nil {
		log.Printf("Error setting RCPT TO: %v", err)
		return
	}

	// Prepare to send the email content
	w, err := client.Data()
	if err != nil {
		log.Printf("Error initiating email data transfer: %v", err)
		return
	}

	// Modify email headers depending on the recipient
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
		log.Printf("Error writing email data: %v", err)
	}

	// Close the data writer, finalizing the email transmission
	err = w.Close()
	if err != nil {
		log.Printf("Error finalizing email data transfer: %v", err)
	}

	log.Printf("Email successfully forwarded to [%s]", targetAddress)
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
	if resp.StatusCode != 200 {
		log.Println(resp.Body)
	}
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
