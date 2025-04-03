package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
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

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/toorop/go-dkim" // 添加 DKIM 库
	"github.com/yumusb/go-smtp"
	"gopkg.in/yaml.v2"
)

func NewUUID() string {
	uuidV4 := uuid.New()
	return uuidV4.String()
}
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
func removeEmailHeaders(emailData []byte, headersToRemove []string) ([]byte, error) {
	msg, err := mail.ReadMessage(bytes.NewReader(emailData))
	if err != nil {
		return nil, err
	}

	// 读取原始邮件头
	headers := make(map[string]string)
	for k, v := range msg.Header {
		headers[strings.ToLower(k)] = strings.Join(v, ", ") // 统一存储为小写
	}

	// 创建正则表达式模式
	patterns := make([]*regexp.Regexp, len(headersToRemove))
	for i, header := range headersToRemove {
		regexPattern := "^" + regexp.QuoteMeta(strings.ToLower(header)) + "$"
		regexPattern = strings.ReplaceAll(regexPattern, "\\*.", ".*") // 处理 *. 形式
		regexPattern = strings.ReplaceAll(regexPattern, "\\*", ".*")  // 处理 * 形式
		patterns[i] = regexp.MustCompile(regexPattern)
	}

	// 移除匹配的 headers
	for k := range headers {
		for _, pattern := range patterns {
			if pattern.MatchString(k) {
				delete(headers, k)
				break
			}
		}
	}

	// 读取邮件正文
	body, err := io.ReadAll(msg.Body)
	if err != nil {
		return nil, err
	}

	// 重新构造邮件内容
	var buf bytes.Buffer
	for k, v := range headers {
		fmt.Fprintf(&buf, "%s: %s\r\n", k, v)
	}
	buf.WriteString("\r\n") // 头部结束

	buf.Write(body) // 追加原始正文

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
		newheader := ""
		if strings.Contains(header, "Original") {
			newheader = strings.ToUpper(headerPrefix + header)
		} else {
			newheader = header
		}
		if existingValue, exists := headers[newheader]; exists {
			// If the header already exists, append the new value
			headers[newheader] = existingValue + ", " + value
		} else {
			headers[newheader] = value
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
	remoteclientHostname := c.Hostname()
	id := NewUUID()
	logrus.Infof("New connection from %s (%s) to %s - UUID: %s", remoteIP, remoteclientHostname, localIP, id)
	session := &Session{
		remoteIP:             remoteIP,
		localIP:              localIP,
		remoteclientHostname: remoteclientHostname,
		UUID:                 id,
	}
	return session, nil
}

func (s *Session) Mail(from string, opts *smtp.MailOptions) error {
	if !isValidEmail(from) {
		return errors.New("invalid email address format")
	}
	s.from = from
	spfCheckErr := SPFCheck(s)
	if spfCheckErr != nil {
		logrus.Errorf("SPF check failed: %v - UUID: %s", spfCheckErr, s.UUID)
		return spfCheckErr
	}
	return nil
}
func (s *Session) Rcpt(to string, opts *smtp.RcptOptions) error {
	if !isValidEmail(to) {
		return errors.New("invalid email address format")
	}
	s.to = append(s.to, to)
	if !shouldForwardEmail(s.to) {
		logrus.Warnf("Not handled by this mail server, %s - UUID: %s", s.to, s.UUID)
		return &smtp.SMTPError{
			Code:         554,
			EnhancedCode: smtp.EnhancedCode{5, 7, 1},
			Message:      "Domain not handled by this mail server",
		}
	}
	return nil
}
func splitMessage(message string, maxLength int) []string {
	var messages []string
	runes := []rune(message) // 支持多字节字符
	for len(runes) > maxLength {
		// 尝试在最后一个空格处分割，避免将单词或句子截断
		splitIndex := maxLength
		for splitIndex > 0 && runes[splitIndex] != ' ' {
			splitIndex--
		}
		if splitIndex == 0 {
			splitIndex = maxLength // 如果找不到空格，就强制在 maxLength 处截断
		}
		messages = append(messages, string(runes[:splitIndex]))
		runes = runes[splitIndex:]
	}
	messages = append(messages, string(runes)) // 追加最后的剩余部分
	return messages
}

func sendToTelegramBot(message string, traceid string) {
	botToken := CONFIG.Telegram.BotToken
	chatID := CONFIG.Telegram.ChatID
	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", botToken)

	// 分割消息
	messages := splitMessage(message, telegramMaxLength)

	// 依次发送每个分割后的消息
	for _, msgPart := range messages {
		payload := map[string]interface{}{
			"chat_id": chatID,
			"text":    msgPart,
		}
		jsonPayload, err := json.Marshal(payload)
		if err != nil {
			logrus.Errorf("Failed to marshal JSON payload - TraceID: %s, Error: %v", traceid, err)
			return
		}

		resp, err := http.Post(apiURL, "application/json", bytes.NewBuffer(jsonPayload))
		if err != nil {
			logrus.Errorf("Failed to send message to Telegram bot - TraceID: %s, Error: %v", traceid, err)
			return
		}
		defer resp.Body.Close()

		logrus.Infof("Message sent to Telegram bot - TraceID: %s, Response: %s", traceid, resp.Status)
		if resp.StatusCode != 200 {
			logrus.Warnf("Non-200 response from Telegram bot - TraceID: %s", traceid)
		}
	}
}

func sendRawEMLToTelegram(emailData []byte, subject string, traceid string) {
	botToken := CONFIG.Telegram.BotToken
	chatID := CONFIG.Telegram.ChatID
	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendDocument", botToken)
	tmpFile, err := os.CreateTemp("", "email-*.eml")
	if err != nil {
		logrus.Errorf("Failed to create temporary file - TraceID: %s, Error: %v", traceid, err)
		return
	}
	defer func() {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
	}()

	_, err = tmpFile.Write(emailData)
	if err != nil {
		logrus.Errorf("Failed to write email data to file - TraceID: %s, Error: %v", traceid, err)
		return
	}

	// 使用安全的文件权限
	err = os.Chmod(tmpFile.Name(), 0600)
	if err != nil {
		logrus.Errorf("Failed to set file permissions - TraceID: %s, Error: %v", traceid, err)
		return
	}

	tmpFile.Seek(0, 0)
	file, err := os.Open(tmpFile.Name())
	if err != nil {
		logrus.Errorf("Failed to open temporary file - TraceID: %s, Error: %v", traceid, err)
		return
	}
	defer file.Close()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("document", tmpFile.Name())
	if err != nil {
		logrus.Errorf("Failed to create form file - TraceID: %s, Error: %v", traceid, err)
		return
	}
	_, err = io.Copy(part, file)
	if err != nil {
		logrus.Errorf("Failed to copy file data - TraceID: %s, Error: %v", traceid, err)
		return
	}

	_ = writer.WriteField("chat_id", chatID)
	_ = writer.WriteField("caption", subject)
	err = writer.Close()
	if err != nil {
		logrus.Errorf("Failed to close writer - TraceID: %s, Error: %v", traceid, err)
		return
	}

	req, err := http.NewRequest("POST", apiURL, body)
	if err != nil {
		logrus.Errorf("Failed to create HTTP request - TraceID: %s, Error: %v", traceid, err)
		return
	}
	req.Header.Add("Content-Type", writer.FormDataContentType())
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		logrus.Errorf("Failed to send email as EML to Telegram - TraceID: %s, Error: %v", traceid, err)
		return
	}
	defer resp.Body.Close()
	logrus.Infof("Raw EML sent to Telegram bot - TraceID: %s, Response: %s", traceid, resp.Status)
}
func checkDMARCRecord(domain string) (bool, error) {
	dmarcDomain := "_dmarc." + domain
	txtRecords, err := net.LookupTXT(dmarcDomain)
	if err != nil {
		// 如果查询出错，可能是没有DMARC记录或DNS查询失败
		if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
			return false, nil // 域名存在但没有DMARC记录
		}
		return false, err // 其他DNS错误
	}
	// 检查是否有DMARC记录
	for _, record := range txtRecords {
		if strings.HasPrefix(strings.ToLower(record), "v=dmarc1") {
			return true, nil // 找到DMARC记录
		}
	}
	return false, nil // 没有找到DMARC记录
}
func forwardEmailToTargetAddress(emailData []byte, formattedSender string, targetAddress string, s *Session) {
	logrus.Infof("Preparing to forward email from [%s] to [%s] - UUID: %s", formattedSender, targetAddress, s.UUID)
	if formattedSender == "" || targetAddress == "" {
		logrus.Warnf("Address error: either sender or recipient address is empty - UUID: %s", s.UUID)
		return
	}
	targetDomain := strings.SplitN(targetAddress, "@", 2)[1]
	senderDomain := strings.SplitN(formattedSender, "@", 2)[1]

	// 检查是否需要应用DMARC签名
	useDMARC := false
	if CONFIG.SMTP.EnableDMARC {
		// 应该检查发件人域名的DMARC记录，而不是接收方域名
		hasDMARC, err := checkDMARCRecord(senderDomain)
		if err != nil {
			logrus.Warnf("无法检查发件人域名 [%s] 的DMARC记录: %v - UUID: %s", senderDomain, err, s.UUID)
		} else if hasDMARC {
			logrus.Infof("发件人域名 [%s] 存在DMARC记录，将应用DMARC签名 - UUID: %s", senderDomain, s.UUID)
			useDMARC = true
		} else {
			logrus.Infof("发件人域名 [%s] 没有DMARC记录 - UUID: %s", senderDomain, s.UUID)
		}
	} else {
		logrus.Debugf("DMARC签名在配置中已禁用 - UUID: %s", s.UUID)
	}

	smtpServer, err := getSMTPServer(targetDomain)
	if err != nil {
		logrus.Errorf("Error retrieving SMTP server for domain [%s]: %v - UUID: %s", targetDomain, err, s.UUID)
		return
	}

	// Attempt to connect to SMTP server using plain connection on port 25
	conn, err := tryDialSMTPPlain(smtpServer, 25)
	if err != nil {
		logrus.Errorf("Failed to establish connection on port 25: %v - UUID: %s", err, s.UUID)
		return
	}
	defer conn.Close()

	// Attempt to initiate STARTTLS for secure email transmission
	tlsConfig := &tls.Config{
		ServerName: smtpServer,
	}
	client, err := smtp.NewClientStartTLSWithLocalName(conn, tlsConfig, getDomainFromEmail(formattedSender))
	if err != nil {
		logrus.Errorf("Failed to establish STARTTLS: %v - UUID: %s", err, s.UUID)
		logrus.Warnf("Downgrading to plain SMTP due to failed STARTTLS handshake - UUID: %s", s.UUID)
		conn.Close()
		conn, err = tryDialSMTPPlain(smtpServer, 25)
		if err != nil {
			logrus.Errorf("Failed to reconnect on port 25 for plain SMTP: %v - UUID: %s", err, s.UUID)
			return
		}
		defer conn.Close()
		client = smtp.NewClientWithLocalName(conn, getDomainFromEmail(formattedSender)) // Re-create the SMTP client without encryption
	} else {
		logrus.Infof("STARTTLS connection established successfully with [%s] - UUID: %s", smtpServer, s.UUID)
	}

	// Ensure the client connection is properly closed
	defer func() {
		if client != nil {
			client.Quit() // Attempt to gracefully close the connection with QUIT
			client.Close()
		}
	}()

	// Set the MAIL FROM command with the sender address
	err = client.Mail(formattedSender, &smtp.MailOptions{})
	if err != nil {
		if isCertInvalidError(err) {
			logrus.Errorf("TLS certificate validation failed: %v - UUID: %s", err, s.UUID)
			logrus.Warnf("Falling back to plain SMTP as certificate verification failed - UUID: %s", s.UUID)
			conn.Close()
			conn, err = tryDialSMTPPlain(smtpServer, 25)
			if err != nil {
				logrus.Errorf("Failed to reconnect on port 25 for plain SMTP after TLS failure: %v - UUID: %s", err, s.UUID)
				return
			}
			defer conn.Close()
			client = smtp.NewClientWithLocalName(conn, getDomainFromEmail(formattedSender))
			if mailErr := client.Mail(formattedSender, &smtp.MailOptions{}); mailErr != nil {
				logrus.Errorf("Error setting MAIL FROM on plain SMTP: %v - UUID: %s", mailErr, s.UUID)
				return
			}
		} else {
			logrus.Errorf("Error setting MAIL FROM: %v - UUID: %s", err, s.UUID)
			if smtpErr, ok := err.(*smtp.SMTPError); ok && smtpErr.Code >= 500 {
				logrus.Errorf("MAIL FROM rejected by server with code %d: %v - UUID: %s", smtpErr.Code, smtpErr, s.UUID)
				return
			}
			logrus.Errorf("Error setting MAIL FROM: %v - UUID: %s", err, s.UUID)
			return
		}
	}

	// Set the RCPT TO command with the recipient address
	err = client.Rcpt(targetAddress, &smtp.RcptOptions{})
	if err != nil {
		if smtpErr, ok := err.(*smtp.SMTPError); ok && smtpErr.Code >= 500 {
			logrus.Errorf("RCPT TO rejected by server with code %d: %v - UUID: %s", smtpErr.Code, smtpErr, s.UUID)
			return
		}
		logrus.Errorf("Error setting RCPT TO: %v - UUID: %s", err, s.UUID)
		return
	}

	// Start the DATA command
	w, err := client.Data()
	if err != nil {
		logrus.Errorf("Error initiating email data transfer: %v - UUID: %s", err, s.UUID)
		return
	}

	// Modify email data
	var modifiedEmailData []byte
	//modifiedEmailData, _ = []byte(removeEmailHeaders()[])
	modifiedEmailData, _ = removeEmailHeaders(emailData, []string{"DKIM-*", "Authentication-*"})
	if strings.EqualFold(targetAddress, CONFIG.SMTP.PrivateEmail) {
		modifiedEmailData, _ = modifyEmailHeaders(modifiedEmailData, formattedSender, "")
		headersToAdd := map[string]string{
			"Original-From":       s.from,
			"Original-To":         strings.Join(s.to, ","),
			"Original-Server":     s.remoteIP,
			"Original-Spf-Result": string(s.spfResult),
			"Original-Message-Id": s.msgId,
			"Message-Id":          fmt.Sprintf("<%s@%s>", s.UUID, senderDomain),
			"UUID":                s.UUID,
		}
		modifiedEmailData, _ = addEmailHeaders(modifiedEmailData, headersToAdd)
	} else {
		modifiedEmailData, _ = modifyEmailHeaders(modifiedEmailData, formattedSender, targetAddress)
		modifiedEmailData, _ = removeEmailHeaders(modifiedEmailData, headersToRemove)
		headersToAdd := map[string]string{
			"Message-Id": fmt.Sprintf("<%s@%s>", s.UUID, senderDomain),
		}
		modifiedEmailData, _ = addEmailHeaders(modifiedEmailData, headersToAdd)
	}
	if useDMARC {
		var dkimErr error
		modifiedEmailData, dkimErr = applyDMARCSignature(modifiedEmailData, formattedSender, senderDomain, s.UUID)
		if dkimErr != nil {
			logrus.Errorf("Failed to apply DMARC signature: %v - UUID: %s", dkimErr, s.UUID)
			// 继续发送邮件，但不使用DMARC签名
		} else {
			logrus.Infof("DMARC signature applied successfully - UUID: %s", s.UUID)
		}
	}

	// Write the modified email data to the server
	_, err = w.Write(modifiedEmailData)
	if err != nil {
		logrus.Errorf("Error writing email data: %v - UUID: %s", err, s.UUID)
		return
	}

	// Close the data writer
	err = w.Close()
	if err != nil {
		logrus.Errorf("Error finalizing email data transfer: %v - UUID: %s", err, s.UUID)
		return
	}

	// Quit the SMTP session
	err = client.Quit()
	if err != nil {
		logrus.Errorf("Error sending QUIT command: %v - UUID: %s", err, s.UUID)
	}
	logrus.Infof("Email successfully forwarded to [%s] - UUID: %s", targetAddress, s.UUID)
}

func tryDialSMTPPlain(smtpServer string, port int) (net.Conn, error) {
	dialer := net.Dialer{
		Timeout:   5 * time.Second,  // Connection timeout
		KeepAlive: 30 * time.Second, // Keep alive interval
	}
	address := net.JoinHostPort(smtpServer, fmt.Sprintf("%d", port))
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
func sendWebhook(config WebhookConfig, title, content string, traceid string) (*http.Response, error) {
	if !config.Enabled {
		return nil, fmt.Errorf("webhook is disabled - TraceID: %s", traceid)
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
			logrus.Errorf("Failed to marshal JSON body - TraceID: %s, Error: %v", traceid, err)
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
		logrus.Errorf("Failed to create HTTP request - TraceID: %s, Error: %v", traceid, err)
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
		logrus.Errorf("Failed to send webhook request - TraceID: %s, Error: %v", traceid, err)
		return nil, err
	}
	logrus.Infof("Webhook response status - TraceID: %s, Status: %s", traceid, resp.Status)
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

func applyDMARCSignature(emailData []byte, sender, domain, uuid string) ([]byte, error) {
	logrus.Infof("开始应用DMARC签名 - 发件人: [%s], 域名: [%s], UUID: %s", sender, domain, uuid)
	// 检查是否有DKIM私钥配置
	if CONFIG.SMTP.DKIMPrivateKey == "" {
		logrus.Errorf("DKIM私钥未配置，无法应用DMARC签名 - UUID: %s", uuid)
		return nil, fmt.Errorf("DKIM private key not configured")
	}
	// 检查DKIM选择器是否配置
	if CONFIG.SMTP.DKIMSelector == "" {
		logrus.Errorf("DKIM选择器未配置，无法应用DMARC签名 - UUID: %s", uuid)
		return nil, fmt.Errorf("DKIM selector not configured")
	}
	// 解析邮件
	logrus.Debugf("解析邮件内容以应用DMARC签名 - UUID: %s", uuid)
	msg, err := mail.ReadMessage(bytes.NewReader(emailData))
	if err != nil {
		logrus.Errorf("解析邮件失败: %v - UUID: %s", err, uuid)
		return nil, fmt.Errorf("failed to parse email: %v", err)
	}
	// 读取原始邮件头
	headers := make(map[string]string)
	for k, v := range msg.Header {
		headers[k] = strings.Join(v, ", ")
	}
	logrus.Debugf("成功读取邮件头，准备添加DKIM签名 - UUID: %s", uuid)
	// 准备DKIM签名所需的头部
	// 这里需要使用第三方库来实现DKIM签名
	logrus.Infof("使用域名 [%s] 和选择器 [%s] 生成DKIM签名 - UUID: %s",
		domain, CONFIG.SMTP.DKIMSelector, uuid)

	// 生成DKIM签名
	dkimSignature, err := generateDKIMSignature(emailData, CONFIG.SMTP.DKIMPrivateKey, CONFIG.SMTP.DKIMSelector, domain)
	if err != nil {
		logrus.Errorf("生成DKIM签名失败: %v - UUID: %s", err, uuid)
		return nil, fmt.Errorf("failed to generate DKIM signature: %v", err)
	}
	logrus.Debugf("DKIM签名生成成功 - UUID: %s", uuid)

	// 添加DKIM-Signature头
	headers["DKIM-Signature"] = dkimSignature
	logrus.Debugf("已添加DKIM-Signature头到邮件 - UUID: %s", uuid)

	// 重建邮件内容
	var buf bytes.Buffer
	for k, v := range headers {
		fmt.Fprintf(&buf, "%s: %s\r\n", k, v)
	}
	buf.WriteString("\r\n")

	// 附加原始邮件正文
	body, err := io.ReadAll(msg.Body)
	if err != nil {
		logrus.Errorf("读取邮件正文失败: %v - UUID: %s", err, uuid)
		return nil, err
	}
	buf.Write(body)

	logrus.Infof("DMARC签名应用完成，邮件已重建 - UUID: %s", uuid)
	return buf.Bytes(), nil
}

func generateDKIMSignature(emailData []byte, privateKey, selector, domain string) (string, error) {
	// 记录签名过程开始
	logrus.Debugf("开始为域名 [%s] 使用选择器 [%s] 生成DKIM签名", domain, selector)
	if len(privateKey) < 10 {
		logrus.Warnf("DKIM私钥长度异常短: %d 字符", len(privateKey))
		return "", fmt.Errorf("DKIM私钥长度异常短")
	}
	// 创建邮件数据的副本，因为签名过程会修改原始数据
	emailCopy := make([]byte, len(emailData))
	copy(emailCopy, emailData)
	// 创建一个新的 DKIM 签名选项
	options := dkim.NewSigOptions()
	options.PrivateKey = []byte(privateKey)
	options.Domain = domain
	options.Selector = selector
	options.SignatureExpireIn = 3600                                          // 签名有效期1小时
	options.BodyLength = 0                                                    // 不限制正文长度
	options.Headers = []string{"from", "to", "subject", "date", "message-id"} // 要签名的头部
	options.AddSignatureTimestamp = true
	options.Canonicalization = "relaxed/relaxed" // 使用宽松的规范化方法

	// 直接对邮件数据进行签名
	// 注意：Sign函数会直接修改传入的邮件数据，添加DKIM-Signature头
	err := dkim.Sign(&emailCopy, options)
	if err != nil {
		logrus.Errorf("生成DKIM签名失败: %v", err)
		return "", fmt.Errorf("failed to generate DKIM signature: %v", err)
	}
	// 从签名后的邮件中提取DKIM-Signature头
	msg, err := mail.ReadMessage(bytes.NewReader(emailCopy))
	if err != nil {
		logrus.Errorf("解析签名后的邮件失败: %v", err)
		return "", fmt.Errorf("failed to parse signed email: %v", err)
	}
	dkimSignature := msg.Header.Get("DKIM-Signature")
	if dkimSignature == "" {
		logrus.Errorf("无法从签名后的邮件中获取DKIM-Signature头")
		return "", fmt.Errorf("DKIM-Signature header not found in signed email")
	}
	// 记录签名成功
	if len(dkimSignature) > 30 {
		logrus.Debugf("DKIM签名生成成功: %s...", dkimSignature[:30])
	} else {
		logrus.Debugf("DKIM签名生成成功: %s", dkimSignature)
	}

	return dkimSignature, nil
}

// 从私钥中提取公钥信息用于DKIM DNS记录
func extractPublicKeyInfo(privateKeyPEM string) (string, error) {
	// 解码PEM块
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return "", errors.New("failed to decode PEM block containing private key")
	}
	// 解析私钥
	var privKey *rsa.PrivateKey
	var err error
	// 尝试PKCS1格式
	privKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// 尝试PKCS8格式
		key, parseErr := x509.ParsePKCS8PrivateKey(block.Bytes)
		if parseErr != nil {
			//logrus.Errorf("Failed to parse private key: %v", parseErr)
			return "", errors.New("failed to parse private key: not PKCS1 or PKCS8 format")
		}
		var ok bool
		privKey, ok = key.(*rsa.PrivateKey)
		if !ok {
			return "", errors.New("private key is not RSA type")
		}
	}
	// 序列化公钥
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return "", errors.New("failed to marshal public key")
	}
	// Base64编码
	pubKeyBase64 := base64.StdEncoding.EncodeToString(pubKeyBytes)
	return pubKeyBase64, nil
}
