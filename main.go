package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"mime"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/jhillyerd/enmime"
	"github.com/mileusna/spf"
	"github.com/sirupsen/logrus" // 引入logrus包
	"github.com/yumusb/go-smtp"
)

func main() {
	// 设置logrus为JSON格式
	logrus.SetFormatter(&logrus.JSONFormatter{})
	logrus.SetOutput(os.Stdout)
	logrus.SetLevel(logrus.InfoLevel)

	// 加载配置
	err := LoadConfig("config.yml")
	if err != nil {
		logrus.Fatalf("Error loading config: %v", err)
	}
	logrus.Infof("Telegram Chat ID: %s", CONFIG.Telegram.ChatID)
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
		logrus.Warnf("Loading TLS certificate failed: %v", err)
		logrus.Infof("Starting plainServer only at %s", CONFIG.SMTP.ListenAddress)

		// Start only the plain SMTP server with STARTTLS in a new goroutine
		if err := plainServer.ListenAndServe(); err != nil {
			logrus.Fatal(err)
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
			logrus.Infof("Starting plainServer at %s", CONFIG.SMTP.ListenAddress)
			if err := plainServer.ListenAndServe(); err != nil {
				logrus.Fatal(err)
			}
		}()

		// Start the SMTPS server (TLS only)
		logrus.Infof("Starting tlsServer at %s", CONFIG.SMTP.ListenAddressTls)
		if err := tlsServer.ListenAndServeTLS(); err != nil {
			logrus.Fatal(err)
		}
	}
}
func SPFCheck(s *Session) *smtp.SMTPError {
	remoteHost, _, err := net.SplitHostPort(s.remoteIP)
	if err != nil {
		logrus.Warn("parse remote addr failed")
		return &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 1, 0}, Message: "Invalid remote address"}
	}
	remoteIP := net.ParseIP(remoteHost)
	s.spfResult = spf.CheckHost(remoteIP, getDomainFromEmail(s.from), s.from, s.clientHostname)
	logrus.Infof("SPF Result: %v - Domain: %s, Remote IP: %s, Sender: %s - UUID: %s", s.spfResult, getDomainFromEmail(s.from), remoteHost, s.from, s.UUID)
	switch s.spfResult {
	case spf.None:
		logrus.Warnf("SPF Result: NONE - No SPF record found for domain %s. Rejecting email.", getDomainFromEmail(s.from))
		return &smtp.SMTPError{Code: 450, EnhancedCode: smtp.EnhancedCode{5, 0, 0}, Message: "SPF check softfail (no SPF record)"}
	case spf.Neutral:
		logrus.Infof("SPF Result: NEUTRAL - Domain %s neither permits nor denies sending mail from IP %s", getDomainFromEmail(s.from), s.remoteIP)
	case spf.Pass:
		logrus.Infof("SPF Result: PASS - SPF check passed for domain %s, email is legitimate", getDomainFromEmail(s.from))
	case spf.Fail:
		logrus.Warnf("SPF Result: FAIL - SPF check failed for domain %s, mail from IP %s is unauthorized", getDomainFromEmail(s.from), s.remoteIP)
		return &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 7, 0}, Message: "SPF check failed"}
	case spf.Softfail:
		logrus.Warnf("SPF Result: SOFTFAIL - SPF check soft failed for domain %s, email is suspicious", getDomainFromEmail(s.from))
		return &smtp.SMTPError{Code: 450, EnhancedCode: smtp.EnhancedCode{5, 0, 1}, Message: "SPF check softfail"}
	case spf.TempError:
		logrus.Warnf("SPF Result: TEMPERROR - Temporary SPF error occurred for domain %s, retry might succeed", getDomainFromEmail(s.from))
		return &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 0, 0}, Message: "Temporary SPF check error"}
	case spf.PermError:
		logrus.Warnf("SPF Result: PERMERROR - Permanent SPF error for domain %s, SPF record is invalid", getDomainFromEmail(s.from))
		return &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 1, 2}, Message: "SPF check permanent error"}
	}
	return nil // SPF 检查通过，返回 nil
}

func (s *Session) Data(r io.Reader) error {
	buf := new(bytes.Buffer)
	_, err := buf.ReadFrom(r)
	if err != nil {
		return fmt.Errorf("error reading data: %v", err)
	}

	if !shouldForwardEmail(s.to) {
		logrus.Warnf("Not handled by this mail server, %s - UUID: %s", s.to, s.UUID)
		return &smtp.SMTPError{
			Code:         554,
			EnhancedCode: smtp.EnhancedCode{5, 7, 1},
			Message:      "Domain not handled by this mail server",
		}
	}

	spfCheckErr := SPFCheck(s)
	if spfCheckErr != nil {
		logrus.Errorf("SPF check failed: %v - UUID: %s", spfCheckErr, s.UUID)
		return spfCheckErr
	}
	data := buf.Bytes()
	env, err := enmime.ReadEnvelope(bytes.NewReader(data))
	if err != nil {
		logrus.Errorf("Failed to parse email: %v - UUID: %s", err, s.UUID)
		return err
	}
	logrus.Infof("Received email: From=%s To=%s Subject=%s - UUID: %s", env.GetHeader("From"), env.GetHeader("To"), env.GetHeader("Subject"), s.UUID)
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
		"📧 New Email Notification\n"+
			"=================================\n"+
			"📤 From: %s\n"+
			"📬 To: %s\n"+
			"---------------------------------\n"+
			"🔍 SPF Status: %s\n"+
			"📝 Subject: %s\n"+
			"📅 Date: %s\n"+
			"📄 Content-Type: %s\n"+
			"=================================\n\n"+
			"✉️ Email Body:\n\n%s\n\n"+
			"=================================\n"+
			"📎 Attachments:\n%s\n"+
			"=================================\n"+
			"🔑 UUID: %s",
		s.from,
		strings.Join(s.to, ", "),
		s.spfResult.String(),
		env.GetHeader("Subject"),
		env.GetHeader("Date"),
		getPrimaryContentType(env.GetHeader("Content-Type")),
		env.Text,
		strings.Join(attachments, "\n"),
		s.UUID,
	)
	parsedTitle := fmt.Sprintf("📬 New Email: %s", env.GetHeader("Subject"))
	sender := extractEmails(env.GetHeader("From"))
	recipient := getFirstMatchingEmail(s.to)
	if !strings.EqualFold(sender, CONFIG.SMTP.PrivateEmail) && !strings.Contains(recipient, "_at_") && !regexp.MustCompile(`^(\w|-)+@.+$`).MatchString(recipient) {
		// 验证收件人的规则
		logrus.Warnf("不符合规则的收件人，需要是 random@qq.com、ran-dom@qq.com，当前为 %s - UUID: %s", recipient, s.UUID)
		return &smtp.SMTPError{
			Code:         550,
			EnhancedCode: smtp.EnhancedCode{5, 1, 0},
			Message:      "Invalid recipient",
		}
	}
	var outsite2private bool
	outsite2private = false
	if CONFIG.SMTP.PrivateEmail != "" {
		formattedSender := ""
		targetAddress := ""
		if strings.EqualFold(sender, CONFIG.SMTP.PrivateEmail) && strings.Contains(recipient, "_at_") {
			// 来自私密邮箱，需要将邮件转发到目标邮箱
			originsenderEmail, selfsenderEmail := parseEmails(recipient)
			targetAddress = originsenderEmail
			formattedSender = selfsenderEmail
			outsite2private = false
			logrus.Infof("Private 2 outside, Forwarding email from %s to %s - UUID: %s", sender, formattedSender, s.UUID)
		} else if strings.EqualFold(sender, CONFIG.SMTP.PrivateEmail) && !strings.Contains(recipient, "_at_") {
			// 来自私密邮箱，但目标邮箱写的有问题
			logrus.Info("not need forward", sender, recipient)
			// 不需要转发，但是可能需要通知给用户。
			return nil
		} else {
			// 来自非私密邮箱，需要将邮件转发到私密邮箱
			domain := getDomainFromEmail(recipient)
			formattedSender = fmt.Sprintf("%s_%s@%s",
				strings.ReplaceAll(strings.ReplaceAll(sender, "@", "_at_"), ".", "_"),
				strings.Split(recipient, "@")[0],
				domain)
			targetAddress = CONFIG.SMTP.PrivateEmail
			logrus.Infof("Outside 2 private, Forwarding email from %s to %s - UUID: %s", sender, formattedSender, s.UUID)
			outsite2private = true
		}
		go forwardEmailToTargetAddress(data, formattedSender, targetAddress, s)
		if outsite2private {
			if CONFIG.Telegram.ChatID != "" {
				go sendToTelegramBot(parsedContent)
				if CONFIG.Telegram.SendEML {
					go sendRawEMLToTelegram(data, env.GetHeader("Subject"))
				} else {
					logrus.Info("Telegram EML is disabled.")
				}
			} else {
				logrus.Info("Telegram is disabled.")
			}
			if CONFIG.Webhook.Enabled {
				go sendWebhook(CONFIG.Webhook, parsedTitle, parsedContent)
			} else {
				logrus.Info("Webhook is disabled.")
			}
		}
	} else {
		logrus.Info("Email forwarder is disabled.")
	}
	return nil
}
