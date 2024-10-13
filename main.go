package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
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

func (s *Session) Data(r io.Reader) error {
	buf := new(bytes.Buffer)
	_, err := buf.ReadFrom(r)
	if err != nil {
		return fmt.Errorf("error reading data: %v", err)
	}
	data := buf.Bytes()
	env, err := enmime.ReadEnvelope(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("error parsing email: %v", err)
	}
	logrus.Infof("Received email: From=%s To=%s RemoteIP=%s LocalIP=%s clientHostname=%s", s.from, s.to, s.remoteIP, s.localIP, s.clientHostname)
	remote_host, _, err := net.SplitHostPort(s.remoteIP)
	if err != nil {
		logrus.Warn("parse remote addr failed")
	}
	remote_ip := net.ParseIP(remote_host)
	for _, recipient := range s.to {
		recipient = extractEmails(recipient)
		sender := extractEmails(env.GetHeader("From"))
		for _, domain := range CONFIG.SMTP.AllowedDomains {
			if checkDomain(recipient, domain) {
				logrus.Info("收件人是允许的收件域，需要进一步处理")
				s.spfResult = spf.CheckHost(remote_ip, getDomainFromEmail(s.from), s.from, s.clientHostname)
				if err != nil {
					logrus.Errorf("Failed to parse email: %v", err)
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
					logrus.Warnf("SPF Result: NONE - No SPF record found for domain %s. Rejecting email.", getDomainFromEmail(s.from))
					return fmt.Errorf("SPF validation failed: no SPF record found")
				case spf.Neutral:
					logrus.Infof("SPF Result: NEUTRAL - Domain %s neither permits nor denies sending mail from IP %s", getDomainFromEmail(s.from), s.remoteIP)
				case spf.Pass:
					logrus.Infof("SPF Result: PASS - SPF check passed for domain %s, email is legitimate", getDomainFromEmail(s.from))
				case spf.Fail:
					logrus.Warnf("SPF Result: FAIL - SPF check failed for domain %s, mail from IP %s is unauthorized", getDomainFromEmail(s.from), s.remoteIP)
					return fmt.Errorf("SPF validation failed: unauthorized sender")
				case spf.Softfail:
					logrus.Warnf("SPF Result: SOFTFAIL - SPF check soft failed for domain %s, email is suspicious", getDomainFromEmail(s.from))
				case spf.TempError:
					logrus.Warnf("SPF Result: TEMPERROR - Temporary SPF error occurred for domain %s, retry might succeed", getDomainFromEmail(s.from))
				case spf.PermError:
					logrus.Warnf("SPF Result: PERMERROR - Permanent SPF error for domain %s, SPF record is invalid", getDomainFromEmail(s.from))
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
						"=================================",
					s.from,
					strings.Join(s.to, ", "),
					s.spfResult.String(),
					env.GetHeader("Subject"),
					env.GetHeader("Date"),
					getPrimaryContentType(env.GetHeader("Content-Type")),
					env.Text,
					strings.Join(attachments, "\n"),
				)
				parsedTitle := fmt.Sprintf("📬 New Email: %s", env.GetHeader("Subject"))
				if !strings.EqualFold(sender, CONFIG.SMTP.PrivateEmail) && !strings.Contains(recipient, "_at_") && !regexp.MustCompile(`^(\w|-)+@.+$`).MatchString(recipient) {
					logrus.Warn("不符合规则的收件人，需要是random@qq.com、ran-dom@qq.com，当前为", recipient)
					break
				}
				if CONFIG.Telegram.ChatID != "" {
					go sendToTelegramBot(parsedContent)
					if CONFIG.Telegram.SendEML {
						go sendRawEMLToTelegram(data, env.GetHeader("Subject"))
					} else {
						logrus.Info("不发送EML原文")
					}
				} else {
					logrus.Info("没配置TG转发")
				}
				if CONFIG.Webhook.Enabled {
					go sendWebhook(CONFIG.Webhook, parsedTitle, parsedContent)
				} else {
					logrus.Info("Webhook is disabled.")
				}
				if CONFIG.SMTP.PrivateEmail != "" {
					formattedSender := ""
					targetAddress := ""
					if strings.EqualFold(sender, CONFIG.SMTP.PrivateEmail) && strings.Contains(recipient, "_at_") {
						originsenderEmail, selfsenderEmail := parseEmails(recipient)
						targetAddress = originsenderEmail
						formattedSender = selfsenderEmail
					} else if strings.EqualFold(sender, CONFIG.SMTP.PrivateEmail) && !strings.Contains(recipient, "_at_") {
						logrus.Info("not need forward", sender, recipient)
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
					logrus.Info("没配置邮件转发")
				}
				break
			} else {
				logrus.Info("收件人不是允许的收件域，不需要处理", recipient)

			}

		}
	}
	return fmt.Errorf("521 Recipient address rejected")
}
