package main

import "blitiri.com.ar/go/spf"

var headersToRemove = []string{"x-*", "x-spam-*", "x-mailer", "x-originating-*", "x-qq-*", "dkim-*", "x-google-*", "x-cm-*", "x-coremail-*", "x-bq-*"}
var CONFIG Config

const headerPrefix = "X-ROUTER-"
const telegramMaxLength = 4096

type Config struct {
	SMTP     SMTPConfig     `yaml:"smtp"`
	Telegram TelegramConfig `yaml:"telegram"`
	Webhook  WebhookConfig  `yaml:"webhook"` // 新增 Webhook 配置
}

type SMTPConfig struct {
	ListenAddress    string   `yaml:"listen_address"`
	ListenAddressTls string   `yaml:"listen_address_tls"`
	AllowedDomains   []string `yaml:"allowed_domains"`
	PrivateEmail     string   `yaml:"private_email"`
	CertFile         string   `yaml:"cert_file"`
	KeyFile          string   `yaml:"key_file"`
}

type TelegramConfig struct {
	BotToken string `yaml:"bot_token"`
	ChatID   string `yaml:"chat_id"`
	SendEML  bool   `yaml:"send_eml"`
}

type WebhookConfig struct {
	Enabled  bool              `yaml:"enabled"`  // 是否启用 Webhook
	Method   string            `yaml:"method"`   // HTTP 请求方法
	URL      string            `yaml:"url"`      // Webhook URL
	Headers  map[string]string `yaml:"headers"`  // 自定义 Headers
	Body     map[string]string `yaml:"body"`     // 请求体数据（支持模板变量）
	BodyType string            `yaml:"bodyType"` // 请求体类型，可以是 "json" 或 "form"
}

type Backend struct {
}
type Session struct {
	from                 string
	to                   []string
	remoteIP             string
	localIP              string
	spfResult            spf.Result
	remoteclientHostname string
	UUID                 string
}
