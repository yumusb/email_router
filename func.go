package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/mail"
	"os"
	"regexp"
	"strings"

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
