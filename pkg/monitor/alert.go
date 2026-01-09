package monitor

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"autopath/pkg/invariants"
)

// AlertManager 告警管理器
type AlertManager struct {
	webhookURL      string
	emailRecipients []string
	alertHistory    []AlertRecord
	alertThrottle   map[string]time.Time // 用于限流
}

// AlertRecord 告警记录
type AlertRecord struct {
	Timestamp   time.Time
	Violation   invariants.ViolationResult
	AlertMethod string // webhook, email, etc.
	Success     bool
}

// NewAlertManager 创建告警管理器
func NewAlertManager() *AlertManager {
	return &AlertManager{
		alertHistory:  make([]AlertRecord, 0),
		alertThrottle: make(map[string]time.Time),
	}
}

// Configure 配置告警管理器
func (a *AlertManager) Configure(webhookURL string, emailRecipients []string) {
	a.webhookURL = webhookURL
	a.emailRecipients = emailRecipients
}

// SendAlert 发送告警
func (a *AlertManager) SendAlert(violation invariants.ViolationResult) {
	// 检查是否需要限流
	throttleKey := fmt.Sprintf("%s:%s", violation.ProjectID, violation.InvariantID)
	if lastAlert, exists := a.alertThrottle[throttleKey]; exists {
		if time.Since(lastAlert) < 5*time.Minute {
			log.Printf("Alert throttled for %s", throttleKey)
			return
		}
	}

	// 更新限流时间
	a.alertThrottle[throttleKey] = time.Now()

	// 发送Webhook告警
	if a.webhookURL != "" {
		go a.sendWebhookAlert(violation)
	}

	// 发送邮件告警（如果配置了）
	if len(a.emailRecipients) > 0 {
		go a.sendEmailAlert(violation)
	}

	// 记录告警历史
	a.recordAlert(violation, "multiple", true)
}

// sendWebhookAlert 发送Webhook告警
func (a *AlertManager) sendWebhookAlert(violation invariants.ViolationResult) {
	payload := WebhookPayload{
		Type:      "INVARIANT_VIOLATION",
		Severity:  "CRITICAL",
		Timestamp: time.Now().Unix(),
		Project:   violation.ProjectID,
		Invariant: violation.InvariantName,
		Block:     violation.BlockNumber,
		Transaction: violation.Transaction.Hex(),
		Details:   violation.Details,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		log.Printf("Failed to marshal webhook payload: %v", err)
		return
	}

	resp, err := http.Post(a.webhookURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("Failed to send webhook alert: %v", err)
		a.recordAlert(violation, "webhook", false)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Webhook returned non-OK status: %d", resp.StatusCode)
		a.recordAlert(violation, "webhook", false)
		return
	}

	log.Printf("Webhook alert sent successfully for violation in %s", violation.ProjectID)
}

// sendEmailAlert 发送邮件告警
func (a *AlertManager) sendEmailAlert(violation invariants.ViolationResult) {
	// 简化实现：实际需要配置SMTP服务器
	log.Printf("Email alert would be sent to %v for violation in %s",
		a.emailRecipients, violation.ProjectID)
}

// recordAlert 记录告警
func (a *AlertManager) recordAlert(violation invariants.ViolationResult, method string, success bool) {
	record := AlertRecord{
		Timestamp:   time.Now(),
		Violation:   violation,
		AlertMethod: method,
		Success:     success,
	}

	a.alertHistory = append(a.alertHistory, record)

	// 保持历史记录在合理范围内
	if len(a.alertHistory) > 10000 {
		a.alertHistory = a.alertHistory[5000:]
	}
}

// GetAlertHistory 获取告警历史
func (a *AlertManager) GetAlertHistory(limit int) []AlertRecord {
	if limit <= 0 || limit > len(a.alertHistory) {
		return a.alertHistory
	}

	// 返回最近的记录
	start := len(a.alertHistory) - limit
	if start < 0 {
		start = 0
	}

	return a.alertHistory[start:]
}

// WebhookPayload Webhook负载
type WebhookPayload struct {
	Type        string                    `json:"type"`
	Severity    string                    `json:"severity"`
	Timestamp   int64                     `json:"timestamp"`
	Project     string                    `json:"project"`
	Invariant   string                    `json:"invariant"`
	Block       uint64                    `json:"block"`
	Transaction string                    `json:"transaction"`
	Details     *invariants.ViolationDetail `json:"details,omitempty"`
}

// AlertStatistics 告警统计
type AlertStatistics struct {
	TotalAlerts      int
	SuccessfulAlerts int
	FailedAlerts     int
	AlertsByProject  map[string]int
	AlertsByInvariant map[string]int
	LastAlertTime    time.Time
}

// GetStatistics 获取告警统计
func (a *AlertManager) GetStatistics() *AlertStatistics {
	stats := &AlertStatistics{
		AlertsByProject:   make(map[string]int),
		AlertsByInvariant: make(map[string]int),
	}

	for _, record := range a.alertHistory {
		stats.TotalAlerts++

		if record.Success {
			stats.SuccessfulAlerts++
		} else {
			stats.FailedAlerts++
		}

		stats.AlertsByProject[record.Violation.ProjectID]++
		stats.AlertsByInvariant[record.Violation.InvariantID]++

		if record.Timestamp.After(stats.LastAlertTime) {
			stats.LastAlertTime = record.Timestamp
		}
	}

	return stats
}