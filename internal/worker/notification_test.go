package worker

import (
	"context"
	"cve-tracker/internal/models"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/pashagolub/pgxmock/v3"
	"github.com/redis/go-redis/v9"
)

func TestWorker_FloodProtection(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("failed to start miniredis: %v", err)
	}
	defer mr.Close()
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()
	
	w := &Worker{Pool: mock, Redis: rdb, HTTP: http.DefaultClient}
	ctx := context.Background()
	userID := 1
	cve := &models.CVE{ID: 1, CVEID: "CVE-2024-0001"}
	sub := models.UserSubscription{UserID: userID, AggregationMode: "hourly"}
	
	// Mock CVE details fetch
	mock.ExpectQuery("SELECT EXISTS").WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(false))
	mock.ExpectQuery("SELECT cve_id").WillReturnRows(pgxmock.NewRows([]string{"cve_id", "description", "cvss_score", "vector_string", "cisa_kev", "epss_score", "cwe_id", "github_poc_count", "published_date", "references"}).
		AddRow("CVE-2024-0001", "desc", 7.0, "V", false, 0.1, "CWE-1", 0, time.Now(), []byte("[]")))

	// 1. First alert should pass
	if !w.notifyIfNew(ctx, userID, cve, sub, "test@example.com", "") {
		t.Errorf("First alert should have passed flood protection")
	}
	
	// 2. Flood it
	floodKey := fmt.Sprintf("flood_protection:%d", userID)
	rdb.Set(ctx, floodKey, 50, 0)
	
	if w.notifyIfNew(ctx, userID, cve, sub, "test@example.com", "") {
		t.Errorf("Alert should have been blocked by flood protection (count=51)")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestWorker_AggregationLogic(t *testing.T) {
	mr, _ := miniredis.Run()
	defer mr.Close()
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	
	mock, _ := pgxmock.NewPool()
	defer mock.Close()
	
	w := &Worker{Pool: mock, Redis: rdb, HTTP: http.DefaultClient}
	ctx := context.Background()
	
	cve := &models.CVE{CVEID: "CVE-MEDIUM", CVSSScore: 5.0}
	sub := models.UserSubscription{AggregationMode: "hourly"}
	
	// Hourly should buffer
	w.bufferAlert(ctx, 1, cve, sub, "test@example.com", "Asset1")
	
	llen, _ := rdb.LLen(ctx, "alert_buffer:1").Result()
	if llen != 1 {
		t.Errorf("Expected 1 alert in buffer for hourly mode, got %d", llen)
	}
	
	// Critical should bypass buffer
	cveCritical := &models.CVE{CVEID: "CVE-CRIT", CVSSScore: 9.5}
	// We need a mock for sendAlert or just verify it doesn't land in Redis
	w.bufferAlert(ctx, 1, cveCritical, sub, "test@example.com", "Asset1")
	
	llen, _ = rdb.LLen(ctx, "alert_buffer:1").Result()
	if llen != 1 {
		t.Errorf("Critical alert should have bypassed buffer, but LLEN is %d", llen)
	}
}

func TestWorker_DeliveryLogging(t *testing.T) {
	mock, _ := pgxmock.NewPool()
	defer mock.Close()
	
	w := &Worker{Pool: mock}
	
	mock.ExpectExec("INSERT INTO notification_delivery_logs").
		WithArgs(1, 2, 3, "slack", "success", "").
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
		
	w.logDelivery(1, 2, 3, "slack", true, "")
	
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Delivery logging failed expectations: %v", err)
	}
}

func TestWorker_SlackTeamsDelivery(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()
	
	w := &Worker{}
	cve := &models.CVE{CVEID: "CVE-2024-TEST", CVSSScore: 8.0, Description: "Test desc"}
	
	success, err := w.sendSlackAlert(ts.URL, cve, "Asset1", "#ff0000", "token", "http://localhost")
	if !success || err != "" {
		t.Errorf("Slack delivery failed: %s", err)
	}
	
	success, err = w.sendTeamsAlert(ts.URL, cve, "Asset1", "#ff0000", "token", "http://localhost")
	if !success || err != "" {
		t.Errorf("Teams delivery failed: %s", err)
	}
}
