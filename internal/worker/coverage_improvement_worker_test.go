package worker

import (
	"context"
	"cve-tracker/internal/models"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/pashagolub/pgxmock/v3"
	"github.com/redis/go-redis/v9"
)

type MockHTTPClientV2 struct {
	DoFunc func(req *http.Request) (*http.Response, error)
}

func (m *MockHTTPClientV2) Do(req *http.Request) (*http.Response, error) {
	return m.DoFunc(req)
}

type EmailSenderMockV2 struct {
	Count int
	Err   error
}

func (m *EmailSenderMockV2) SendEmail(to, subject, body string) error {
	m.Count++
	return m.Err
}

func TestNotifier_SendAlert_Webhooks_Detailed(t *testing.T) {
	mock, _ := pgxmock.NewPool()
	defer mock.Close()

	mr, _ := miniredis.Run()
	defer mr.Close()
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	tests := []struct {
		name       string
		statusCode int
		shouldPass bool
	}{
		{"Webhook_200", 200, true},
		{"Webhook_400", 400, false},
		{"Webhook_500", 500, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
			}))
			defer ts.Close()
			t.Setenv("TEST_MODE", "1") // Disable SSRF loopback check for test
			
			httpClient := &MockHTTPClientV2{
				DoFunc: func(req *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: tt.statusCode,
						Body:       io.NopCloser(strings.NewReader("")),
					}, nil
				},
			}

			w := &Worker{
				Pool:   mock,
				Redis:  rdb,
				Mailer: &EmailSenderMockV2{},
				HTTP:   httpClient,
			}

			sub := models.UserSubscription{
				EnableWebhook: true,
				WebhookURL:    ts.URL, // Local mock server
			}
			cve := &models.CVE{
				CVEID:       "CVE-2023-0001",
				Description: "Test",
				CVSSScore:   9.5,
			}

			success := w.sendAlert(sub, cve, "user@example.com", "Asset1")
			if success != tt.shouldPass {
				t.Errorf("%s: expected success %v, got %v", tt.name, tt.shouldPass, success)
			}
		})
	}
}

func TestAlertBuffer_ProcessUserBuffer_Detailed(t *testing.T) {
	mr, _ := miniredis.Run()
	defer mr.Close()
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	mock, _ := pgxmock.NewPool()
	defer mock.Close()

	w := &Worker{
		Pool:   mock,
		Redis:  rdb,
		Mailer: &EmailSenderMockV2{},
	}

	userID := 1
	key := fmt.Sprintf("alert_buffer:%d", userID)

	t.Run("MultipleItems_Digest", func(t *testing.T) {
		cve1 := models.CVE{CVEID: "CVE-2023-0001", CVSSScore: 8.0, OSINTData: map[string]interface{}{"hn": []interface{}{"link"}}}
		cve2 := models.CVE{CVEID: "CVE-2023-0002", CVSSScore: 7.0, GitHubPoCCount: 20}
		
		data1, _ := json.Marshal(map[string]interface{}{"cve": cve1, "email": "user@example.com", "asset_name": "A1"})
		data2, _ := json.Marshal(map[string]interface{}{"cve": cve2, "email": "user@example.com", "asset_name": ""})
		
		rdb.RPush(context.Background(), key, data1, data2)

		w.processUserBuffer(context.Background(), userID)

		// Check buffer cleared
		llen, _ := rdb.LLen(context.Background(), key).Result()
		if llen != 0 {
			t.Errorf("expected buffer to be empty, got %d", llen)
		}
	})

	t.Run("SingleItem_DirectAlert", func(t *testing.T) {
		cve1 := models.CVE{CVEID: "CVE-2023-0003", CVSSScore: 8.5}
		data1, _ := json.Marshal(map[string]interface{}{"cve": cve1, "email": "user@example.com", "asset_name": "A1"})
		rdb.RPush(context.Background(), key, data1)

		w.processUserBuffer(context.Background(), userID)
		
		llen, _ := rdb.LLen(context.Background(), key).Result()
		if llen != 0 {
			t.Errorf("expected buffer to be empty, got %d", llen)
		}
	})
    
    t.Run("EmptyBuffer", func(t *testing.T) {
        w.processUserBuffer(context.Background(), userID)
    })
}

func TestEmailWorker_Queues_Detailed(t *testing.T) {
	mr, _ := miniredis.Run()
	defer mr.Close()
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	t.Run("EmailVerification_SuccessAndFailure", func(t *testing.T) {
		mockMailer := &EmailSenderMockV2{}
		w := &Worker{
			Redis:  rdb,
			Mailer: mockMailer,
		}

		// Success case
		payload, _ := json.Marshal(map[string]string{"email": "test@example.com", "token": "tok123"})
		rdb.LPush(context.Background(), "email_verification_queue", payload)

		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()

		w.processEmailVerification(ctx)

		if mockMailer.Count == 0 {
			t.Errorf("expected email to be sent")
		}

		// Failure case (error from mailer)
		mockMailer.Err = fmt.Errorf("mail error")
		rdb.LPush(context.Background(), "email_verification_queue", payload)
		
		ctx2, cancel2 := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel2()
		w.processEmailVerification(ctx2)
        
        // It should have re-enqueued the item in delayed queue
        args := redis.ZRangeArgs{Key: "email_verification_delayed", ByScore: true, Start: "-inf", Stop: "+inf"}
        items, _ := rdb.ZRangeArgs(context.Background(), args).Result()
        if len(items) == 0 {
            t.Errorf("expected item to be re-enqueued on failure")
        }
	})

    t.Run("EmailChange_Success", func(t *testing.T) {
		mockMailer := &EmailSenderMockV2{}
		w := &Worker{
			Redis:  rdb,
			Mailer: mockMailer,
		}

		payload, _ := json.Marshal(map[string]string{"email": "test@example.com", "token": "tok456", "type": "new"})
		rdb.LPush(context.Background(), "email_change_queue", payload)

		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()

		w.processEmailChange(ctx)

		if mockMailer.Count == 0 {
			t.Errorf("expected email to be sent")
		}
	})
    
    t.Run("InvalidPayloads", func(t *testing.T) {
        rdb.LPush(context.Background(), "email_verification_queue", "invalid json")
        rdb.LPush(context.Background(), "email_change_queue", "invalid json")
        
        w := &Worker{Redis: rdb}
        ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
        defer cancel()
        
        go w.processEmailVerification(ctx)
        go w.processEmailChange(ctx)
        
        time.Sleep(300*time.Millisecond)
    })
}
