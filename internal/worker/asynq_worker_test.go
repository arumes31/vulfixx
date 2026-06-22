package worker

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"cve-tracker/internal/models"

	"github.com/alicebob/miniredis/v2"
	"github.com/hibiken/asynq"
	"github.com/pashagolub/pgxmock/v3"
)

func TestAsynqWorker_Flow(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()
	mock.MatchExpectationsInOrder(false)

	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("failed to start miniredis: %v", err)
	}
	defer mr.Close()

	// Initialize asynq client and server options with miniredis
	redisOpt := asynq.RedisClientOpt{Addr: mr.Addr()}

	asynqClient := asynq.NewClient(redisOpt)
	defer asynqClient.Close()

	w := NewWorker(mock, nil, &EmailSenderMock{}, http.DefaultClient)
	w.AsynqClient = asynqClient

	t.Run("EnqueueAndProcessCVEAlert", func(t *testing.T) {
		cve := models.CVE{
			ID:        123,
			CVEID:     "CVE-ASYNQ-TEST",
			CVSSScore: 9.8,
		}

		// Set up mock DB expectations
		mock.ExpectQuery("SELECT user_id FROM alert_history WHERE cve_id =").
			WithArgs(cve.ID).
			WillReturnRows(pgxmock.NewRows([]string{"user_id"}))
		mock.ExpectQuery("SELECT s.id, s.user_id").
			WithArgs(cve.CVSSScore, pgxmock.AnyArg()).
			WillReturnRows(pgxmock.NewRows([]string{"id", "user_id", "keyword", "min_severity", "webhook_url", "enable_email", "enable_webhook", "filter_logic", "email"}))
		mock.ExpectQuery("SELECT ak.keyword, a.user_id").
			WithArgs(pgxmock.AnyArg()).
			WillReturnRows(pgxmock.NewRows([]string{"keyword", "user_id", "email", "name"}))

		// Enqueue the alert via our helper
		ctx := context.Background()
		err := w.enqueueAlertsForCVE(ctx, cve)
		if err != nil {
			t.Fatalf("failed to enqueue CVE alert: %v", err)
		}

		// Initialize Asynq server
		srv := asynq.NewServer(redisOpt, asynq.Config{
			Concurrency: 1,
		})

		mux := asynq.NewServeMux()
		mux.HandleFunc("task:cve_alert", w.handleCVEAlertTask)

		// Start Asynq server
		if err := srv.Start(mux); err != nil {
			t.Fatalf("failed to start asynq server: %v", err)
		}
		defer srv.Shutdown()

		// Wait a brief moment for processing to complete
		time.Sleep(200 * time.Millisecond)

		// Assert that expectations were met
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})

	t.Run("EmailVerificationTask", func(t *testing.T) {
		mailer := &EmailSenderMockV2{}
		w.Mailer = mailer

		payload, _ := json.Marshal(map[string]interface{}{
			"email": "user@example.com",
			"token": "asynq-token-123",
		})

		task := asynq.NewTask("task:email_verification", payload)
		_, err := asynqClient.Enqueue(task)
		if err != nil {
			t.Fatalf("failed to enqueue: %v", err)
		}

		srv := asynq.NewServer(redisOpt, asynq.Config{Concurrency: 1})
		mux := asynq.NewServeMux()
		mux.HandleFunc("task:email_verification", w.handleEmailVerificationTask)

		if err := srv.Start(mux); err != nil {
			t.Fatalf("failed to start: %v", err)
		}

		// Wait briefly for processing, then shut down to guarantee worker completion before assertion.
		time.Sleep(500 * time.Millisecond)
		srv.Shutdown()

		if mailer.Count() != 1 {
			t.Errorf("expected 1 email to be sent, got %d", mailer.Count())
		}
	})

	t.Run("EmailChangeTask", func(t *testing.T) {
		mailer := &EmailSenderMockV2{}
		w.Mailer = mailer

		payload, _ := json.Marshal(map[string]interface{}{
			"old_email": "user_old@example.com",
			"old_token": "asynq-token-old",
			"new_email": "user_new@example.com",
			"new_token": "asynq-token-new",
		})

		task := asynq.NewTask("task:email_change", payload)
		_, err := asynqClient.Enqueue(task)
		if err != nil {
			t.Fatalf("failed to enqueue: %v", err)
		}

		srv := asynq.NewServer(redisOpt, asynq.Config{Concurrency: 1})
		mux := asynq.NewServeMux()
		mux.HandleFunc("task:email_change", w.handleEmailChangeTask)

		if err := srv.Start(mux); err != nil {
			t.Fatalf("failed to start: %v", err)
		}

		// Wait briefly for processing, then shut down to guarantee worker completion before assertion.
		time.Sleep(500 * time.Millisecond)
		srv.Shutdown()

		if mailer.Count() != 2 {
			t.Errorf("expected 2 emails to be sent, got %d", mailer.Count())
		}
	})
}

func TestAsynqLogger_Fatal(t *testing.T) {
	// We removed os.Exit(1) from asynqLogger.Fatal
	logger := &asynqLogger{}
	// This should not panic or exit the test process
	logger.Fatal("this is a fatal message")
}
