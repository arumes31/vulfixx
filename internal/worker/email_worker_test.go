package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestEmailWorker_Queues(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis.Run failed: %v", err)
	}
	defer mr.Close()
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer func() { _ = rdb.Close() }()

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

		// Failure case
		mockMailer.Err = fmt.Errorf("mail error")
		rdb.LPush(context.Background(), "email_verification_queue", payload)

		ctx2, cancel2 := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel2()
		w.processEmailVerification(ctx2)

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
}

func TestEmailSender_Coverage(t *testing.T) {
	t.Run("MissingConfig", func(t *testing.T) {
		t.Setenv("SMTP_HOST", "")
		sender := &RealEmailSender{}
		err := sender.SendEmail("to@example.com", "sub", "body")
		if err == nil {
			t.Error("expected error")
		}
	})
	t.Run("InvalidRecipient", func(t *testing.T) {
		t.Setenv("SMTP_HOST", "localhost")
		t.Setenv("SMTP_FROM", "from@example.com")
		sender := &RealEmailSender{}
		err := sender.SendEmail("invalid\n", "sub", "body")
		if err == nil {
			t.Error("expected error")
		}
	})
}
