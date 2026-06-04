package worker

import (
	"context"
	"crypto/rand"
	"cve-tracker/internal/db"
	"cve-tracker/internal/models"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"golang.org/x/time/rate"
	"log/slog"
	"sync"
	"time"

	"github.com/hibiken/asynq"
)

type Worker struct {
	Pool                   db.DBPool
	Redis                  db.RedisProvider
	Mailer                 EmailSender
	HTTP                   HTTPClient
	AdminEmail             string
	WebhookSecret          string
	alertTimestamps        map[string]time.Time
	alertMu                sync.Mutex
	HNLimiter              *rate.Limiter
	RedditLimiter          *rate.Limiter
	alertResendBackoff     time.Duration
	enrichmentQueue        chan int
	AsynqClient            *asynq.Client
	HNClient               HNClient
	TickerFactory          func(time.Duration) Ticker
	TimerFactory           func(time.Duration) Timer
	OnHealthCheckDone      func()
	OnIntelligenceSyncDone func()
	OnAdvisoryRSSSyncDone  func()
}

func (w *Worker) initLimiters() {
	if w.HNLimiter == nil {
		w.HNLimiter = rate.NewLimiter(rate.Every(500*time.Millisecond), 1)
	}
	if w.RedditLimiter == nil {
		w.RedditLimiter = rate.NewLimiter(rate.Every(500*time.Millisecond), 1)
	}
}

func NewWorker(pool db.DBPool, redis db.RedisProvider, mailer EmailSender, http HTTPClient) *Worker {
	w := &Worker{
		Pool:               pool,
		HNLimiter:          rate.NewLimiter(rate.Every(500*time.Millisecond), 1),
		RedditLimiter:      rate.NewLimiter(rate.Every(500*time.Millisecond), 1),
		Redis:              redis,
		Mailer:             mailer,
		HTTP:               http,
		alertTimestamps:    make(map[string]time.Time),
		alertResendBackoff: 4 * time.Hour,
		enrichmentQueue:    make(chan int, 1000),
		TickerFactory: func(d time.Duration) Ticker {
			return &realTicker{time.NewTicker(d)}
		},
		TimerFactory: func(d time.Duration) Timer {
			return &realTimer{time.NewTimer(d)}
		},
	}
	w.HNClient = NewHNClient(http)
	return w
}

func (w *Worker) Start(ctx context.Context) {
	if ctx.Err() != nil {
		slog.Info("Worker: Context already cancelled, not starting background tasks.")
		return
	}
	slog.Info("Worker: Starting background tasks...")

	w.initLimiters()

	// Test LLM connectivity on startup if provider is configured
	go func() {
		testCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		w.TestLLMConnectivity(testCtx)
	}()

	var wg sync.WaitGroup

	runTask := func(task func(context.Context)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			task(ctx)
		}()
	}

	// Synchronization Tasks
	runTask(w.fetchCVEsPeriodically)
	runTask(w.fetchCISAKEVPeriodically)
	runTask(w.syncEPSSPeriodically)
	runTask(w.syncThreatIntelPeriodically)
	runTask(w.syncGitHubBuzzPeriodically)
	runTask(w.syncIntelligencePeriodically)
	runTask(w.syncGreyNoisePeriodically)
	runTask(w.syncOSVPeriodically)
	runTask(w.syncInTheWildPeriodically)
	runTask(w.syncAdvisoryRSSPeriodically)
	runTask(w.startHealthCheckPeriodically)

	// Notification & Alert Processing
	if w.AsynqClient != nil {
		runTask(func(ctx context.Context) { w.StartAsynqServer(ctx) })
	} else {
		// Fallback to legacy Redis queues for backwards compatibility / local tests
		runTask(w.processAlerts)
		runTask(w.processEmailVerification)
		runTask(w.processEmailChange)
		runTask(w.startEmailRetryPoller)
	}

	runTask(w.startWeeklySummaryTask)
	runTask(w.startIntelligenceEnrichmentTask)

	slog.Info("Worker: All background goroutines started.")
	<-ctx.Done()
	slog.Info("Worker: Stopping background tasks, waiting for goroutines to finish...")
	wg.Wait()
	slog.Info("Worker: All tasks gracefully stopped.")
}

func (w *Worker) enqueueAlertsForCVE(ctx context.Context, cve models.CVE) error {
	if cve.ID == 0 {
		var id int
		err := w.Pool.QueryRow(ctx, "SELECT id FROM cves WHERE cve_id = $1", cve.CVEID).Scan(&id)
		if err != nil {
			return fmt.Errorf("failed to get internal ID for CVE %s: %w", cve.CVEID, err)
		}
		cve.ID = id
	}

	alertJob, err := json.Marshal(cve)
	if err != nil {
		return fmt.Errorf("failed to marshal alert for %s: %w", cve.CVEID, err)
	}

	if w.AsynqClient != nil {
		task := asynq.NewTask("task:cve_alert", alertJob)
		_, err := w.AsynqClient.EnqueueContext(ctx, task)
		if err != nil {
			return fmt.Errorf("failed to enqueue asynq alert for %s: %w", cve.CVEID, err)
		}
		return nil
	}

	var lastErr error
	for i := 0; i < 3; i++ {
		if err := w.Redis.LPush(ctx, "cve_alerts_queue", alertJob).Err(); err != nil {
			lastErr = err
			time.Sleep(100 * time.Millisecond)
			continue
		}
		return nil
	}

	return fmt.Errorf("failed to enqueue alert for %s after retries: %w", cve.CVEID, lastErr)
}

// acquireLock attempts to acquire a Redis-based distributed lock for a task.
// If Redis is not configured, it falls back to local execution with a dummy token (returns true).
func (w *Worker) acquireLock(ctx context.Context, taskName string, ttl time.Duration) (string, bool) {
	if w.Redis == nil {
		return "no-redis-token", true
	}
	tokenBytes := make([]byte, 16)
	_, _ = rand.Read(tokenBytes)
	token := hex.EncodeToString(tokenBytes)

	key := "lock:task:" + taskName
	ok, err := w.Redis.SetNX(ctx, key, token, ttl).Result()
	if err != nil {
		slog.Error("Worker: Failed to acquire Redis lock", "task", taskName, "error", err)
		return "", false
	}
	if !ok {
		return "", false
	}
	return token, true
}

// releaseLock deletes the Redis key for a task lock atomically using a Lua script to ensure only the owner can release.
func (w *Worker) releaseLock(ctx context.Context, taskName string, token string) {
	if w.Redis == nil || token == "no-redis-token" {
		return
	}
	key := "lock:task:" + taskName
	script := `
		if redis.call("GET", KEYS[1]) == ARGV[1] then
			return redis.call("DEL", KEYS[1])
		else
			return 0
		end
	`
	res, err := w.Redis.Eval(ctx, script, []string{key}, token).Result()
	if err != nil {
		slog.Error("Worker: Failed to release Redis lock via Lua script", "task", taskName, "error", err)
		return
	}
	if val, ok := res.(int64); ok && val == 0 {
		slog.Warn("Worker: Failed to release Redis lock, token mismatch or expired", "task", taskName)
	}
}

// runWithLock executes the given sync task within a Redis distributed lock, extending the lock TTL periodically while taskFn runs.
func (w *Worker) runWithLock(ctx context.Context, taskName string, ttl time.Duration, taskFn func(context.Context)) {
	token, acquired := w.acquireLock(ctx, taskName, ttl)
	if !acquired {
		slog.Info("Worker: Task already running or locked in another instance", "task", taskName)
		return
	}

	heartbeatCtx, heartbeatCancel := context.WithCancel(ctx)
	defer heartbeatCancel()

	go func() {
		ticker := time.NewTicker(ttl / 3)
		defer ticker.Stop()
		for {
			select {
			case <-heartbeatCtx.Done():
				return
			case <-ticker.C:
				if w.Redis == nil || token == "no-redis-token" {
					return
				}
				key := "lock:task:" + taskName
				script := `
					if redis.call("GET", KEYS[1]) == ARGV[1] then
						return redis.call("EXPIRE", KEYS[1], ARGV[2])
					else
						return 0
					end
				`
				res, err := w.Redis.Eval(heartbeatCtx, script, []string{key}, token, int(ttl.Seconds())).Result()
				if err != nil {
					slog.Error("Worker: Failed to extend Redis lock TTL", "task", taskName, "error", err)
					return
				}
				if val, ok := res.(int64); ok && val == 0 {
					slog.Warn("Worker: Failed to extend Redis lock, lock lost or token mismatch", "task", taskName)
					return
				}
				slog.Debug("Worker: Successfully extended Redis lock TTL", "task", taskName)
			}
		}
	}()

	defer w.releaseLock(context.Background(), taskName, token)
	taskFn(ctx)
}
