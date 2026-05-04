package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"vulfixx-scalper/proto"

	"github.com/PuerkitoBio/goquery"
	"github.com/chromedp/chromedp"
	"github.com/go-redsync/redsync/v4"
	"github.com/go-redsync/redsync/v4/redis/goredis/v9"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
)

// Config holds environment configurations
type Config struct {
	Port               string
	DatabaseURL        string
	RedisURL           string
	TorProxy           string
	UserAgents         []string
	AhmiaURL           string
	AhmiaSleep         time.Duration
	AhmiaTimeout       time.Duration
	WorkerPopTimeout   time.Duration
	RedlockExpiry      time.Duration
	RedlockExtend      time.Duration
	RetryInterval      time.Duration
	DefaultDepth       int
	EnrichTimeout      time.Duration
	EnrichSnippetLen   int
	EnrichMaxLinks     int
	DownloadMaxSize    int64
	DownloadTimeout    time.Duration
	LatencyTimeout     time.Duration
	HoneyLures         []string
	EnableOCR          bool
}

const (
	MAX_CVE_IDS      = 100
	MAX_PRIORITY     = 10
	MAX_DEPTH        = 5
	MAX_BODY_SIZE    = 10 << 20 // 10MB
)

var (
	pool    *pgxpool.Pool
	rdb     *redis.Client
	rsync   *redsync.Redsync
	config  Config
)

type scalperServer struct {
	proto.UnimplementedScalperServiceServer
}

func init() {
	defaultUserAgents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	}

	defaultHoneyLures := []string{"official law enforcement", "trap", "honeypot", "fbi.gov", "interpol"}

	config = Config{
		Port:               getEnv("PORT", "9090"),
		DatabaseURL:        os.Getenv("DATABASE_URL"),
		RedisURL:           os.Getenv("REDIS_URL"),
		TorProxy:           getEnv("SCALPER_TOR_PROXY", getEnv("TOR_PROXY", "socks5://localhost:9050")),
		UserAgents:         getEnvSlice("SCALPER_USER_AGENTS", defaultUserAgents),
		AhmiaURL:           getEnv("SCALPER_AHMIA_URL", "https://ahmia.fi/search/?q="),
		AhmiaSleep:         getEnvDuration("SCALPER_AHMIA_SLEEP", 5*time.Second),
		AhmiaTimeout:       getEnvDuration("SCALPER_AHMIA_TIMEOUT", 30*time.Second),
		WorkerPopTimeout:   getEnvDuration("SCALPER_WORKER_POP_TIMEOUT", 5*time.Second),
		RedlockExpiry:      getEnvDuration("SCALPER_REDLOCK_EXPIRY", 10*time.Minute),
		RedlockExtend:      getEnvDuration("SCALPER_REDLOCK_EXTEND", 3*time.Minute),
		RetryInterval:      getEnvDuration("SCALPER_RETRY_INTERVAL", 1*time.Second),
		DefaultDepth:       getEnvInt("SCALPER_DEFAULT_DEPTH", 2),
		EnrichTimeout:      getEnvDuration("SCALPER_ENRICH_TIMEOUT", 30*time.Second),
		EnrichSnippetLen:   getEnvInt("SCALPER_ENRICH_SNIPPET_LEN", 500),
		EnrichMaxLinks:     getEnvInt("SCALPER_ENRICH_MAX_LINKS", 3),
		DownloadMaxSize:    getEnvInt64("SCALPER_DOWNLOAD_MAX_SIZE", 10*1024*1024),
		DownloadTimeout:    getEnvDuration("SCALPER_DOWNLOAD_TIMEOUT", 20*time.Second),
		LatencyTimeout:     getEnvDuration("SCALPER_LATENCY_TIMEOUT", 5*time.Second),
		HoneyLures:         getEnvSlice("SCALPER_HONEY_LURES", defaultHoneyLures),
		EnableOCR:          getEnvBool("SCALPER_ENABLE_OCR", true),
	}
}

func main() {
	// (4) Initialize PostgreSQL Connection
	initPostgres()
	// (1, 5) Initialize Redis & Redlock
	initRedis()

	// (3) Start gRPC Server
	lis, err := net.Listen("tcp", ":"+config.Port)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	s := grpc.NewServer()
	proto.RegisterScalperServiceServer(s, &scalperServer{})
	reflection.Register(s)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup

	// (8) Workers are stateless - can run multiple in background
	if rdb != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runWorker(ctx)
		}()
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)

	go func() {
		log.Printf("Hardened Darknet Scalper gRPC Server listening on %v", lis.Addr())
		if err := s.Serve(lis); err != nil {
			log.Printf("failed to serve: %v", err)
			quit <- syscall.SIGTERM
		}
	}()

	<-quit
	log.Println("Shutting down gracefully...")

	cancel()
	s.GracefulStop()

	wg.Wait()

	if pool != nil {
		pool.Close()
	}
	if rdb != nil {
		rdb.Close()
	}
}

func initPostgres() {
	if config.DatabaseURL == "" {
		log.Printf("DATABASE_URL not set, persistence disabled.")
		return
	}
	var err error
	pool, err = pgxpool.New(context.Background(), config.DatabaseURL)
	if err != nil {
		log.Fatalf("Unable to connect to database: %v", err)
	}
	log.Printf("PostgreSQL connected for intelligence persistence.")
}

func initRedis() {
	if config.RedisURL == "" {
		log.Printf("REDIS_URL not set, distributed logic disabled.")
		return
	}
	opts, err := redis.ParseURL(config.RedisURL)
	if err != nil {
		log.Fatalf("Failed to parse REDIS_URL: %v", err)
	}
	rdb = redis.NewClient(opts)
	rsync = redsync.New(goredis.NewPool(rdb))
	log.Printf("Redis & Redlock initialized.")
}

// gRPC Implementation

func (s *scalperServer) Scan(ctx context.Context, req *proto.ScanRequest) (*proto.ScanResponse, error) {
	log.Printf("gRPC: Received Scan for %s (depth: %d)", req.Query, req.Depth)
	
	if req.Depth < 0 || req.Depth > MAX_DEPTH {
		return nil, status.Errorf(codes.InvalidArgument, "depth out of range (0-%d)", MAX_DEPTH)
	}

	// Improvement 57: Check PostgreSQL for existing hits (deduplication)
	if !req.ForceRefresh && pool != nil {
		hits, count := fetchHitsFromDB(req.Query)
		if count > 0 {
			// Basic pagination logic
			start := 0
			if req.PageToken != "" {
				fmt.Sscanf(req.PageToken, "%d", &start)
			}
			
			pageSize := int(req.PageSize)
			if pageSize <= 0 {
				pageSize = 10
			}
			
			end := start + pageSize
			if end > count {
				end = count
			}
			
			var paginatedHits []*proto.Hit
			if start < count {
				paginatedHits = hits[start:end]
			}
			
			nextPageToken := ""
			if end < count {
				nextPageToken = fmt.Sprintf("%d", end)
			}

			return &proto.ScanResponse{
				Query:         req.Query,
				TotalHits:     int32(count),
				Hits:          paginatedHits,
				IsCached:      true,
				NextPageToken: nextPageToken,
			}, nil
		}
	}

	results := scalpMultiEngine(ctx, req.Query, int(req.Depth))
	
	// Save to DB
	if pool != nil {
		saveHitsToDB(results)
	}

	// Pagination for fresh results
	pageSize := int(req.PageSize)
	if pageSize <= 0 {
		pageSize = 10
	}
	
	totalHits := len(results.Hits)
	end := pageSize
	if end > totalHits {
		end = totalHits
	}
	
	nextPageToken := ""
	if totalHits > pageSize {
		nextPageToken = fmt.Sprintf("%d", pageSize)
	}

	return &proto.ScanResponse{
		Query:         req.Query,
		TotalHits:     int32(totalHits),
		Hits:          results.Hits[:end],
		IsCached:      false,
		NextPageToken: nextPageToken,
	}, nil
}

var cveRegex = regexp.MustCompile(`^CVE-\d{4}-\d+$`)

func (s *scalperServer) Backfill(ctx context.Context, req *proto.BackfillRequest) (*proto.BackfillResponse, error) {
	if rdb == nil {
		return nil, status.Error(codes.FailedPrecondition, "redis not available")
	}

	if len(req.CveIds) > MAX_CVE_IDS {
		return nil, status.Errorf(codes.InvalidArgument, "too many CVE IDs (max %d)", MAX_CVE_IDS)
	}
	if req.Priority < 0 || req.Priority > MAX_PRIORITY {
		return nil, status.Errorf(codes.InvalidArgument, "priority out of range (0-%d)", MAX_PRIORITY)
	}

	pipe := rdb.TxPipeline()
	queuedCount := 0
	for _, cve := range req.CveIds {
		if cve == "" || !cveRegex.MatchString(cve) {
			continue
		}
		queuedCount++
		if req.Priority > 5 {
			pipe.LPush(ctx, "darknet_scan_tasks", cve)
		} else {
			pipe.RPush(ctx, "darknet_scan_tasks", cve)
		}
	}

	if _, err := pipe.Exec(ctx); err != nil {
		log.Printf("Backfill error queuing tasks: %v", err)
		return nil, status.Error(codes.Internal, fmt.Sprintf("failed to queue tasks: %v", err))
	}

	return &proto.BackfillResponse{
		Status:       "Queued",
		QueuedCount: int32(queuedCount),
	}, nil
}

func (s *scalperServer) Health(ctx context.Context, req *proto.HealthRequest) (*proto.HealthResponse, error) {
	latency := checkTorLatency()
	if latency == 0 {
		return &proto.HealthResponse{
			Status:         "UNHEALTHY",
			TorLatencyMs:   0,
		}, status.Errorf(codes.Unavailable, "Tor proxy is unreachable")
	}
	return &proto.HealthResponse{
		Status:         "OK",
		TorLatencyMs: float32(latency.Seconds() * 1000),
	}, nil
}

// (1, 5, 8, 9) Worker Logic with Redlock
func runWorker(ctx context.Context) {
	log.Printf("Stateless worker started...")
	for {
		select {
		case <-ctx.Done():
			log.Printf("Worker shutting down...")
			return
		default:
		}

		result, err := rdb.BLPop(ctx, config.WorkerPopTimeout, "darknet_scan_tasks").Result()
		if err != nil {
			if err == context.Canceled || err == context.DeadlineExceeded {
				return
			}
			if err != redis.Nil {
				time.Sleep(config.RetryInterval)
			}
			continue
		}

		cveID := result[1]
		
		// (5) Redlock: Prevent concurrent scans of the same CVE
		mutex := rsync.NewMutex("lock:"+cveID, redsync.WithExpiry(config.RedlockExpiry))
		if err := mutex.Lock(); err != nil {
			log.Printf("Worker: Skipping %s (already locked by another node)", cveID)
			if pushErr := rdb.RPush(context.Background(), "darknet_scan_tasks", cveID).Err(); pushErr != nil {
				log.Printf("Worker: Failed to requeue task %s: %v", cveID, pushErr)
			}
			continue
		}

		log.Printf("Worker: Locked and processing %s", cveID)
		
		parentCtx, cancel := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() {
			ticker := time.NewTicker(config.RedlockExtend)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					if ok, _ := mutex.Extend(); !ok {
						log.Printf("Worker: Failed to extend lock for %s, aborting...", cveID)
						cancel()
					}
				case <-done:
					return
				}
			}
		}()

		// Perform scan
		res := scalpMultiEngine(parentCtx, cveID, config.DefaultDepth)
		if parentCtx.Err() == nil && pool != nil {
			saveHitsToDB(res)
		}
		
		close(done)
		cancel()
		if ok, err := mutex.Unlock(); !ok || err != nil {
			log.Printf("Worker: Error unlocking %s: %v", cveID, err)
		}
		log.Printf("Worker: Task complete for %s", cveID)
	}
}

// Scraping Core

func scalpMultiEngine(ctx context.Context, q string, maxDepth int) *proto.ScanResponse {
	var wg sync.WaitGroup
	var mu sync.Mutex
	finalResult := &proto.ScanResponse{
		Query: q,
		Hits:  []*proto.Hit{},
	}

	engines := []string{"ahmia", "torch"}
	wg.Add(len(engines))

	for _, engine := range engines {
		go func(e string) {
			defer wg.Done()
			var hits []*proto.Hit
			switch e {
			case "ahmia":
				hits, _ = scalpAhmia(ctx, q, maxDepth)
			case "torch":
				hits, _ = scalpTorch(ctx, q, maxDepth)
			}

			if len(hits) > 0 {
				mu.Lock()
				finalResult.Hits = append(finalResult.Hits, hits...)
				mu.Unlock()
			}
		}(engine)
	}

	wg.Wait()
	finalResult.TotalHits = int32(len(finalResult.Hits))
	return finalResult
}

func scalpAhmia(ctx context.Context, q string, maxDepth int) ([]*proto.Hit, error) {
	// Implementation using chromedp (Fingerprinting already hardened in Phase 2)
	// (18) Multi-depth logic added here
	query := fmt.Sprintf("%s OR \"%s exploit\"", q, q)
	
	torProxy := config.TorProxy

	var ua string
	if len(config.UserAgents) > 0 {
		ua = config.UserAgents[rand.Intn(len(config.UserAgents))]
	} else {
		ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
	}

	opts := []chromedp.ExecAllocatorOption{
		chromedp.UserAgent(ua),
		chromedp.NoSandbox,
		chromedp.ProxyServer(torProxy),
	}

	allocCtx, cancel := chromedp.NewExecAllocator(ctx, opts...)
	defer cancel()
	
	timeoutCtx, cancelTimeout := context.WithTimeout(allocCtx, config.AhmiaTimeout)
	defer cancelTimeout()

	chromeCtx, cancelChrome := chromedp.NewContext(timeoutCtx)
	defer cancelChrome()

	var html string
	err := chromedp.Run(chromeCtx,
		chromedp.Navigate(config.AhmiaURL+url.QueryEscape(query)),
		chromedp.Sleep(config.AhmiaSleep),
		chromedp.OuterHTML("html", &html),
	)
	if err != nil {
		return nil, err
	}

	hits := parseAhmiaHTML(html, q)
	
	// (18) Depth logic: Traverse discovered links
	if maxDepth > 1 {
		for i := 0; i < len(hits) && i < config.EnrichMaxLinks; i++ {
			enrichHit(hits[i], maxDepth-1)
		}
	}

	return hits, nil
}

func enrichHit(hit *proto.Hit, depth int) {
	_ = depth // Future use for recursive crawling
	if hit.Url == "" || !strings.Contains(hit.Url, ".onion") {
		return
	}

	torProxy := config.TorProxy
	proxyURL, err := url.Parse(torProxy)
	if err != nil {
		log.Printf("Error parsing tor proxy %q: %v", torProxy, err)
		return
	}

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: config.EnrichTimeout,
	}

	resp, err := client.Get(hit.Url)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(io.LimitReader(resp.Body, MAX_BODY_SIZE))
	if err != nil {
		return
	}

	// (23) Language Detection (Simple implementation)
	text := doc.Find("body").Text()
	hit.Language = detectLanguage(text)
	
	// (97) Honey-link Detection
	if isHoneyLink(hit.Url, text) {
		hit.IsHoneyLink = true
	}

	hitURL, parseErr := url.Parse(hit.Url)

	// (17) OCR Integration: Find images and scan for CVE IDs
	if config.EnableOCR {
		doc.Find("img").Each(func(i int, s *goquery.Selection) {
			imgSrc, _ := s.Attr("src")
			if imgSrc != "" {
				if parseErr == nil {
					imgURL, err := url.Parse(imgSrc)
					if err == nil {
						imgSrc = hitURL.ResolveReference(imgURL).String()
					}
				}
				ocrText := performOCRFromURL(imgSrc)
				if strings.Contains(ocrText, hit.Title) || strings.Contains(ocrText, "CVE-") {
					text += " [OCR: " + ocrText + "]"
				}
			}
		})
	}

	if len(text) > config.EnrichSnippetLen {
		hit.Snippet = text[:config.EnrichSnippetLen] + "..."
	} else {
		hit.Snippet = text
	}
}

// Helpers

func performOCRFromURL(imgURL string) string {
	// Download image via Tor
	imgData, err := downloadFile(imgURL)
	if err != nil {
		return ""
	}
	text, err := performOCR(imgData)
	if err != nil {
		log.Printf("OCR error for %s: %v", imgURL, err)
		return ""
	}
	return text
}

func detectLanguage(text string) string {
	// (23) Placeholder for real NLP - simple regex check for cyrillic (Russian)
	if regexp.MustCompile(`[а-яА-Я]`).MatchString(text) {
		return "ru"
	}
	return "en"
}

func isHoneyLink(u, text string) bool {
	// (97) Pattern matching for known LE lure terms
	for _, lure := range config.HoneyLures {
		if strings.Contains(strings.ToLower(text), lure) || strings.Contains(strings.ToLower(u), lure) {
			return true
		}
	}
	return false
}

func fetchHitsFromDB(query string) ([]*proto.Hit, int) {
	rows, err := pool.Query(context.Background(), "SELECT title, url, engine, snippet, language, is_honey_link FROM darknet_intel_hits WHERE cve_id = $1", query)
	if err != nil {
		return nil, 0
	}
	defer rows.Close()

	var hits []*proto.Hit
	for rows.Next() {
		var h proto.Hit
		if err := rows.Scan(&h.Title, &h.Url, &h.Engine, &h.Snippet, &h.Language, &h.IsHoneyLink); err == nil {
			hits = append(hits, &h)
		} else {
			log.Printf("Error scanning hit row: %v", err)
		}
	}
	if err := rows.Err(); err != nil {
		log.Printf("Error iterating hits rows: %v", err)
	}
	return hits, len(hits)
}

func saveHitsToDB(res *proto.ScanResponse) {
	for _, h := range res.Hits {
		_, err := pool.Exec(context.Background(), `
			INSERT INTO darknet_intel_hits (cve_id, engine, title, url, snippet, language, is_honey_link)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			ON CONFLICT (url) DO NOTHING
		`, res.Query, h.Engine, h.Title, h.Url, h.Snippet, h.Language, h.IsHoneyLink)
		if err != nil {
			log.Printf("Error saving hit (query: %s, url: %s): %v", res.Query, h.Url, err)
		}
	}

	// Update main CVE table
	_, err := pool.Exec(context.Background(), `
		UPDATE cves SET darknet_mentions = (SELECT COUNT(*) FROM darknet_intel_hits WHERE cve_id = $1), darknet_last_seen = NOW()
		WHERE cve_id = $1
	`, res.Query)
	if err != nil {
		log.Printf("Error updating darknet mentions (query: %s): %v", res.Query, err)
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getEnvDuration(key string, fallback time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		d, err := time.ParseDuration(v)
		if err == nil {
			return d
		}
		log.Printf("Invalid duration for %s: %v. Using fallback: %v", key, v, fallback)
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		i, err := strconv.Atoi(v)
		if err == nil {
			return i
		}
		log.Printf("Invalid integer for %s: %v. Using fallback: %d", key, v, fallback)
	}
	return fallback
}

func getEnvInt64(key string, fallback int64) int64 {
	if v := os.Getenv(key); v != "" {
		i, err := strconv.ParseInt(v, 10, 64)
		if err == nil {
			return i
		}
		log.Printf("Invalid int64 for %s: %v. Using fallback: %d", key, v, fallback)
	}
	return fallback
}

func getEnvSlice(key string, fallback []string) []string {
	if v := os.Getenv(key); v != "" {
		return strings.Split(v, ",")
	}
	return fallback
}

func getEnvBool(key string, fallback bool) bool {
	if v := os.Getenv(key); v != "" {
		b, err := strconv.ParseBool(v)
		if err == nil {
			return b
		}
		log.Printf("Invalid boolean for %s: %v. Using fallback: %v", key, v, fallback)
	}
	return fallback
}

func checkTorLatency() time.Duration {
	torProxy := config.TorProxy
	proxyURL, err := url.Parse(torProxy)
	if err != nil || proxyURL.Host == "" {
		return 0
	}
	start := time.Now()
	conn, err := net.DialTimeout("tcp", proxyURL.Host, config.LatencyTimeout)
	if err != nil {
		return 0
	}
	conn.Close()
	return time.Since(start)
}

func downloadFile(u string) ([]byte, error) {
	torProxy := config.TorProxy
	proxyURL, err := url.Parse(torProxy)
	if err != nil {
		log.Printf("Error parsing tor proxy %q in downloadFile: %v", torProxy, err)
		return nil, err
	}

	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout: config.DownloadTimeout,
	}
	resp, err := client.Get(u)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	maxDownload := config.DownloadMaxSize
	if resp.ContentLength > maxDownload {
		return nil, fmt.Errorf("response too large")
	}

	limitedReader := io.LimitReader(resp.Body, maxDownload+1)
	data, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxDownload {
		return nil, fmt.Errorf("response exceeded maximum size")
	}
	
	return data, nil
}

// Ahmia HTML Parser (simplified for demo)
func parseAhmiaHTML(html, q string) []*proto.Hit {
	_ = q // Future use for keyword highlighting
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(html))
	var hits []*proto.Hit
	if err != nil {
		log.Printf("Error parsing HTML: %v", err)
		return hits
	}
	doc.Find("li.result").Each(func(i int, s *goquery.Selection) {
		hits = append(hits, &proto.Hit{
			Title:  strings.TrimSpace(s.Find("h4").Text()),
			Url:    s.Find("cite").Text(),
			Engine: "ahmia",
		})
	})
	return hits
}

func scalpTorch(ctx context.Context, q string, depth int) ([]*proto.Hit, error) {
	_ = q
	_ = depth
	// Mock implementation for Torch
	return nil, nil
}
