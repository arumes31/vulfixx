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
	Port        string
	DatabaseURL string
	RedisURL    string
	TorProxy    string
}

var (
	pool    *pgxpool.Pool
	rdb     *redis.Client
	rsync   *redsync.Redsync
	config  Config
	userAgents = []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	}
)

type scalperServer struct {
	proto.UnimplementedScalperServiceServer
}

func init() {
	config = Config{
		Port:        getEnv("PORT", "9090"),
		DatabaseURL: os.Getenv("DATABASE_URL"),
		RedisURL:    os.Getenv("REDIS_URL"),
		TorProxy:    getEnv("TOR_PROXY", "socks5://localhost:9050"),
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

	go func() {
		log.Printf("Hardened Darknet Scalper gRPC Server listening on %v", lis.Addr())
		if err := s.Serve(lis); err != nil {
			log.Fatalf("failed to serve: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
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
	
	// Improvement 57: Check PostgreSQL for existing hits (deduplication)
	if !req.ForceRefresh && pool != nil {
		hits, count := fetchHitsFromDB(req.Query)
		if count > 0 {
			return &proto.ScanResponse{
				Query:     req.Query,
				TotalHits: int32(count),
				Hits:      hits,
				IsCached:  true,
			}, nil
		}
	}

	results := scalpMultiEngine(req.Query, int(req.Depth))
	
	// Save to DB
	if pool != nil {
		saveHitsToDB(results)
	}

	return &proto.ScanResponse{
		Query:     req.Query,
		TotalHits: int32(results.TotalHits),
		Hits:      results.Hits,
		IsCached:  false,
	}, nil
}

func (s *scalperServer) Backfill(ctx context.Context, req *proto.BackfillRequest) (*proto.BackfillResponse, error) {
	if rdb == nil {
		return nil, fmt.Errorf("redis not available")
	}

	for _, cve := range req.CveIds {
		// (9) Priority Queuing: Higher priority tasks are pushed to front (using LPush/RPush)
		// Or using a sorted set if complex priority is needed.
		var err error
		if req.Priority > 5 {
			err = rdb.LPush(ctx, "darknet_scan_tasks", cve).Err()
		} else {
			err = rdb.RPush(ctx, "darknet_scan_tasks", cve).Err()
		}
		if err != nil {
			log.Printf("Backfill error queuing %s: %v", cve, err)
			return nil, fmt.Errorf("failed to queue tasks")
		}
	}

	return &proto.BackfillResponse{
		Status:       "Queued",
		QueuedCount: int32(len(req.CveIds)),
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

		result, err := rdb.BLPop(ctx, 5*time.Second, "darknet_scan_tasks").Result()
		if err != nil {
			if err != redis.Nil {
				time.Sleep(1 * time.Second)
			}
			continue
		}

		cveID := result[1]
		
		// (5) Redlock: Prevent concurrent scans of the same CVE
		mutex := rsync.NewMutex("lock:"+cveID, redsync.WithExpiry(10*time.Minute))
		if err := mutex.Lock(); err != nil {
			log.Printf("Worker: Skipping %s (already locked by another node)", cveID)
			if pushErr := rdb.RPush(context.Background(), "darknet_scan_tasks", cveID).Err(); pushErr != nil {
				log.Printf("Worker: Failed to requeue task %s: %v", cveID, pushErr)
			}
			continue
		}

		log.Printf("Worker: Locked and processing %s", cveID)
		
		// Perform scan (default depth 2)
		res := scalpMultiEngine(cveID, 2)
		if pool != nil {
			saveHitsToDB(res)
		}
		
		mutex.Unlock()
		log.Printf("Worker: Task complete for %s", cveID)
	}
}

// Scraping Core

func scalpMultiEngine(q string, maxDepth int) *proto.ScanResponse {
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
				hits, _ = scalpAhmia(q, maxDepth)
			case "torch":
				hits, _ = scalpTorch(q, maxDepth)
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

func scalpAhmia(q string, maxDepth int) ([]*proto.Hit, error) {
	// Implementation using chromedp (Fingerprinting already hardened in Phase 2)
	// (18) Multi-depth logic added here
	query := fmt.Sprintf("%s OR \"%s exploit\"", q, q)
	
	torProxy := config.TorProxy
	if torProxy == "" {
		torProxy = "socks5://localhost:9050"
	}

	opts := []chromedp.ExecAllocatorOption{
		chromedp.UserAgent(userAgents[rand.Intn(len(userAgents))]),
		chromedp.NoSandbox,
		chromedp.ProxyServer(torProxy),
	}

	allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancel()
	
	timeoutCtx, cancelTimeout := context.WithTimeout(allocCtx, 30*time.Second)
	defer cancelTimeout()

	ctx, cancelChrome := chromedp.NewContext(timeoutCtx)
	defer cancelChrome()

	var html string
	err := chromedp.Run(ctx,
		chromedp.Navigate("https://ahmia.fi/search/?q="+url.QueryEscape(query)),
		chromedp.Sleep(5*time.Second),
		chromedp.OuterHTML("html", &html),
	)
	if err != nil {
		return nil, err
	}

	hits := parseAhmiaHTML(html, q)
	
	// (18) Depth logic: Traverse discovered links
	if maxDepth > 1 {
		for i := 0; i < len(hits) && i < 3; i++ {
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
	if torProxy == "" {
		torProxy = "socks5://localhost:9050"
	}
	proxyURL, _ := url.Parse(torProxy)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: 30 * time.Second,
	}

	resp, err := client.Get(hit.Url)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(resp.Body)
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

	// (17) OCR Integration: Find images and scan for CVE IDs
	doc.Find("img").Each(func(i int, s *goquery.Selection) {
		imgSrc, _ := s.Attr("src")
		if imgSrc != "" {
			ocrText := performOCRFromURL(imgSrc)
			if strings.Contains(ocrText, hit.Title) || strings.Contains(ocrText, "CVE-") {
				text += " [OCR: " + ocrText + "]"
			}
		}
	})

	if len(text) > 500 {
		hit.Snippet = text[:500] + "..."
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
	return performOCR(imgData)
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
	lures := []string{"official law enforcement", "trap", "honeypot", "fbi.gov", "interpol"}
	for _, lure := range lures {
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
		}
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

func checkTorLatency() time.Duration {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", "127.0.0.1:9050", 5*time.Second)
	if err != nil {
		return 0
	}
	conn.Close()
	return time.Since(start)
}

func downloadFile(u string) ([]byte, error) {
	torProxy := config.TorProxy
	if torProxy == "" {
		torProxy = "socks5://localhost:9050"
	}
	proxyURL, _ := url.Parse(torProxy)

	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout: 20 * time.Second,
	}
	resp, err := client.Get(u)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	const maxDownload = 10 * 1024 * 1024 // 10MB
	if resp.ContentLength > maxDownload {
		return nil, fmt.Errorf("response too large")
	}

	limitedReader := io.LimitReader(resp.Body, maxDownload+1)
	data, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, err
	}
	if len(data) > maxDownload {
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

func scalpTorch(q string, depth int) ([]*proto.Hit, error) {
	_ = q
	_ = depth
	// Mock implementation for Torch
	return nil, nil
}
