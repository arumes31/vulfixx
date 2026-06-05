package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const (
	nvdBase        = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	resultsPerPage = 2000
	outputDir      = "data/nvd"
)

func main() {
	apiKey := os.Getenv("NVD_API_KEY")
	if apiKey == "" {
		log.Println("Warning: NVD_API_KEY not set. Speed will be limited.")
	}

	if err := os.MkdirAll(outputDir, 0755); err != nil {
		log.Fatalf("Failed to create output directory: %v", err)
	}

	client := &http.Client{Timeout: 60 * time.Second}

	startIndex := 0
	totalResults := -1

	for {
		url := fmt.Sprintf("%s?resultsPerPage=%d&startIndex=%d", nvdBase, resultsPerPage, startIndex)
		fmt.Printf("Fetching batch starting at %d... ", startIndex)

		data, total, err := fetchBatch(client, apiKey, url)
		if err != nil {
			log.Fatalf("\nError fetching batch: %v", err)
		}

		if totalResults == -1 {
			totalResults = total
			fmt.Printf("(Total results: %d)\n", totalResults)
		} else {
			fmt.Println("Done.")
		}

		filename := filepath.Join(outputDir, fmt.Sprintf("nvd_batch_%d.json", startIndex))
		if err := os.WriteFile(filename, data, 0644); err != nil {
			log.Fatalf("Error writing file %s: %v", filename, err)
		}

		startIndex += resultsPerPage
		if startIndex >= totalResults {
			break
		}

		// Rate limiting: 0.6s with key, 6s without
		delay := 6 * time.Second
		if apiKey != "" {
			delay = 600 * time.Millisecond
		}
		time.Sleep(delay)
	}

	fmt.Printf("\nDownload complete. Files saved in %s\n", outputDir)
}

func fetchBatch(client *http.Client, apiKey, url string) ([]byte, int, error) {
	for attempt := 1; attempt <= 5; attempt++ {
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to create request: %w", err)
		}
		if apiKey != "" {
			req.Header.Set("apiKey", apiKey)
		}

		resp, err := client.Do(req)
		if err != nil {
			fmt.Printf(" (Attempt %d failed: %v) ", attempt, err)
			time.Sleep(time.Duration(attempt) * 2 * time.Second)
			continue
		}

		if resp.StatusCode == 403 || resp.StatusCode == 429 {
			fmt.Printf(" (Rate limited, status %d, waiting...) ", resp.StatusCode)
			resp.Body.Close()
			time.Sleep(30 * time.Second)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, 0, fmt.Errorf("bad status: %d", resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, 0, err
		}

		var metadata struct {
			TotalResults int `json:"totalResults"`
		}
		if err := json.Unmarshal(body, &metadata); err != nil {
			return nil, 0, fmt.Errorf("failed to parse metadata: %w", err)
		}

		return body, metadata.TotalResults, nil
	}
	return nil, 0, fmt.Errorf("max attempts reached")
}
