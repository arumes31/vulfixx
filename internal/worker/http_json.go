package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// FetchJSON is a helper function that performs an HTTP GET request to the given URL,
// sets the User-Agent header, executes the request using the provided HTTP client,
// and decodes the JSON response into the target interface.
// It returns the HTTP status code (if a response was received) and any error encountered.
func FetchJSON(ctx context.Context, client HTTPClient, url string, target interface{}) (int, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil) // #nosec G704
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "Vulfixx-Threat-Intel/2.0")

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK && target != nil {
		if err := json.NewDecoder(resp.Body).Decode(target); err != nil {
			return resp.StatusCode, fmt.Errorf("failed to decode JSON response: %w", err)
		}
	}

	return resp.StatusCode, nil
}
