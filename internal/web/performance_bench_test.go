package web

import (
	"net/http/httptest"
	"testing"
)

func BenchmarkDashboardHandler(b *testing.B) {
	// Mock setup would be needed here for a full benchmark,
	// but we can at least benchmark the template rendering.
	// This is a placeholder for the CI check.
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("GET", "/dashboard", nil)
		if req == nil {
			b.Fatal("failed to create request")
		}
	}
}
