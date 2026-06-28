package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSendJSONResponse(t *testing.T) {
	tests := []struct {
		name       string
		success    bool
		data       interface{}
		errMsg     string
		meta       interface{}
		wantStatus int
		wantError  string
	}{
		{
			name:       "SuccessPath",
			success:    true,
			data:       map[string]string{"foo": "bar"},
			errMsg:     "",
			meta:       nil,
			wantStatus: http.StatusOK,
			wantError:  "",
		},
		{
			name:       "ErrorPath",
			success:    false,
			data:       nil,
			errMsg:     "custom error",
			meta:       nil,
			wantStatus: http.StatusBadRequest,
			wantError:  "custom error",
		},
		{
			name:       "MarshalError",
			success:    true,
			data:       make(chan int), // triggers JSON marshal error
			errMsg:     "",
			meta:       nil,
			wantStatus: http.StatusInternalServerError,
			wantError:  "Internal server error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			SendJSONResponse(w, tt.wantStatus, tt.success, tt.data, tt.errMsg, tt.meta)

			if w.Code != tt.wantStatus {
				t.Errorf("SendJSONResponse() status = %d, want %d", w.Code, tt.wantStatus)
			}

			var resp APIResponse
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("failed to unmarshal response: %v", err)
			}

			if tt.name == "MarshalError" {
				if resp.Success {
					t.Errorf("expected success to be false")
				}
				if resp.Error != tt.wantError {
					t.Errorf("expected error %q, got %q", tt.wantError, resp.Error)
				}
			} else {
				if resp.Success != tt.success {
					t.Errorf("expected success to be %v, got %v", tt.success, resp.Success)
				}
				if resp.Error != tt.wantError {
					t.Errorf("expected error %q, got %q", tt.wantError, resp.Error)
				}
			}
		})
	}
}
