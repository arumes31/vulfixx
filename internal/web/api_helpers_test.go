package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSendJSONResponse(t *testing.T) {
	tests := []struct {
		name               string
		statusCode         int
		success            bool
		data               interface{}
		errMsg             string
		meta               interface{}
		expectedCode       int
		expectedSuccess    bool
		expectedError      string
		expectedData       interface{}
	}{
		{
			name:            "SuccessResponse",
			statusCode:      http.StatusOK,
			success:         true,
			data:            map[string]string{"foo": "bar"},
			errMsg:          "",
			meta:            nil,
			expectedCode:    http.StatusOK,
			expectedSuccess: true,
			expectedError:   "",
			expectedData:    map[string]interface{}{"foo": "bar"},
		},
		{
			name:            "ErrorResponse",
			statusCode:      http.StatusBadRequest,
			success:         false,
			data:            nil,
			errMsg:          "bad request error",
			meta:            nil,
			expectedCode:    http.StatusBadRequest,
			expectedSuccess: false,
			expectedError:   "bad request error",
			expectedData:    nil,
		},
		{
			name:            "MarshalError",
			statusCode:      http.StatusOK,
			success:         true,
			data:            make(chan int), // Channel cannot be marshaled
			errMsg:          "",
			meta:            nil,
			expectedCode:    http.StatusInternalServerError,
			expectedSuccess: false,
			expectedError:   "Internal server error",
			expectedData:    nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			SendJSONResponse(rr, tt.statusCode, tt.success, tt.data, tt.errMsg, tt.meta)

			if rr.Code != tt.expectedCode {
				t.Errorf("expected code %d, got %d", tt.expectedCode, rr.Code)
			}

			contentType := rr.Header().Get("Content-Type")
			if contentType != "application/json" {
				t.Errorf("expected application/json, got %s", contentType)
			}

			var resp APIResponse
			if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
				t.Fatalf("failed to decode response: %v", err)
			}

			if resp.Success != tt.expectedSuccess {
				t.Errorf("expected success %v, got %v", tt.expectedSuccess, resp.Success)
			}

			if resp.Error != tt.expectedError {
				t.Errorf("expected error %q, got %q", tt.expectedError, resp.Error)
			}

			if tt.expectedData != nil {
				dataMap, ok := resp.Data.(map[string]interface{})
				if !ok {
					t.Fatalf("expected data to be map[string]interface{}, got %T", resp.Data)
				}
				expectedMap := tt.expectedData.(map[string]interface{})
				for k, v := range expectedMap {
					if dataMap[k] != v {
						t.Errorf("expected data[%q]=%v, got %v", k, v, dataMap[k])
					}
				}
			}
		})
	}
}
