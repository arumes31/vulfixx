package web

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSendJSONResponse(t *testing.T) {
    tests := []struct {
        name       string
        statusCode int
        success    bool
        data       interface{}
        errMsg     string
        meta       interface{}
        wantCode   int
        wantBody   string
    }{
        {
            name:       "success response",
            statusCode: http.StatusOK,
            success:    true,
            data:       map[string]string{"key": "value"},
            errMsg:     "",
            meta:       nil,
            wantCode:   http.StatusOK,
            wantBody:   `{"success":true,"data":{"key":"value"}}`,
        },
        {
            name:       "error response",
            statusCode: http.StatusBadRequest,
            success:    false,
            data:       nil,
            errMsg:     "bad request",
            meta:       nil,
            wantCode:   http.StatusBadRequest,
            wantBody:   `{"success":false,"error":"bad request"}`,
        },
        {
            name:       "marshal error",
            statusCode: http.StatusOK,
            success:    true,
            data:       make(chan int), // Cannot marshal a channel
            errMsg:     "",
            meta:       nil,
            wantCode:   http.StatusInternalServerError,
            wantBody:   `{"success":false,"error":"Internal server error"}`,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            rr := httptest.NewRecorder()
            SendJSONResponse(rr, tt.statusCode, tt.success, tt.data, tt.errMsg, tt.meta)

            if rr.Code != tt.wantCode {
                t.Errorf("expected code %d, got %d", tt.wantCode, rr.Code)
            }

            // check json format exactly or parse json and compare
            if rr.Body.String() != tt.wantBody {
                t.Errorf("expected body %s, got %s", tt.wantBody, rr.Body.String())
            }
        })
    }
}
