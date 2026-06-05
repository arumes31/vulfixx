package proto

import (
	"context"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func TestCVERequest_Methods(t *testing.T) {
	tests := []struct {
		name     string
		req      *CVERequest
		expected string
	}{
		{
			name:     "nil request",
			req:      nil,
			expected: "",
		},
		{
			name:     "valid request",
			req:      &CVERequest{CveId: "CVE-2023-1234"},
			expected: "CVE-2023-1234",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.req.GetCveId(); got != tt.expected {
				t.Errorf("GetCveId() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestCVEResponse_Methods(t *testing.T) {
	tests := []struct {
		name string
		resp *CVEResponse
		want *CVEResponse
	}{
		{
			name: "nil response",
			resp: nil,
			want: &CVEResponse{},
		},
		{
			name: "valid response",
			resp: &CVEResponse{
				Id:            1,
				CveId:         "CVE-2023-1234",
				Description:   "Test desc",
				CvssScore:     9.8,
				PublishedDate: "2023-01-01",
			},
			want: &CVEResponse{
				Id:            1,
				CveId:         "CVE-2023-1234",
				Description:   "Test desc",
				CvssScore:     9.8,
				PublishedDate: "2023-01-01",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.resp.GetId(); got != tt.want.Id {
				t.Errorf("GetId() = %v, want %v", got, tt.want.Id)
			}
			if got := tt.resp.GetCveId(); got != tt.want.CveId {
				t.Errorf("GetCveId() = %v, want %v", got, tt.want.CveId)
			}
			if got := tt.resp.GetDescription(); got != tt.want.Description {
				t.Errorf("GetDescription() = %v, want %v", got, tt.want.Description)
			}
			if got := tt.resp.GetCvssScore(); got != tt.want.CvssScore {
				t.Errorf("GetCvssScore() = %v, want %v", got, tt.want.CvssScore)
			}
			if got := tt.resp.GetPublishedDate(); got != tt.want.PublishedDate {
				t.Errorf("GetPublishedDate() = %v, want %v", got, tt.want.PublishedDate)
			}
		})
	}
}

func TestCVERequest_ProtoMethods(t *testing.T) {
	req := &CVERequest{CveId: "CVE-2024-1234"}

	req.ProtoMessage()

	ref := req.ProtoReflect()
	if ref == nil {
		t.Error("ProtoReflect() returned nil")
	}

	str := req.String()
	if str == "" {
		t.Error("String() returned empty")
	}

	req.Reset()
	if req.CveId != "" {
		t.Errorf("Reset() failed, got %v", req.CveId)
	}
}

func TestCVEResponse_ProtoMethods(t *testing.T) {
	resp := &CVEResponse{Id: 1, CveId: "CVE-2024-1234"}

	resp.ProtoMessage()

	ref := resp.ProtoReflect()
	if ref == nil {
		t.Error("ProtoReflect() returned nil")
	}

	str := resp.String()
	if str == "" {
		t.Error("String() returned empty")
	}

	resp.Reset()
	if resp.Id != 0 || resp.CveId != "" {
		t.Errorf("Reset() failed, got %+v", resp)
	}
}

// GRPC Tests

type mockUnimplementedServer struct {
	UnimplementedCVEServiceServer
}

func TestNewCVEServiceClient(t *testing.T) {
	client := NewCVEServiceClient(nil)
	if client == nil {
		t.Error("NewCVEServiceClient returned nil")
	}
}

func TestUnimplementedCVEServiceServer(t *testing.T) {
	srv := &UnimplementedCVEServiceServer{}

	resp, err := srv.GetCVE(context.Background(), &CVERequest{})
	if err == nil {
		t.Error("expected error from UnimplementedCVEServiceServer.GetCVE")
	}
	if resp != nil {
		t.Error("expected nil response from UnimplementedCVEServiceServer.GetCVE")
	}

	srv.mustEmbedUnimplementedCVEServiceServer()
	srv.testEmbeddedByValue()
}

func TestRegisterCVEServiceServer(t *testing.T) {
	srv := grpc.NewServer()
	RegisterCVEServiceServer(srv, &mockUnimplementedServer{})
}

func TestCVEService_GetCVE_Handler(t *testing.T) {
	srv := &mockUnimplementedServer{}

	dec := func(v interface{}) error {
		return nil
	}

	_, err := _CVEService_GetCVE_Handler(srv, context.Background(), dec, nil)
	if err == nil {
		t.Error("expected unimplemented error")
	}
}

type mockCVEServiceServer struct {
	UnimplementedCVEServiceServer
}

func (s *mockCVEServiceServer) GetCVE(ctx context.Context, req *CVERequest) (*CVEResponse, error) {
	return &CVEResponse{Id: 1, CveId: req.CveId}, nil
}

func TestGetCVE_ClientServer(t *testing.T) {
	lis, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	s := grpc.NewServer()
	RegisterCVEServiceServer(s, &mockCVEServiceServer{})
	go func() {
		if err := s.Serve(lis); err != nil {
			t.Logf("failed to serve: %v", err)
		}
	}()
	defer s.Stop()

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	c := NewCVEServiceClient(conn)

	ctx := context.Background()
	r, err := c.GetCVE(ctx, &CVERequest{CveId: "CVE-2024-1234"})
	if err != nil {
		t.Fatalf("could not get CVE: %v", err)
	}
	if r.GetCveId() != "CVE-2024-1234" {
		t.Errorf("expected %s, got %s", "CVE-2024-1234", r.GetCveId())
	}
}
