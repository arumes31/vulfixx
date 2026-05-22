package web

import (
	"context"
	"testing"

	"cve-tracker/internal/worker/proto"

	"github.com/jackc/pgx/v5"
	"github.com/pashagolub/pgxmock/v3"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestGRPC_GetCVE_Success(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create pgxmock pool: %v", err)
	}
	defer mock.Close()

	server := &CVEServiceServerImpl{Pool: mock}

	cveID := "CVE-2026-12345"
	mock.ExpectQuery(`SELECT id, cve_id, description, COALESCE\(cvss_score, 0\), published_date FROM cves WHERE cve_id = \$1`).
		WithArgs(cveID).
		WillReturnRows(pgxmock.NewRows([]string{"id", "cve_id", "description", "cvss_score", "published_date"}).
			AddRow(int32(42), cveID, "Test description", 8.8, "2026-05-22"))

	resp, err := server.GetCVE(context.Background(), &proto.CVERequest{CveId: cveID})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.Id != 42 {
		t.Errorf("expected ID 42, got %d", resp.Id)
	}
	if resp.CveId != cveID {
		t.Errorf("expected CVE ID %s, got %s", cveID, resp.CveId)
	}
	if resp.Description != "Test description" {
		t.Errorf("expected description 'Test description', got %s", resp.Description)
	}
	if resp.CvssScore != 8.8 {
		t.Errorf("expected CVSS score 8.8, got %f", resp.CvssScore)
	}
	if resp.PublishedDate != "2026-05-22" {
		t.Errorf("expected published date '2026-05-22', got %s", resp.PublishedDate)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestGRPC_GetCVE_NotFound(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create pgxmock pool: %v", err)
	}
	defer mock.Close()

	server := &CVEServiceServerImpl{Pool: mock}

	cveID := "CVE-NOT-FOUND"
	mock.ExpectQuery(`SELECT id, cve_id, description, COALESCE\(cvss_score, 0\), published_date FROM cves WHERE cve_id = \$1`).
		WithArgs(cveID).
		WillReturnError(pgx.ErrNoRows)

	_, err = server.GetCVE(context.Background(), &proto.CVERequest{CveId: cveID})
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got: %v", err)
	}

	if st.Code() != codes.NotFound {
		t.Errorf("expected status code NotFound, got %s", st.Code())
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestGRPC_GetCVE_EmptyInput(t *testing.T) {
	server := &CVEServiceServerImpl{Pool: nil}
	_, err := server.GetCVE(context.Background(), &proto.CVERequest{CveId: ""})
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got: %v", err)
	}

	if st.Code() != codes.InvalidArgument {
		t.Errorf("expected status code InvalidArgument, got %s", st.Code())
	}
}
