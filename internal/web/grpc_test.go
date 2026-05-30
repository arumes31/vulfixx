package web

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"testing"
	"time"

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

func TestGRPC_GetCVE_DatabaseError(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create pgxmock pool: %v", err)
	}
	defer mock.Close()

	server := &CVEServiceServerImpl{Pool: mock}

	cveID := "CVE-ERROR"
	mock.ExpectQuery(`SELECT id, cve_id, description, COALESCE\(cvss_score, 0\), published_date FROM cves WHERE cve_id = \$1`).
		WithArgs(cveID).
		WillReturnError(fmt.Errorf("db error"))

	_, err = server.GetCVE(context.Background(), &proto.CVERequest{CveId: cveID})
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got: %v", err)
	}

	if st.Code() != codes.Internal {
		t.Errorf("expected status code Internal, got %s", st.Code())
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

func TestGRPC_StartServer(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create pgxmock pool: %v", err)
	}
	defer mock.Close()

	// Insecure server start
	srv, err := StartGRPCServer(mock, "0", "", "")
	if err != nil {
		t.Fatalf("failed to start gRPC server: %v", err)
	}
	if srv == nil {
		t.Fatal("expected non-nil gRPC server")
	}
	srv.GracefulStop()

	// Secure server start (should fail with invalid cert paths)
	_, err = StartGRPCServer(mock, "0", "nonexistent_cert.pem", "nonexistent_key.pem")
	if err == nil {
		t.Fatal("expected error starting secure gRPC server with missing cert files")
	}
}

func TestGRPC_StartServer_ListenError(t *testing.T) {
	mock, _ := pgxmock.NewPool()
	// Pass an invalid port to trigger net.Listen error
	_, err := StartGRPCServer(mock, "-1", "", "")
	if err == nil {
		t.Fatal("expected error with invalid port")
	}
}

func TestGRPC_StartServer_Secure_Success(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create pgxmock pool: %v", err)
	}
	defer mock.Close()

	certFile, keyFile, cleanup := generateTestCertFiles(t)
	defer cleanup()

	srv, err := StartGRPCServer(mock, "0", certFile, keyFile)
	if err != nil {
		t.Fatalf("failed to start secure gRPC server: %v", err)
	}
	if srv == nil {
		t.Fatal("expected non-nil gRPC server")
	}
	srv.GracefulStop()
}

func generateTestCertFiles(t *testing.T) (string, string, func()) {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		t.Fatalf("failed to generate serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Test Co"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	certOut, err := os.CreateTemp("", "cert.pem")
	if err != nil {
		t.Fatalf("failed to open cert.pem for writing: %v", err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		t.Fatalf("failed to write data to cert.pem: %v", err)
	}
	certOut.Close()

	keyOut, err := os.CreateTemp("", "key.pem")
	if err != nil {
		t.Fatalf("failed to open key.pem for writing: %v", err)
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("unable to marshal private key: %v", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		t.Fatalf("failed to write data to key.pem: %v", err)
	}
	keyOut.Close()

	cleanup := func() {
		os.Remove(certOut.Name())
		os.Remove(keyOut.Name())
	}

	return certOut.Name(), keyOut.Name(), cleanup
}
