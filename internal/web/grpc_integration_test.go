package web

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"cve-tracker/internal/worker/proto"
	"github.com/pashagolub/pgxmock/v3"
)

func generateCerts() (string, string, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Co"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return "", "", err
	}

	certFile, err := os.CreateTemp("", "cert-*.pem")
	if err != nil {
		return "", "", err
	}
	pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certFile.Close()

	keyFile, err := os.CreateTemp("", "key-*.pem")
	if err != nil {
		return "", "", err
	}
	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return "", "", err
	}
	pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})
	keyFile.Close()

	return certFile.Name(), keyFile.Name(), nil
}

func getFreePort() (string, error) {
	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		return "", err
	}
	port := strconv.Itoa(l.Addr().(*net.TCPAddr).Port)
	l.Close()
	return port, nil
}

func TestStartGRPCServer_Integration(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create pgxmock pool: %v", err)
	}
	defer mock.Close()

	t.Run("Insecure Server", func(t *testing.T) {
		port, err := getFreePort()
		if err != nil {
			t.Fatalf("failed to get free port: %v", err)
		}

		srv, err := StartGRPCServer(mock, port, "", "")
		if err != nil {
			t.Fatalf("failed to start insecure server: %v", err)
		}
		defer srv.GracefulStop()

		// Give the server a moment to start
		time.Sleep(100 * time.Millisecond)

		conn, err := grpc.NewClient("localhost:"+port, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			t.Fatalf("failed to connect to insecure server: %v", err)
		}
		defer conn.Close()

		client := proto.NewCVEServiceClient(conn)
		_, err = client.GetCVE(context.Background(), &proto.CVERequest{CveId: ""})
		if err == nil {
			t.Error("expected error for empty CVE ID, got nil")
		}
	})

	t.Run("Secure Server", func(t *testing.T) {
		certFile, keyFile, err := generateCerts()
		if err != nil {
			t.Fatalf("failed to generate certs: %v", err)
		}
		defer os.Remove(certFile)
		defer os.Remove(keyFile)

		port, err := getFreePort()
		if err != nil {
			t.Fatalf("failed to get free port: %v", err)
		}

		srv, err := StartGRPCServer(mock, port, certFile, keyFile)
		if err != nil {
			t.Fatalf("failed to start secure server: %v", err)
		}
		defer srv.GracefulStop()

		time.Sleep(100 * time.Millisecond)

		tlsCreds := credentials.NewTLS(&tls.Config{InsecureSkipVerify: true})
		conn, err := grpc.NewClient("localhost:"+port, grpc.WithTransportCredentials(tlsCreds))
		if err != nil {
			t.Fatalf("failed to connect to secure server: %v", err)
		}
		defer conn.Close()

		client := proto.NewCVEServiceClient(conn)
		_, err = client.GetCVE(context.Background(), &proto.CVERequest{CveId: ""})
		if err == nil {
			t.Error("expected error for empty CVE ID, got nil")
		}
	})

	t.Run("Invalid Port", func(t *testing.T) {
		_, err := StartGRPCServer(mock, "invalid-port", "", "")
		if err == nil {
			t.Error("expected error starting server on invalid port, got nil")
		}
	})
}
