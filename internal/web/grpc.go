package web

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"

	"cve-tracker/internal/db"
	"cve-tracker/internal/worker/proto"

	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

// CVEServiceServerImpl implements proto.CVEServiceServer
type CVEServiceServerImpl struct {
	proto.UnimplementedCVEServiceServer
	Pool db.DBPool
}

// GetCVE retrieves a single CVE from the database by its cve_id.
func (s *CVEServiceServerImpl) GetCVE(ctx context.Context, req *proto.CVERequest) (*proto.CVEResponse, error) {
	if req.GetCveId() == "" {
		return nil, status.Error(codes.InvalidArgument, "cve_id cannot be empty")
	}

	var id int32
	var cveID string
	var description string
	var cvssScore float64
	var publishedDate string

	err := s.Pool.QueryRow(ctx, `
		SELECT id, cve_id, description, COALESCE(cvss_score, 0), published_date
		FROM cves
		WHERE cve_id = $1
	`, req.GetCveId()).Scan(&id, &cveID, &description, &cvssScore, &publishedDate)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, status.Errorf(codes.NotFound, "CVE %s not found", req.GetCveId())
		}
		log.Printf("gRPC GetCVE database error: %v", err)
		return nil, status.Error(codes.Internal, "Internal database error")
	}

	return &proto.CVEResponse{
		Id:            id,
		CveId:         cveID,
		Description:   description,
		CvssScore:     cvssScore,
		PublishedDate: publishedDate,
	}, nil
}

// StartGRPCServer initializes and runs a secure or plaintext gRPC server.
func StartGRPCServer(pool db.DBPool, port string, certFile, keyFile string) (*grpc.Server, error) {
	lis, err := net.Listen("tcp", ":"+port)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on gRPC port %s: %w", port, err)
	}

	var opts []grpc.ServerOption
	if certFile != "" && keyFile != "" {
		creds, err := credentials.NewServerTLSFromFile(certFile, keyFile)
		if err != nil {
			_ = lis.Close()
			return nil, fmt.Errorf("failed to load TLS keys: %w", err)
		}
		opts = append(opts, grpc.Creds(creds))
		log.Printf("Starting secure gRPC server on port %s (TLS enabled)", port)
	} else {
		log.Printf("Starting insecure gRPC server on port %s (TLS disabled)", port)
	}

	grpcServer := grpc.NewServer(opts...)
	proto.RegisterCVEServiceServer(grpcServer, &CVEServiceServerImpl{Pool: pool})

	go func() {
		if err := grpcServer.Serve(lis); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			log.Printf("gRPC server error: %v", err)
		}
	}()

	return grpcServer, nil
}
