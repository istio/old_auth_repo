// Copyright 2017 Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package grpc

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/golang/glog"

	"golang.org/x/net/context"

	"istio.io/auth/pkg/pki/ca"
	pb "istio.io/auth/proto"
)

const certExpirationBuffer = time.Minute

// Server implements pb.IstioCAService and provides the service on the
// specified port.
type Server struct {
	ca          ca.CertificateAuthority
	certificate *tls.Certificate
	hostname    string
	port        int
}

// HandleCSR handles an incoming certificate signing request (CSR). It does
// proper validation (e.g. authentication) and upon validated, signs the CSR
// and returns the resulting certificate. If not approved, reason for refusal
// to sign is returned as part of the response object.
func (s *Server) HandleCSR(ctx context.Context, request *pb.Request) (*pb.Response, error) {
	// TODO: handle authentication here

	cert, err := s.ca.Sign(request.CsrPem)
	if err != nil {
		glog.Error(err)
		// TODO: possibly wrap err in GRPC error
		return nil, err
	}

	response := &pb.Response{
		IsApproved:      true,
		SignedCertChain: cert,
	}

	return response, nil
}

// Run starts a GRPC server on the specified port.
func (s *Server) Run() error {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", s.port))
	if err != nil {
		return fmt.Errorf("cannot listen on port %d (error: %v)", s.port, err)
	}

	serverOption := s.createTLSServerOption()

	grpcServer := grpc.NewServer(serverOption)
	pb.RegisterIstioCAServiceServer(grpcServer, s)

	// grpcServer.Serve() is a blocking call, so run it in a goroutine.
	go func() {
		glog.Infof("Starting GRPC server on port %d", s.port)

		err := grpcServer.Serve(listener)

		// grpcServer.Serve() always returns a non-nil error.
		glog.Warningf("GRPC server returns an error: %v", err)
	}()

	return nil
}

// New creates a new instance of `IstioCAServiceServer`.
func New(ca ca.CertificateAuthority, hostname string, port int) *Server {
	return &Server{
		ca:       ca,
		hostname: hostname,
		port:     port,
	}
}

func (s *Server) createTLSServerOption() grpc.ServerOption {
	config := &tls.Config{
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			if s.certificate == nil || shouldRefresh(s.certificate) {
				// Apply new certificate if there isn't one yet, or the one has become invalid.
				newCert, err := s.applyServerCertificate()
				if err != nil {
					return nil, err
				}
				s.certificate = newCert
			}
			return s.certificate, nil
		},
	}
	return grpc.Creds(credentials.NewTLS(config))
}

func (s *Server) applyServerCertificate() (*tls.Certificate, error) {
	opts := ca.CertOptions{
		Host:       s.hostname,
		RSAKeySize: 2048,
	}

	csrPEM, privPEM, err := ca.GenCSR(opts)
	if err != nil {
		return nil, err
	}

	certPEM, err := s.ca.Sign(csrPEM)
	if err != nil {
		return nil, err
	}

	cert, err := tls.X509KeyPair(certPEM, privPEM)
	if err != nil {
		return nil, err
	}
	return &cert, nil
}

// shouldRefresh indicates whether the given certificate should be refreshed.
func shouldRefresh(cert *tls.Certificate) bool {
	// Check whether there is a valid leaf certificate.
	leaf := cert.Leaf
	if leaf == nil {
		return true
	}

	// Check whether the leaf certificate is about to expire.
	return leaf.NotAfter.Add(-certExpirationBuffer).Before(time.Now())
}