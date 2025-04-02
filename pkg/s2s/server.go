// ------------------------------------------------------------------
// Splunk-to-Splunk Protocol Library
// ------------------------------------------------------------------
// Copyright (c) 2025 Mike Dickey
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

package s2s

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
)

// Server represents a Splunk-to-Splunk server that can accept connections
type Server struct {
	Endpoint    string
	Encrypted   bool
	CertFile    string
	KeyFile     string
	InsecureTLS bool
	listener    net.Listener
	stopChan    chan struct{}
}

// NewServer creates a new unencrypted Splunk-to-Splunk server
func NewServer(endpoint string) *Server {
	return &Server{
		Endpoint:  endpoint,
		Encrypted: false,
		stopChan:  make(chan struct{}),
	}
}

// NewTLSServer creates a new TLS-enabled Splunk-to-Splunk server
func NewTLSServer(endpoint, certFile, keyFile string, insecureTLS bool) *Server {
	return &Server{
		Endpoint:    endpoint,
		Encrypted:   true,
		CertFile:    certFile,
		KeyFile:     keyFile,
		InsecureTLS: insecureTLS,
		stopChan:    make(chan struct{}),
	}
}

// Start starts the server and begins accepting connections
func (s *Server) Start() error {
	var err error
	if s.Encrypted {
		cert, err := tls.LoadX509KeyPair(s.CertFile, s.KeyFile)
		if err != nil {
			return fmt.Errorf("failed to load TLS certificate: %v", err)
		}

		config := &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
		if s.InsecureTLS {
			config.InsecureSkipVerify = true
		}

		s.listener, err = tls.Listen("tcp", s.Endpoint, config)
	} else {
		s.listener, err = net.Listen("tcp", s.Endpoint)
	}

	if err != nil {
		return fmt.Errorf("failed to start server: %v", err)
	}

	go s.acceptConnections()

	return nil
}

// Stop stops the server and closes all connections
func (s *Server) Stop() error {
	close(s.stopChan)
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

// acceptConnections handles incoming connections
func (s *Server) acceptConnections() {
	for {
		select {
		case <-s.stopChan:
			return
		default:
			conn, err := s.listener.Accept()
			if err != nil {
				if !errors.Is(err, net.ErrClosed) {
					log.Printf("Error accepting connection: %v", err)
				}
				continue
			}

			go s.handleConnection(conn)
		}
	}
}

// handleConnection processes a single client connection
func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()

	// Read and verify signature
	signature := make([]byte, 128)
	if _, err := io.ReadFull(conn, signature); err != nil {
		log.Printf("Failed to read signature: %v", err)
		return
	}

	// The signature includes null padding, so we need to trim it before comparing
	sigStr := strings.TrimRight(string(signature), "\x00")
	if sigStr != "--splunk-cooked-mode-v2--" {
		log.Printf("Invalid signature received: %q", sigStr)
		return
	}

	// Read server name and management port (we don't use these)
	serverName := make([]byte, 256)
	mgmtPort := make([]byte, 16)
	if _, err := io.ReadFull(conn, serverName); err != nil {
		log.Printf("Failed to read server name: %v", err)
		return
	}
	if _, err := io.ReadFull(conn, mgmtPort); err != nil {
		log.Printf("Failed to read management port: %v", err)
		return
	}

	// Read events until connection is closed
	for {
		event := &Event{}
		if err := event.Read(conn); err != nil {
			if err != io.EOF {
				log.Printf("Error reading event: %v", err)
			}
			return
		}
		fmt.Printf("Received event: %s\n", event.String())
	}
}
