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
		var cert tls.Certificate
		cert, err = tls.LoadX509KeyPair(s.CertFile, s.KeyFile)
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
	var version int
	sigStr := strings.TrimRight(string(signature), "\x00")
	switch sigStr {
	case "--splunk-cooked-mode-v2--":
		version = 2
	case "--splunk-cooked-mode-v3--":
		version = 3
	default:
		log.Printf("Invalid signature received: %q", sigStr)
		return
	}
	log.Printf("Received v%d connection from %s", version, conn.RemoteAddr())

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

	// Read messages until connection is closed
	for {
		m := &Message{}
		if err := m.Read(conn); err != nil {
			if err != io.EOF {
				log.Printf("Error reading message: %v", err)
			}
			log.Printf("Connection closed from %s", conn.RemoteAddr())
			return
		}
		if len(m.Raw) == 0 {
			// look for v3 control messages
			capabilities, ok := m.Fields["__s2s_capabilities"]
			if ok {
				log.Printf("Received s2s capabilities: %s", capabilities)
				v3Response := &Message{
					Fields: map[string]string{
						// from pcap: "cap_response=success;cap_flush_key=true;idx_can_send_hb=true;idx_can_recv_token=true;request_certificate=true;v4=true;channel_limit=300;pl=7"
						"__s2s_control_msg": "cap_response=success;cap_flush_key=false;idx_can_send_hb=false;idx_can_recv_token=false;request_certificate=false;v4=false;channel_limit=300;pl=7",
					},
				}
				if err := v3Response.Write(conn); err != nil {
					log.Printf("Error sending capabilities response: %v", err)
					return
				}
				continue
			}
		}
		fmt.Printf("Received message: %s\n", m.String())
	}
}
