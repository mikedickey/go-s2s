// ------------------------------------------------------------------
// Splunk-to-Splunk Protocol Utility
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

package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/mikedickey/go-s2s/pkg/s2s"
)

var (
	flagVersion     bool
	flagEndpoint    string
	flagFile        string
	flagTLS         bool
	flagCert        string
	flagServerName  string
	flagInsecureTLS bool
	flagServerMode  bool
	flagKeyFile     string
	flagIndex       string
	flagHost        string
	flagSource      string
	flagSourceType  string
)

// isConnectionError returns true if the error indicates a broken connection
func isConnectionError(err error) bool {
	if err == nil {
		return false
	}

	// Check for common connection errors
	if errors.Is(err, io.EOF) ||
		errors.Is(err, net.ErrClosed) ||
		errors.Is(err, io.ErrClosedPipe) {
		return true
	}

	// Check for "broken pipe" error message
	if strings.Contains(err.Error(), "write: broken pipe") {
		return true
	}

	return false
}

func main() {
	// process command line args
	flag.BoolVar(&flagVersion, "version", false, "display current version")
	flag.StringVar(&flagEndpoint, "endpoint", "localhost:9997", "S2S server endpoint (host:port)")
	flag.StringVar(&flagFile, "file", "", "log file to send")
	flag.BoolVar(&flagTLS, "tls", false, "enable TLS connection")
	flag.StringVar(&flagCert, "cert", "", "path to client certificate for TLS (optional)")
	flag.StringVar(&flagServerName, "server-name", "", "server name for TLS verification")
	flag.BoolVar(&flagInsecureTLS, "insecure", false, "skip TLS certificate verification")
	flag.BoolVar(&flagServerMode, "server", false, "run in server mode (listen for incoming connections)")
	flag.StringVar(&flagKeyFile, "key", "", "path to private key file for TLS server mode")
	flag.StringVar(&flagIndex, "index", "", "index to send events to")
	flag.StringVar(&flagHost, "host", "", "host value for events")
	flag.StringVar(&flagSource, "source", "", "source value for events")
	flag.StringVar(&flagSourceType, "sourcetype", "", "sourcetype value for events")
	flag.Parse()

	if flagVersion {
		fmt.Printf("s2s version %s\n", s2s.VersionString())
		return
	}

	if !strings.Contains(flagEndpoint, ":") {
		// default to port 9997
		flagEndpoint = flagEndpoint + ":9997"
	}

	if flagServerMode {
		if flagTLS && (flagCert == "" || flagKeyFile == "") {
			log.Fatal("Both -cert and -key must be specified when using TLS in server mode")
		}

		var server *s2s.Server
		if flagTLS {
			server = s2s.NewTLSServer(flagEndpoint, flagCert, flagKeyFile, flagInsecureTLS)
		} else {
			server = s2s.NewServer(flagEndpoint)
		}

		if err := server.Start(); err != nil {
			log.Fatalf("Failed to start S2S server: %v", err)
		}

		fmt.Printf("S2S server listening on %s\n", flagEndpoint)
		if flagTLS {
			fmt.Println("TLS enabled")
		}

		// Wait for Ctrl+C
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

		if err := server.Stop(); err != nil {
			log.Printf("Error stopping S2S server: %v", err)
		}
		return
	}

	if flagFile == "" {
		log.Fatal("Please specify a log file using -file")
	}

	if flagSource == "" {
		// default to log file name
		flagSource = flagFile
	}

	// Open the log file
	file, err := os.Open(flagFile)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}
	defer file.Close()

	// Create S2S connection
	var conn *s2s.Conn
	if flagTLS {
		conn, err = s2s.ConnectTLS(flagEndpoint, flagCert, flagServerName, flagInsecureTLS)
	} else {
		conn, err = s2s.Connect(flagEndpoint)
	}
	if err != nil {
		log.Fatalf("Failed to create S2S connection: %v", err)
	}
	defer conn.Close()

	// Read and send events
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		event := &s2s.Event{
			Raw:        scanner.Text(),
			Index:      flagIndex,
			Host:       flagHost,
			Source:     flagSource,
			SourceType: flagSourceType,
		}
		if err := conn.SendEvent(event); err != nil {
			if isConnectionError(err) {
				log.Printf("Connection lost: %v", err)
				return
			}
			log.Printf("Failed to send event: %v", err)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Printf("Error reading log file: %v", err)
	}
}
