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
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

const (
	ConnectionTimeout = 10 * time.Second
)

var (
	ErrInvalidEndpoint = errors.New("invalid endpoint format")
	ErrTLSCertificate  = errors.New("invalid client certificate")
)

// Conn is a splunk-to-splunk connection
type Conn struct {
	Endpoint     string
	Encrypted    bool
	Version      int
	conn         net.Conn
	didHandshake bool
}

// Connect establishes a new splunk-to-splunk connection
func Connect(endpoint string) (*Conn, error) {
	if !strings.Contains(endpoint, ":") {
		return nil, ErrInvalidEndpoint
	}

	c := &Conn{
		Endpoint:     endpoint,
		Encrypted:    false,
		Version:      3,
		didHandshake: false,
	}
	var err error
	c.conn, err = net.DialTimeout("tcp", endpoint, ConnectionTimeout)
	if err != nil {
		return nil, err
	}

	return c, nil
}

// ConnectTLS establishes a new splunk-to-splunk connection using TLS
func ConnectTLS(endpoint, cert, serverName string, insecureSkipVerify bool) (*Conn, error) {
	if !strings.Contains(endpoint, ":") {
		return nil, ErrInvalidEndpoint
	}

	if serverName == "" {
		serverName = "SplunkServerDefaultCert"
	}

	tlsConfig := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: insecureSkipVerify,
	}

	if len(cert) > 0 {
		certPool := x509.NewCertPool()
		if !certPool.AppendCertsFromPEM([]byte(cert)) {
			return nil, ErrTLSCertificate
		}
		tlsConfig.RootCAs = certPool
	}

	c := &Conn{
		Endpoint:     endpoint,
		Encrypted:    true,
		Version:      3,
		didHandshake: false,
	}
	var err error
	c.conn, err = tls.Dial("tcp", endpoint, tlsConfig)
	if err != nil {
		return nil, err
	}

	return c, nil
}

// Close closes the splunk-to-splunk connection
func (c *Conn) Close() error {
	return c.conn.Close()
}

// SendEvent sends an event to the splunk-to-splunk connection
func (c *Conn) SendEvent(event *Event) error {
	if !c.didHandshake {
		if err := c.doHandshake(); err != nil {
			return err
		}
		c.didHandshake = true
	}

	if err := event.Write(c.conn); err != nil {
		return err
	}

	return nil
}

// doHandshake performs a splunk-to-splunk protocol handshake
func (c *Conn) doHandshake() error {
	// send the signature header
	if err := writeSignature(c.conn, c.Endpoint, c.Version); err != nil {
		return err
	}
	if c.Version < 3 {
		return nil
	}

	// send s2s capabilities to the server
	clientMsg := &Event{
		Fields: map[string]string{
			"__s2s_capabilities": "ack=0;compression=0",
		},
	}
	if err := clientMsg.Write(c.conn); err != nil {
		return fmt.Errorf("s2s v3 handshake failure: %v", err)
	}

	// read the s2s capabilities from the server
	serverMsg := &Event{}
	if err := serverMsg.Read(c.conn); err != nil {
		return fmt.Errorf("s2s v3 handshake failure: %v", err)
	}

	return nil
}

// writeSignature writes a splunk-to-splunk signature to the writer
func writeSignature(w io.Writer, endpoint string, version int) error {
	var signature [128]byte
	var serverName [256]byte
	var mgmtPort [16]byte

	endpointParts := strings.Split(endpoint, ":")
	if len(endpointParts) != 2 {
		return ErrInvalidEndpoint
	}
	copy(signature[:], fmt.Sprintf("--splunk-cooked-mode-v%d--", version))
	copy(serverName[:], endpointParts[0])
	copy(mgmtPort[:], endpointParts[1])

	_, err := w.Write(signature[:])
	if err != nil {
		return err
	}

	_, err = w.Write(serverName[:])
	if err != nil {
		return err
	}

	_, err = w.Write(mgmtPort[:])
	if err != nil {
		return err
	}

	return nil
}
