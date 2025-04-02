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
// limitations under the License.package s2s

package s2s

import (
	"bytes"
	"testing"
)

// createFixedSizeBytes creates a byte slice of the specified size with the given content
func createFixedSizeBytes(content string, size int) []byte {
	result := make([]byte, size)
	copy(result, content)
	return result
}

func TestWriteSignature(t *testing.T) {
	tests := []struct {
		name          string
		endpoint      string
		wantErr       bool
		wantSignature []byte
	}{
		{
			name:     "basic signature",
			endpoint: "test-server:8089",
			wantErr:  false,
			wantSignature: bytes.Join([][]byte{
				createFixedSizeBytes("--splunk-cooked-mode-v2--", 128),
				createFixedSizeBytes("test-server", 256),
				createFixedSizeBytes("8089", 16),
			}, nil),
		},
		{
			name:     "empty server name",
			endpoint: "",
			wantErr:  true,
		},
		{
			name:     "zero port",
			endpoint: "test-server:0",
			wantErr:  false,
			wantSignature: bytes.Join([][]byte{
				createFixedSizeBytes("--splunk-cooked-mode-v2--", 128),
				createFixedSizeBytes("test-server", 256),
				createFixedSizeBytes("0", 16),
			}, nil),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := writeSignature(&buf, tt.endpoint)

			if tt.wantErr {
				if err == nil {
					t.Error("writeSignature() error = nil, wantErr true")
				}
				return
			}
			if err != nil {
				t.Errorf("writeSignature() error = %v, wantErr %v", err, false)
				return
			}

			got := buf.Bytes()
			wantLen := 128 + 256 + 16
			if len(got) != wantLen {
				t.Errorf("writeSignature() length = %v, want %v", len(got), wantLen)
				return
			}
			if !bytes.Equal(got, tt.wantSignature) {
				t.Errorf("writeSignature() = %v, want %v", got, tt.wantSignature)
			}
		})
	}
}
