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
	"errors"
	"io"
	"testing"
)

func TestEncodeString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []byte
	}{
		{
			name:     "empty string",
			input:    "",
			expected: []byte{0, 0, 0, 1, 0},
		},
		{
			name:     "simple string",
			input:    "hello",
			expected: []byte{0, 0, 0, 6, 'h', 'e', 'l', 'l', 'o', 0},
		},
		{
			name:     "string with spaces",
			input:    "hello world",
			expected: []byte{0, 0, 0, 12, 'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd', 0},
		},
		{
			name:     "unicode string",
			input:    "Hello 世界 🌍",
			expected: []byte{0, 0, 0, 18, 'H', 'e', 'l', 'l', 'o', ' ', 0xe4, 0xb8, 0x96, 0xe7, 0x95, 0x8c, ' ', 0xf0, 0x9f, 0x8c, 0x8d, 0},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := EncodeString(&buf, tt.input); err != nil {
				t.Errorf("EncodeString() error = %v", err)
				return
			}
			got := buf.Bytes()
			if len(got) != len(tt.expected) {
				t.Errorf("EncodeString() length = %v, want %v", len(got), len(tt.expected))
				return
			}
			if !bytes.Equal(got, tt.expected) {
				t.Errorf("EncodeString() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestDecodeString(t *testing.T) {
	tests := []struct {
		name        string
		input       []byte
		want        string
		wantErr     bool
		errContains string
	}{
		{
			name:    "empty string",
			input:   []byte{0, 0, 0, 1, 0},
			want:    "",
			wantErr: false,
		},
		{
			name:    "simple string",
			input:   []byte{0, 0, 0, 6, 'h', 'e', 'l', 'l', 'o', 0},
			want:    "hello",
			wantErr: false,
		},
		{
			name:    "unicode string",
			input:   []byte{0, 0, 0, 18, 'H', 'e', 'l', 'l', 'o', ' ', 0xe4, 0xb8, 0x96, 0xe7, 0x95, 0x8c, ' ', 0xf0, 0x9f, 0x8c, 0x8d, 0},
			want:    "Hello 世界 🌍",
			wantErr: false,
		},
		{
			name:        "too short",
			input:       []byte{0, 0, 0, 1}, // length=1 but no data
			want:        "",
			wantErr:     true,
			errContains: "EOF",
		},
		{
			name:        "missing null terminator",
			input:       []byte{0, 0, 0, 2, 'a'}, // length=2 but no null terminator
			want:        "",
			wantErr:     true,
			errContains: "EOF",
		},
		{
			name:        "length mismatch",
			input:       []byte{0, 0, 0, 3, 'a', 0}, // length=3 but only 1 byte of data
			want:        "",
			wantErr:     true,
			errContains: "EOF",
		},
		{
			name:        "invalid null terminator",
			input:       []byte{0, 0, 0, 2, 'a', 'b'}, // length=2 but wrong null terminator
			want:        "",
			wantErr:     true,
			errContains: "invalid data format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DecodeString(bytes.NewReader(tt.input))
			if tt.wantErr {
				if err == nil {
					t.Error("DecodeString() error = nil, wantErr true")
				}
				if tt.errContains != "" {
					if tt.errContains == "EOF" {
						if !errors.Is(err, io.EOF) {
							t.Errorf("DecodeString() error = %v, want EOF", err)
						}
					} else if tt.errContains == "invalid data format" {
						if !errors.Is(err, ErrInvalidData) {
							t.Errorf("DecodeString() error = %v, want invalid data format", err)
						}
					}
				}
				return
			}
			if err != nil {
				t.Errorf("DecodeString() error = %v, wantErr false", err)
				return
			}
			if got != tt.want {
				t.Errorf("DecodeString() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEncodeKeyValue(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		value    string
		expected []byte
	}{
		{
			name:     "empty key and value",
			key:      "",
			value:    "",
			expected: []byte{0, 0, 0, 1, 0, 0, 0, 0, 1, 0},
		},
		{
			name:     "simple key-value",
			key:      "name",
			value:    "John",
			expected: []byte{0, 0, 0, 5, 'n', 'a', 'm', 'e', 0, 0, 0, 0, 5, 'J', 'o', 'h', 'n', 0},
		},
		{
			name:     "unicode key-value",
			key:      "名前",
			value:    "世界",
			expected: []byte{0, 0, 0, 7, 0xe5, 0x90, 0x8d, 0xe5, 0x89, 0x8d, 0, 0, 0, 0, 7, 0xe4, 0xb8, 0x96, 0xe7, 0x95, 0x8c, 0},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := EncodeKeyValue(&buf, tt.key, tt.value); err != nil {
				t.Errorf("EncodeKeyValue() error = %v", err)
				return
			}
			got := buf.Bytes()
			if len(got) != len(tt.expected) {
				t.Errorf("EncodeKeyValue() length = %v, want %v", len(got), len(tt.expected))
				return
			}
			if !bytes.Equal(got, tt.expected) {
				t.Errorf("EncodeKeyValue() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestDecodeKeyValue(t *testing.T) {
	tests := []struct {
		name        string
		input       []byte
		wantKey     string
		wantValue   string
		wantErr     bool
		errContains string
	}{
		{
			name:      "empty key and value",
			input:     []byte{0, 0, 0, 1, 0, 0, 0, 0, 1, 0},
			wantKey:   "",
			wantValue: "",
			wantErr:   false,
		},
		{
			name:      "simple key-value",
			input:     []byte{0, 0, 0, 5, 'n', 'a', 'm', 'e', 0, 0, 0, 0, 5, 'J', 'o', 'h', 'n', 0},
			wantKey:   "name",
			wantValue: "John",
			wantErr:   false,
		},
		{
			name:      "unicode key-value",
			input:     []byte{0, 0, 0, 7, 0xe5, 0x90, 0x8d, 0xe5, 0x89, 0x8d, 0, 0, 0, 0, 7, 0xe4, 0xb8, 0x96, 0xe7, 0x95, 0x8c, 0},
			wantKey:   "名前",
			wantValue: "世界",
			wantErr:   false,
		},
		{
			name:        "incomplete key",
			input:       []byte{0, 0, 0, 2}, // length=2 but no data
			wantKey:     "",
			wantValue:   "",
			wantErr:     true,
			errContains: "EOF",
		},
		{
			name:        "incomplete value",
			input:       []byte{0, 0, 0, 2, 'a', 0, 0, 0, 1}, // complete key, incomplete value
			wantKey:     "",
			wantValue:   "",
			wantErr:     true,
			errContains: "unexpected EOF",
		},
		{
			name:        "invalid null terminator in key",
			input:       []byte{0, 0, 0, 2, 'a', 'b', 0, 0, 0, 2, 'c', 0}, // wrong null terminator in key
			wantKey:     "",
			wantValue:   "",
			wantErr:     true,
			errContains: "invalid data format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var key, value string
			err := DecodeKeyValue(bytes.NewReader(tt.input), &key, &value)
			if tt.wantErr {
				if err == nil {
					t.Error("DecodeKeyValue() error = nil, wantErr true")
				}
				if tt.errContains != "" && tt.errContains != err.Error() {
					t.Errorf("DecodeKeyValue() error = %v, want %v", err, tt.errContains)
				}
				return
			}
			if err != nil {
				t.Errorf("DecodeKeyValue() error = %v, wantErr false", err)
				return
			}
			if key != tt.wantKey {
				t.Errorf("DecodeKeyValue() key = %v, want %v", key, tt.wantKey)
			}
			if value != tt.wantValue {
				t.Errorf("DecodeKeyValue() value = %v, want %v", value, tt.wantValue)
			}
		})
	}
}

func TestEncodeEvent(t *testing.T) {
	tests := []struct {
		name     string
		event    *Event
		wantErr  bool
		validate func([]byte) error
	}{
		{
			name: "minimal event",
			event: &Event{
				Index:  "main",
				Raw:    "test event",
				Fields: make(map[string]string),
			},
			wantErr: false,
			validate: func(data []byte) error {
				// Verify size and maps count (first 8 bytes)
				if len(data) < 8 {
					return errors.New("data too short")
				}
				// Verify presence of required fields
				if !bytes.Contains(data, []byte("_MetaData:Index")) {
					return errors.New("missing _MetaData:Index")
				}
				if !bytes.Contains(data, []byte("_done")) {
					return errors.New("missing _done")
				}
				if !bytes.Contains(data, []byte("_raw")) {
					return errors.New("missing _raw")
				}
				return nil
			},
		},
		{
			name: "full event",
			event: &Event{
				Index:      "main",
				Host:       "testhost",
				Source:     "testsource",
				SourceType: "test:sourcetype",
				Raw:        "full test event",
				Fields: map[string]string{
					"custom_field": "custom_value",
				},
			},
			wantErr: false,
			validate: func(data []byte) error {
				if !bytes.Contains(data, []byte("MetaData:Host")) {
					return errors.New("missing MetaData:Host")
				}
				if !bytes.Contains(data, []byte("MetaData:Source")) {
					return errors.New("missing MetaData:Source")
				}
				if !bytes.Contains(data, []byte("MetaData:Sourcetype")) {
					return errors.New("missing MetaData:Sourcetype")
				}
				if !bytes.Contains(data, []byte("custom_field")) {
					return errors.New("missing custom field")
				}
				return nil
			},
		},
		{
			name: "event with unicode",
			event: &Event{
				Index: "main",
				Host:  "世界",
				Raw:   "🌍 test event",
				Fields: map[string]string{
					"unicode_field": "测试",
				},
			},
			wantErr: false,
			validate: func(data []byte) error {
				if !bytes.Contains(data, []byte("世界")) {
					return errors.New("missing unicode host")
				}
				if !bytes.Contains(data, []byte("测试")) {
					return errors.New("missing unicode field value")
				}
				return nil
			},
		},
		{
			name:    "nil event",
			event:   nil,
			wantErr: true,
		},
		{
			name: "empty index",
			event: &Event{
				Raw:    "test event",
				Fields: make(map[string]string),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := EncodeEvent(&buf, tt.event)

			if tt.wantErr {
				if err == nil {
					t.Error("EncodeEvent() error = nil, wantErr true")
				}
				return
			}

			if err != nil {
				t.Errorf("EncodeEvent() error = %v, wantErr false", err)
				return
			}

			// Get the encoded data
			data := buf.Bytes()

			// Verify the data is not empty
			if len(data) == 0 {
				t.Error("EncodeEvent() produced empty output")
				return
			}

			// Verify message size
			size, _ := getHeaderValues(tt.event)
			if size+4 != uint32(len(data)) {
				t.Errorf("EncodeEvent() header message size = %v, want %v", size, len(data))
			}

			// Run custom validation if provided
			if tt.validate != nil {
				if err := tt.validate(data); err != nil {
					t.Errorf("validation failed: %v", err)
				}
			}
		})
	}
}

// TestEncodeEventRoundTrip tests that an event can be encoded and then decoded correctly
func TestEncodeEventRoundTrip(t *testing.T) {
	original := &Event{
		Index:      "main",
		Host:       "testhost",
		Source:     "testsource",
		SourceType: "test:sourcetype",
		Raw:        "test event data",
		Fields: map[string]string{
			"field1": "value1",
			"field2": "value2",
		},
	}

	// Encode the event
	var buf bytes.Buffer
	if err := EncodeEvent(&buf, original); err != nil {
		t.Fatalf("EncodeEvent() error = %v", err)
	}

	// Decode the event
	decoded := &Event{}
	err := DecodeEvent(bytes.NewReader(buf.Bytes()), decoded)
	if err != nil {
		t.Fatalf("DecodeEvent() error = %v", err)
	}

	// Compare the events
	if decoded.Index != original.Index {
		t.Errorf("Index = %v, want %v", decoded.Index, original.Index)
	}
	if decoded.Host != original.Host {
		t.Errorf("Host = %v, want %v", decoded.Host, original.Host)
	}
	if decoded.Source != original.Source {
		t.Errorf("Source = %v, want %v", decoded.Source, original.Source)
	}
	if decoded.SourceType != original.SourceType {
		t.Errorf("SourceType = %v, want %v", decoded.SourceType, original.SourceType)
	}
	if decoded.Raw != original.Raw {
		t.Errorf("Raw = %v, want %v", decoded.Raw, original.Raw)
	}

	// Compare fields
	if len(decoded.Fields) != len(original.Fields) {
		t.Errorf("Fields length = %v, want %v", len(decoded.Fields), len(original.Fields))
	}
	for k, v := range original.Fields {
		if decoded.Fields[k] != v {
			t.Errorf("Fields[%v] = %v, want %v", k, decoded.Fields[k], v)
		}
	}
}
