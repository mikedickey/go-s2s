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
	"fmt"
	"io"
	"strings"
	"time"
)

// Message may used for control or data, with Raw containing one or more events.
type Message struct {
	Index      string
	Host       string
	Source     string
	SourceType string
	Raw        string
	Time       time.Time
	Fields     map[string]string
}

// Clear clears the message.
func (m *Message) Clear() {
	m.Index = ""
	m.Host = ""
	m.Source = ""
	m.SourceType = ""
	m.Raw = ""
	m.Time = time.Time{}
	m.Fields = make(map[string]string)
}

// Read reads the message from a reader.
func (m *Message) Read(r io.Reader) error {
	if m == nil {
		return ErrNilMessage
	}
	m.Clear()
	return DecodeMessage(r, m)
}

// Write writes the message to a writer.
func (m *Message) Write(w io.Writer) error {
	if m == nil {
		return ErrNilMessage
	}
	return EncodeMessage(w, m)
}

// String returns a string representation of the message.
func (m *Message) String() string {
	var sb strings.Builder
	if m.Index != "" {
		sb.WriteString("index=")
		sb.WriteString(m.Index)
		sb.WriteString(" ")
	}
	if m.Host != "" {
		sb.WriteString("host=")
		sb.WriteString(m.Host)
		sb.WriteString(" ")
	}
	if m.Source != "" {
		sb.WriteString("source=")
		sb.WriteString(m.Source)
		sb.WriteString(" ")
	}
	if m.SourceType != "" {
		sb.WriteString("sourcetype=")
		sb.WriteString(m.SourceType)
		sb.WriteString(" ")
	}
	for k, v := range m.Fields {
		if k != "" {
			sb.WriteString(k)
			sb.WriteString("=")
			sb.WriteString(v)
			sb.WriteString(" ")
		}
	}
	if !m.Time.IsZero() {
		sb.WriteString("_time=")
		sb.WriteString(fmt.Sprintf("%d", m.Time.Unix()))
		sb.WriteString(" ")
	}
	if m.Raw != "" {
		sb.WriteString("_raw=")
		sb.WriteString(m.Raw)
		sb.WriteString(" ")
	}
	return strings.TrimSpace(sb.String())
}
