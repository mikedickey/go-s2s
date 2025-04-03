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

// Event represents an event in the Splunk-to-Splunk protocol.
type Event struct {
	Index      string
	Host       string
	Source     string
	SourceType string
	Raw        string
	Time       time.Time
	Fields     map[string]string
}

// Clear clears the event.
func (e *Event) Clear() {
	e.Index = ""
	e.Host = ""
	e.Source = ""
	e.SourceType = ""
	e.Raw = ""
	e.Time = time.Time{}
	e.Fields = make(map[string]string)
}

// Read reads the event from a reader.
func (e *Event) Read(r io.Reader) error {
	if e == nil {
		return ErrNilEvent
	}
	e.Clear()
	return DecodeEvent(r, e)
}

// Write writes the event to a writer.
func (e *Event) Write(w io.Writer) error {
	if e == nil {
		return ErrNilEvent
	}
	return EncodeEvent(w, e)
}

// String returns a string representation of the event.
func (e *Event) String() string {
	var sb strings.Builder
	if e.Index != "" {
		sb.WriteString("index=")
		sb.WriteString(e.Index)
		sb.WriteString(" ")
	}
	if e.Host != "" {
		sb.WriteString("host=")
		sb.WriteString(e.Host)
		sb.WriteString(" ")
	}
	if e.Source != "" {
		sb.WriteString("source=")
		sb.WriteString(e.Source)
		sb.WriteString(" ")
	}
	if e.SourceType != "" {
		sb.WriteString("sourcetype=")
		sb.WriteString(e.SourceType)
		sb.WriteString(" ")
	}
	for k, v := range e.Fields {
		if k != "" {
			sb.WriteString(k)
			sb.WriteString("=")
			sb.WriteString(v)
			sb.WriteString(" ")
		}
	}
	if !e.Time.IsZero() {
		sb.WriteString("_time=")
		sb.WriteString(fmt.Sprintf("%d", e.Time.Unix()))
		sb.WriteString(" ")
	}
	if e.Raw != "" {
		sb.WriteString("_raw=")
		sb.WriteString(e.Raw)
		sb.WriteString(" ")
	}
	return strings.TrimSpace(sb.String())
}
