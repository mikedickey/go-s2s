// ------------------------------------------------------------------
// Golang Splunk-to-Splunk Protocol Library
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

import "fmt"

type Event struct {
	Host   string
	Source string
	Index  string
	Time   string
	Event  string
	Fields map[string]interface{}
}

func NewEvent(host, source, index, time, event string, fields map[string]interface{}) *Event {
	return &Event{
		Host:   host,
		Source: source,
		Index:  index,
		Time:   time,
		Event:  event,
		Fields: fields,
	}
}

func (e *Event) String() string {
	return fmt.Sprintf("%s %s %s %s %s %v", e.Host, e.Source, e.Index, e.Time, e.Event, e.Fields)
}
