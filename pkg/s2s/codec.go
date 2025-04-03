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
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

var ErrInvalidData = errors.New("invalid data format")
var ErrNilEvent = errors.New("event is nil")

// EncodeString writes a string to the given writer in the wire protocol format.
// The format is: 4-byte length (big-endian uint32) + string contents + null terminator
func EncodeString(w io.Writer, s string) error {
	// Write length
	if err := binary.Write(w, binary.BigEndian, uint32(len(s)+1)); err != nil {
		return err
	}

	// Write string contents
	if _, err := io.WriteString(w, s); err != nil {
		return err
	}

	// Write null terminator
	if _, err := w.Write([]byte{0}); err != nil {
		return err
	}

	return nil
}

// DecodeString reads a string from the given reader in the wire protocol format.
// The format is: 4-byte length (big-endian uint32) + string contents + null terminator
func DecodeString(r io.Reader) (string, error) {
	// Read length
	var length uint32
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return "", err
	}

	// Read string contents
	buf := make([]byte, length-1)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}

	// Read and verify null terminator
	nullByte := make([]byte, 1)
	if _, err := io.ReadFull(r, nullByte); err != nil {
		return "", err
	}
	if nullByte[0] != 0 {
		return "", ErrInvalidData
	}

	return string(buf), nil
}

// EncodeKeyValue writes a key-value pair to the given writer in the wire protocol format.
func EncodeKeyValue(w io.Writer, key string, value string) error {
	if err := EncodeString(w, key); err != nil {
		return err
	}
	return EncodeString(w, value)
}

// DecodeKeyValue reads a key-value pair from the given reader in the wire protocol format.
func DecodeKeyValue(r io.Reader, key *string, value *string) error {
	var err error
	*key, err = DecodeString(r)
	if err != nil {
		return err
	}
	*value, err = DecodeString(r)
	if err != nil {
		return err
	}
	return nil
}

// EncodeEvent writes an event to the given writer in the wire protocol format.
func EncodeEvent(w io.Writer, e *Event) error {
	if e == nil {
		return ErrNilEvent
	}

	// write size and maps header fields
	size, maps := getHeaderValues(e)
	if err := binary.Write(w, binary.BigEndian, size); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, maps); err != nil {
		return err
	}

	// always write index (even if empty)
	if e.Index != "" {
		if err := EncodeKeyValue(w, "_MetaData:Index", e.Index); err != nil {
			return err
		}
	}

	// write host if present
	if e.Host != "" {
		if err := EncodeKeyValue(w, "MetaData:Host", "host::"+e.Host); err != nil {
			return err
		}
	}

	// write source if present
	if e.Source != "" {
		if err := EncodeKeyValue(w, "MetaData:Source", "source::"+e.Source); err != nil {
			return err
		}
	}

	// write source type if present
	if e.SourceType != "" {
		if err := EncodeKeyValue(w, "MetaData:Sourcetype", "sourcetype::"+e.SourceType); err != nil {
			return err
		}
	}

	// write other fields
	for k, v := range e.Fields {
		if err := EncodeKeyValue(w, k, v); err != nil {
			return err
		}
	}

	// write _time if present
	if !e.Time.IsZero() {
		if err := EncodeKeyValue(w, "_time", fmt.Sprintf("%d", e.Time.Unix())); err != nil {
			return err
		}
	}

	// write _done and _raw
	if err := EncodeKeyValue(w, "_done", "_done"); err != nil {
		return err
	}
	if err := EncodeKeyValue(w, "_raw", e.Raw); err != nil {
		return err
	}

	// write 4 bytes for _raw null padding
	if err := binary.Write(w, binary.BigEndian, uint32(0)); err != nil {
		return err
	}

	// write _raw trailer
	if err := EncodeString(w, "_raw"); err != nil {
		return err
	}

	return nil
}

// DecodeEvent reads an event from the given reader in the wire protocol format.
func DecodeEvent(r io.Reader, e *Event) error {
	if e == nil {
		return ErrNilEvent
	}

	// Read size and maps count
	var size, maps uint32
	if err := binary.Read(r, binary.BigEndian, &size); err != nil {
		return err
	}
	if err := binary.Read(r, binary.BigEndian, &maps); err != nil {
		return err
	}

	// sanity check that Fields are initialized
	if e.Fields == nil {
		e.Fields = make(map[string]string)
	}

	// Read all key-value pairs
	var mapsRead uint32
	for mapsRead < maps {
		var key, value string
		if err := DecodeKeyValue(r, &key, &value); err != nil {
			return err
		}

		// Handle special metadata fields
		switch key {
		case "_MetaData:Index":
			e.Index = value
		case "MetaData:Host":
			if strings.HasPrefix(value, "host::") {
				e.Host = strings.TrimPrefix(value, "host::")
			} else {
				e.Host = value
			}
		case "MetaData:Source":
			if strings.HasPrefix(value, "source::") {
				e.Source = strings.TrimPrefix(value, "source::")
			} else {
				e.Source = value
			}
		case "MetaData:Sourcetype":
			if strings.HasPrefix(value, "sourcetype::") {
				e.SourceType = strings.TrimPrefix(value, "sourcetype::")
			} else {
				e.SourceType = value
			}
		case "_time":
			t, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return ErrInvalidData
			}
			e.Time = time.Unix(t, 0)
		case "_done":
			// Skip _done=_done
		case "_raw":
			e.Raw = value
		default:
			e.Fields[key] = value
		}

		mapsRead++
	}

	// Read and verify _raw null padding (4 bytes)
	var padding uint32
	if err := binary.Read(r, binary.BigEndian, &padding); err != nil {
		return err
	}
	if padding != 0 {
		return ErrInvalidData
	}

	// Read and verify _raw trailer
	trailer, err := DecodeString(r)
	if err != nil {
		return err
	}
	if trailer != "_raw" {
		return ErrInvalidData
	}

	return nil
}

// getHeader returns message size and number of maps
func getHeaderValues(e *Event) (uint32, uint32) {
	if e == nil {
		return 0, 0
	}

	// 4 for size + 1 for null terminator
	const stringOverhead = uint32(5)
	const kvOverhead = stringOverhead + stringOverhead

	// include 4 bytes for number of maps
	size := uint32(4)

	// number of key value pairs
	maps := uint32(0)

	if e.Index != "" {
		// key is "_MetaData:Index"
		size += 15 + uint32(len(e.Index)) + kvOverhead
		maps += 1
	}

	if e.Host != "" {
		// key is "MetaData:Host", value prefix is "host::"
		size += 13 + 6 + uint32(len(e.Host)) + kvOverhead
		maps += 1
	}
	if e.Source != "" {
		// key is "MetaData:Source", value prefix is "source::"
		size += 15 + 8 + uint32(len(e.Source)) + kvOverhead
		maps += 1
	}
	if e.SourceType != "" {
		// key is "MetaData:Sourcetype", value prefix is "sourcetype::"
		size += 19 + 12 + uint32(len(e.SourceType)) + kvOverhead
		maps += 1
	}

	// include other fields
	for k, v := range e.Fields {
		size += uint32(len(k)) + uint32(len(v)) + kvOverhead
		maps += 1
	}

	// _done=_done
	size += 10 + kvOverhead
	maps += 1

	// _raw=<raw>
	size += 4 + uint32(len(e.Raw)) + kvOverhead
	maps += 1

	// extra null padding after _raw
	size += 4

	// "_raw<null>" trailer (includes string size)
	size += 9

	return size, maps
}
