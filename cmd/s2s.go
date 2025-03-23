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
// limitations under the License.

package main

import (
	"flag"
	"fmt"

	"github.com/mikedickey/go-s2s/pkg/s2s"
)

var (
	flagVersion bool
)

func main() {
	// process command line args
	flag.BoolVar(&flagVersion, "version", false, "display current version")
	flag.Parse()

	if flagVersion {
		fmt.Printf("s2s version %s\n", s2s.VersionString())
	}
}
