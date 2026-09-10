/*
Copyright 2025 KeyAuthority.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package http

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

func writeHTTP(w http.ResponseWriter, code int, b []byte) {
	w.WriteHeader(code)
	w.Write(b)
}

func writeHTTPWithHeaders(w http.ResponseWriter, code int, b []byte, headers map[string]string) {
	if len(headers) > 0 {
		for k, v := range headers {
			w.Header().Set(k, v)
		}
	}
	writeHTTP(w, code, b)
}

func writeJSONOk(w http.ResponseWriter, data any) {
	var b []byte
	if data != nil {
		var err error
		b, err = json.Marshal(data)
		if err != nil {
			writeHTTP(w, http.StatusInternalServerError, nil)
			return
		}
	}
	writeHTTPWithHeaders(w, http.StatusOK, b,
		map[string]string{"Content-Type": "application/json"})
}

func decodeJSONBody(r *http.Request, dst any) error {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return fmt.Errorf("couldn't read body: %w", err)
	}
	if err := json.Unmarshal(body, dst); err != nil {
		return fmt.Errorf("couldn't unmarshal body as JSON: %w", err)
	}
	return nil
}

func (server *Server) logErrorAndWriteHTTP(w http.ResponseWriter, r *http.Request, code int, msg string, args ...any) {
	var errors []error
	var logArgs []any
	for i := range args {
		if e, isError := args[i].(error); isError && e != nil {
			logArgs = append(logArgs, "error", e)
			errors = append(errors, e)
		}
	}

	server.log.Error(r, msg, logArgs...)

	var m struct {
		Errors []string `json:"errors"`
	}
	m.Errors = []string{msg}

	// Exclude 500+ errors
	if code < http.StatusInternalServerError {
		for _, err := range errors {
			m.Errors = append(m.Errors, err.Error())
		}
	}

	b, _ := json.Marshal(m)

	writeHTTPWithHeaders(w, code, b,
		map[string]string{"Content-Type": "application/json"})
}
