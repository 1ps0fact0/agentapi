package httpapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/agentapi/lib/httpapi"
	"github.com/coder/agentapi/lib/logctx"
	"github.com/coder/agentapi/lib/msgfmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Ensure the OpenAPI schema on disk is up to date.
// To update the schema, run `go run main.go server --print-openapi dummy > openapi.json`.
func TestOpenAPISchema(t *testing.T) {
	t.Parallel()

	ctx := logctx.WithLogger(context.Background(), slog.New(slog.NewTextHandler(os.Stdout, nil)))
	srv, err := httpapi.NewServer(ctx, httpapi.ServerConfig{
		AgentType:      msgfmt.AgentTypeClaude,
		AgentIO:        nil,
		Port:           0,
		ChatBasePath:   "/chat",
		AllowedHosts:   []string{"*"},
		AllowedOrigins: []string{"*"},
	})
	require.NoError(t, err)
	currentSchemaStr := srv.GetOpenAPI()
	var currentSchema any
	if err := json.Unmarshal([]byte(currentSchemaStr), &currentSchema); err != nil {
		t.Fatalf("failed to unmarshal current schema: %s", err)
	}

	diskSchemaFile, err := os.OpenFile("../../openapi.json", os.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("failed to open disk schema: %s", err)
	}
	defer func() {
		_ = diskSchemaFile.Close()
	}()

	diskSchemaBytes, err := io.ReadAll(diskSchemaFile)
	if err != nil {
		t.Fatalf("failed to read disk schema: %s", err)
	}
	var diskSchema any
	if err := json.Unmarshal(diskSchemaBytes, &diskSchema); err != nil {
		t.Fatalf("failed to unmarshal disk schema: %s", err)
	}

	require.Equal(t, currentSchema, diskSchema)
}

func TestServer_redirectToChat(t *testing.T) {
	cases := []struct {
		name                 string
		chatBasePath         string
		expectedResponseCode int
		expectedLocation     string
	}{
		{"default base path", "/chat", http.StatusTemporaryRedirect, "/chat/embed"},
		{"custom base path", "/custom", http.StatusTemporaryRedirect, "/custom/embed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tCtx := logctx.WithLogger(context.Background(), slog.New(slog.NewTextHandler(os.Stdout, nil)))
			s, err := httpapi.NewServer(tCtx, httpapi.ServerConfig{
				AgentType:      msgfmt.AgentTypeClaude,
				AgentIO:        nil,
				Port:           0,
				ChatBasePath:   tc.chatBasePath,
				AllowedHosts:   []string{"*"},
				AllowedOrigins: []string{"*"},
			})
			require.NoError(t, err)
			tsServer := httptest.NewServer(s.Handler())
			t.Cleanup(tsServer.Close)

			client := &http.Client{
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}
			resp, err := client.Get(tsServer.URL + "/")
			require.NoError(t, err, "unexpected error making GET request")
			t.Cleanup(func() {
				_ = resp.Body.Close()
			})
			require.Equal(t, tc.expectedResponseCode, resp.StatusCode, "expected %d status code", tc.expectedResponseCode)
			loc := resp.Header.Get("Location")
			require.Equal(t, tc.expectedLocation, loc, "expected Location %q, got %q", tc.expectedLocation, loc)
		})
	}
}

func TestServer_AllowedHosts(t *testing.T) {
	cases := []struct {
		name               string
		allowedHosts       []string
		hostHeader         string
		expectedStatusCode int
		expectedErrorMsg   string
		validationErrorMsg string
	}{
		{
			name:               "wildcard hosts - any host allowed",
			allowedHosts:       []string{"*"},
			hostHeader:         "example.com",
			expectedStatusCode: http.StatusOK,
		},
		{
			name:               "wildcard hosts - another host allowed",
			allowedHosts:       []string{"*"},
			hostHeader:         "malicious.com",
			expectedStatusCode: http.StatusOK,
		},
		{
			name:               "specific hosts - valid host allowed",
			allowedHosts:       []string{"localhost", "app.example.com"},
			hostHeader:         "localhost:3000",
			expectedStatusCode: http.StatusOK,
		},
		{
			name:               "specific hosts - another valid host allowed",
			allowedHosts:       []string{"localhost", "app.example.com"},
			hostHeader:         "app.example.com",
			expectedStatusCode: http.StatusOK,
		},
		{
			name:               "specific hosts - invalid host rejected",
			allowedHosts:       []string{"localhost", "app.example.com"},
			hostHeader:         "malicious.com",
			expectedStatusCode: http.StatusBadRequest,
			expectedErrorMsg:   "Invalid host header. Allowed hosts: localhost, app.example.com",
		},
		{
			name:               "ipv6 bracketed configured allowed - with port",
			allowedHosts:       []string{"[2001:db8::1]"},
			hostHeader:         "[2001:db8::1]:80",
			expectedStatusCode: http.StatusOK,
		},
		{
			name:               "ipv6 literal invalid host rejected",
			allowedHosts:       []string{"[2001:db8::1]"},
			hostHeader:         "[2001:db8::2]",
			expectedStatusCode: http.StatusBadRequest,
			expectedErrorMsg:   "Invalid host header. Allowed hosts: 2001:db8::1",
		},
		{
			name:               "allowed hosts must not be empty",
			allowedHosts:       []string{},
			validationErrorMsg: "the list must not be empty",
		},
		{
			name:               "ipv6 literal without square brackets is invalid",
			allowedHosts:       []string{"2001:db8::1"},
			validationErrorMsg: "must not include a port",
		},
		{
			name:               "host with port in config is invalid",
			allowedHosts:       []string{"example.com:8080"},
			validationErrorMsg: "must not include a port",
		},
		{
			name:               "bracketed ipv6 with port in config is invalid",
			allowedHosts:       []string{"[2001:db8::1]:443"},
			validationErrorMsg: "must not include a port",
		},
		{
			name:               "hostname with http scheme is invalid",
			allowedHosts:       []string{"http://example.com"},
			validationErrorMsg: "must not include http:// or https://",
		},
		{
			name:               "hostname with https scheme is invalid",
			allowedHosts:       []string{"https://example.com"},
			validationErrorMsg: "must not include http:// or https://",
		},
		{
			name:               "hostname containing comma is invalid",
			allowedHosts:       []string{"example.com,malicious.com"},
			validationErrorMsg: "contains comma characters, which are not allowed",
		},
		{
			name:               "hostname with leading whitespace is invalid",
			allowedHosts:       []string{" example.com"},
			validationErrorMsg: "contains whitespace characters, which are not allowed",
		},
		{
			name:               "hostname with internal whitespace is invalid",
			allowedHosts:       []string{"exa mple.com"},
			validationErrorMsg: "contains whitespace characters, which are not allowed",
		},
		{
			name:               "uppercase allowed host matches lowercase request",
			allowedHosts:       []string{"EXAMPLE.COM"},
			hostHeader:         "example.com:80",
			expectedStatusCode: http.StatusOK,
		},
		{
			name:               "wildcard with extra invalid entries still allows all",
			allowedHosts:       []string{"*", "https://bad.com", "example.com:8080", " space.com"},
			hostHeader:         "malicious.com",
			expectedStatusCode: http.StatusOK,
		},
		{
			name:               "trailing dot in allowed host requires trailing dot in request (no match)",
			allowedHosts:       []string{"example.com."},
			hostHeader:         "example.com",
			expectedStatusCode: http.StatusBadRequest,
			expectedErrorMsg:   "Invalid host header. Allowed hosts: example.com.",
		},
		{
			name:               "trailing dot in allowed host matches trailing dot in request",
			allowedHosts:       []string{"example.com."},
			hostHeader:         "example.com.:80",
			expectedStatusCode: http.StatusOK,
		},
		{
			name:               "ipv6 bracketed configured allowed - without port header",
			allowedHosts:       []string{"[2001:db8::1]"},
			hostHeader:         "[2001:db8::1]",
			expectedStatusCode: http.StatusOK,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := logctx.WithLogger(context.Background(), slog.New(slog.NewTextHandler(os.Stdout, nil)))
			s, err := httpapi.NewServer(ctx, httpapi.ServerConfig{
				AgentType:      msgfmt.AgentTypeClaude,
				AgentIO:        nil,
				Port:           0,
				ChatBasePath:   "/chat",
				AllowedHosts:   tc.allowedHosts,
				AllowedOrigins: []string{"https://example.com"}, // Set a default to isolate host testing
			})
			if tc.validationErrorMsg != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.validationErrorMsg)
				return
			} else {
				require.NoError(t, err)
			}
			tsServer := httptest.NewServer(s.Handler())
			t.Cleanup(tsServer.Close)

			req, err := http.NewRequest("GET", tsServer.URL+"/status", nil)
			require.NoError(t, err)

			if tc.hostHeader != "" {
				req.Host = tc.hostHeader
			}

			client := &http.Client{}
			resp, err := client.Do(req)
			require.NoError(t, err)
			t.Cleanup(func() {
				_ = resp.Body.Close()
			})

			require.Equal(t, tc.expectedStatusCode, resp.StatusCode,
				"expected status code %d, got %d", tc.expectedStatusCode, resp.StatusCode)

			if tc.expectedErrorMsg != "" {
				body, err := io.ReadAll(resp.Body)
				require.NoError(t, err)
				require.Contains(t, string(body), tc.expectedErrorMsg)
			}
		})
	}
}

func TestServer_CORSPreflightWithHosts(t *testing.T) {
	cases := []struct {
		name               string
		allowedHosts       []string
		hostHeader         string
		originHeader       string
		expectedStatusCode int
		expectCORSHeaders  bool
	}{
		{
			name:               "preflight with wildcard hosts",
			allowedHosts:       []string{"*"},
			hostHeader:         "example.com",
			originHeader:       "https://example.com",
			expectedStatusCode: http.StatusOK,
			expectCORSHeaders:  true,
		},
		{
			name:               "preflight with specific valid host",
			allowedHosts:       []string{"localhost"},
			hostHeader:         "localhost:3000",
			originHeader:       "https://localhost:3000",
			expectedStatusCode: http.StatusOK,
			expectCORSHeaders:  true,
		},
		{
			name:               "preflight with invalid host",
			allowedHosts:       []string{"localhost"},
			hostHeader:         "malicious.com",
			originHeader:       "https://malicious.com",
			expectedStatusCode: http.StatusBadRequest,
			expectCORSHeaders:  false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := logctx.WithLogger(context.Background(), slog.New(slog.NewTextHandler(os.Stdout, nil)))
			s, err := httpapi.NewServer(ctx, httpapi.ServerConfig{
				AgentType:      msgfmt.AgentTypeClaude,
				AgentIO:        nil,
				Port:           0,
				ChatBasePath:   "/chat",
				AllowedHosts:   tc.allowedHosts,
				AllowedOrigins: []string{"*"}, // Set wildcard origins to isolate host testing
			})
			require.NoError(t, err)
			tsServer := httptest.NewServer(s.Handler())
			t.Cleanup(tsServer.Close)

			// Test CORS preflight request
			req, err := http.NewRequest("OPTIONS", tsServer.URL+"/status", nil)
			require.NoError(t, err)

			if tc.hostHeader != "" {
				req.Host = tc.hostHeader
			}
			if tc.originHeader != "" {
				req.Header.Set("Origin", tc.originHeader)
			}
			req.Header.Set("Access-Control-Request-Method", "GET")
			req.Header.Set("Access-Control-Request-Headers", "Content-Type")

			client := &http.Client{}
			resp, err := client.Do(req)
			require.NoError(t, err)
			t.Cleanup(func() {
				_ = resp.Body.Close()
			})

			require.Equal(t, tc.expectedStatusCode, resp.StatusCode,
				"expected status code %d, got %d", tc.expectedStatusCode, resp.StatusCode)

			if tc.expectCORSHeaders {
				allowMethods := resp.Header.Get("Access-Control-Allow-Methods")
				require.Contains(t, allowMethods, "GET", "expected GET in allowed methods")

				allowHeaders := resp.Header.Get("Access-Control-Allow-Headers")
				require.Contains(t, allowHeaders, "Content-Type", "expected Content-Type in allowed headers")
			}
		})
	}
}

func TestServer_CORSOrigins(t *testing.T) {
	cases := []struct {
		name                   string
		allowedOrigins         []string
		originHeader           string
		expectedStatusCode     int
		expectedCORSOrigin     string
		expectCORSOriginHeader bool
		validationErrorMsg     string
	}{
		{
			name:                   "wildcard origins - any origin allowed",
			allowedOrigins:         []string{"*"},
			originHeader:           "https://example.com",
			expectedStatusCode:     http.StatusOK,
			expectedCORSOrigin:     "*",
			expectCORSOriginHeader: true,
		},
		{
			name:                   "wildcard origins - malicious origin allowed",
			allowedOrigins:         []string{"*"},
			originHeader:           "http://malicious.com",
			expectedStatusCode:     http.StatusOK,
			expectedCORSOrigin:     "*",
			expectCORSOriginHeader: true,
		},
		{
			name:                   "specific origins - valid origin allowed https",
			allowedOrigins:         []string{"https://localhost:3000", "http://app.example.com"},
			originHeader:           "https://localhost:3000",
			expectedStatusCode:     http.StatusOK,
			expectedCORSOrigin:     "https://localhost:3000",
			expectCORSOriginHeader: true,
		},
		{
			name:                   "specific origins - valid origin allowed http",
			allowedOrigins:         []string{"https://localhost:3000", "http://app.example.com"},
			originHeader:           "http://app.example.com",
			expectedStatusCode:     http.StatusOK,
			expectedCORSOrigin:     "http://app.example.com",
			expectCORSOriginHeader: true,
		},
		{
			name:                   "specific origins - invalid origin rejected",
			allowedOrigins:         []string{"https://localhost:3000", "http://app.example.com"},
			originHeader:           "https://malicious.com",
			expectedStatusCode:     http.StatusOK, // Server allows request - CORS is enforced by browser
			expectCORSOriginHeader: false,
		},
		{
			name:               "no origin header - request not coming from a browser",
			allowedOrigins:     []string{"https://example.com"},
			originHeader:       "",
			expectedStatusCode: http.StatusOK,
		},
		{
			name:               "allowed origins must not be empty",
			allowedOrigins:     []string{},
			validationErrorMsg: "the list must not be empty",
		},
		{
			name:               "origin containing comma is invalid",
			allowedOrigins:     []string{"https://example.com,http://localhost:3000"},
			validationErrorMsg: "contains comma characters, which are not allowed",
		},
		{
			name:               "origin with internal whitespace is invalid",
			allowedOrigins:     []string{"https://exa mple.com"},
			validationErrorMsg: "contains whitespace characters, which are not allowed",
		},
		{
			name:               "origin with leading whitespace is invalid",
			allowedOrigins:     []string{" https://example.com"},
			validationErrorMsg: "contains whitespace characters, which are not allowed",
		},
		{
			name:                   "wildcard with extra invalid entries still allows all",
			allowedOrigins:         []string{"*", "https://bad.com,too", "http://bad host"},
			originHeader:           "http://malicious.com",
			expectedCORSOrigin:     "*",
			expectCORSOriginHeader: true,
			expectedStatusCode:     http.StatusOK,
		},
		{
			name:                   "ipv6 origin allowed",
			allowedOrigins:         []string{"http://[2001:db8::1]:8080"},
			originHeader:           "http://[2001:db8::1]:8080",
			expectedCORSOrigin:     "http://[2001:db8::1]:8080",
			expectCORSOriginHeader: true,
			expectedStatusCode:     http.StatusOK,
		},
		{
			name:                   "origin with path, query, and fragment normalizes to scheme+host",
			allowedOrigins:         []string{"https://example.com/path?x=1#frag"},
			originHeader:           "https://example.com",
			expectedCORSOrigin:     "https://example.com",
			expectCORSOriginHeader: true,
			expectedStatusCode:     http.StatusOK,
		},
		{
			name:                   "trailing slash is ignored for matching",
			allowedOrigins:         []string{"https://example.com/"},
			originHeader:           "https://example.com",
			expectedCORSOrigin:     "https://example.com",
			expectCORSOriginHeader: true,
			expectedStatusCode:     http.StatusOK,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := logctx.WithLogger(context.Background(), slog.New(slog.NewTextHandler(os.Stdout, nil)))
			s, err := httpapi.NewServer(ctx, httpapi.ServerConfig{
				AgentType:      msgfmt.AgentTypeClaude,
				AgentIO:        nil,
				Port:           0,
				ChatBasePath:   "/chat",
				AllowedHosts:   []string{"*"}, // Set wildcard to isolate CORS testing
				AllowedOrigins: tc.allowedOrigins,
			})
			if tc.validationErrorMsg != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.validationErrorMsg)
				return
			}
			tsServer := httptest.NewServer(s.Handler())
			t.Cleanup(tsServer.Close)

			req, err := http.NewRequest("GET", tsServer.URL+"/status", nil)
			require.NoError(t, err)

			if tc.originHeader != "" {
				req.Header.Set("Origin", tc.originHeader)
			}

			client := &http.Client{}
			resp, err := client.Do(req)
			require.NoError(t, err)
			t.Cleanup(func() {
				_ = resp.Body.Close()
			})

			require.Equal(t, tc.expectedStatusCode, resp.StatusCode,
				"expected status code %d, got %d", tc.expectedStatusCode, resp.StatusCode)

			if tc.expectCORSOriginHeader {
				corsOrigin := resp.Header.Get("Access-Control-Allow-Origin")
				require.Equal(t, tc.expectedCORSOrigin, corsOrigin,
					"expected CORS origin %q, got %q", tc.expectedCORSOrigin, corsOrigin)
			} else if tc.expectedStatusCode == http.StatusOK && tc.originHeader != "" {
				corsOrigin := resp.Header.Get("Access-Control-Allow-Origin")
				require.Empty(t, corsOrigin, "expected no CORS origin header, got %q", corsOrigin)
			}
		})
	}
}

func TestServer_CORSPreflightOrigins(t *testing.T) {
	cases := []struct {
		name               string
		allowedOrigins     []string
		originHeader       string
		expectedStatusCode int
		expectCORSHeaders  bool
	}{
		{
			name:               "preflight with wildcard origins",
			allowedOrigins:     []string{"*"},
			originHeader:       "https://example.com",
			expectedStatusCode: http.StatusOK,
			expectCORSHeaders:  true,
		},
		{
			name:               "preflight with specific valid origin",
			allowedOrigins:     []string{"https://localhost:3000"},
			originHeader:       "https://localhost:3000",
			expectedStatusCode: http.StatusOK,
			expectCORSHeaders:  true,
		},
		{
			name:               "preflight with invalid origin",
			allowedOrigins:     []string{"https://localhost:3000"},
			originHeader:       "https://malicious.com",
			expectedStatusCode: http.StatusOK, // Request succeeds but no CORS headers
			expectCORSHeaders:  false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := logctx.WithLogger(context.Background(), slog.New(slog.NewTextHandler(os.Stdout, nil)))
			s, err := httpapi.NewServer(ctx, httpapi.ServerConfig{
				AgentType:      msgfmt.AgentTypeClaude,
				AgentIO:        nil,
				Port:           0,
				ChatBasePath:   "/chat",
				AllowedHosts:   []string{"*"}, // Set wildcard to isolate CORS testing
				AllowedOrigins: tc.allowedOrigins,
			})
			require.NoError(t, err)
			tsServer := httptest.NewServer(s.Handler())
			t.Cleanup(tsServer.Close)

			req, err := http.NewRequest("OPTIONS", tsServer.URL+"/status", nil)
			require.NoError(t, err)

			if tc.originHeader != "" {
				req.Header.Set("Origin", tc.originHeader)
			}
			req.Header.Set("Access-Control-Request-Method", "GET")
			req.Header.Set("Access-Control-Request-Headers", "Content-Type")

			client := &http.Client{}
			resp, err := client.Do(req)
			require.NoError(t, err)
			t.Cleanup(func() {
				_ = resp.Body.Close()
			})

			require.Equal(t, tc.expectedStatusCode, resp.StatusCode,
				"expected status code %d, got %d", tc.expectedStatusCode, resp.StatusCode)

			if tc.expectCORSHeaders {
				allowMethods := resp.Header.Get("Access-Control-Allow-Methods")
				require.Contains(t, allowMethods, "GET", "expected GET in allowed methods")

				allowHeaders := resp.Header.Get("Access-Control-Allow-Headers")
				require.Contains(t, allowHeaders, "Content-Type", "expected Content-Type in allowed headers")

				corsOrigin := resp.Header.Get("Access-Control-Allow-Origin")
				require.NotEmpty(t, corsOrigin, "expected CORS origin header for valid preflight")
			} else if tc.originHeader != "" {
				corsOrigin := resp.Header.Get("Access-Control-Allow-Origin")
				require.Empty(t, corsOrigin, "expected no CORS origin header for invalid origin")
			}
		})
	}
}

func TestServer_SSEMiddleware_Events(t *testing.T) {
	t.Parallel()
	ctx := logctx.WithLogger(context.Background(), slog.New(slog.NewTextHandler(os.Stdout, nil)))
	srv, err := httpapi.NewServer(ctx, httpapi.ServerConfig{
		AgentType:      msgfmt.AgentTypeClaude,
		AgentIO:        nil,
		Port:           0,
		ChatBasePath:   "/chat",
		AllowedHosts:   []string{"*"},
		AllowedOrigins: []string{"*"},
	})
	require.NoError(t, err)
	tsServer := httptest.NewServer(srv.Handler())
	t.Cleanup(tsServer.Close)

	t.Run("events", func(t *testing.T) {
		t.Parallel()
		resp, err := tsServer.Client().Get(tsServer.URL + "/events")
		require.NoError(t, err)
		t.Cleanup(func() {
			_ = resp.Body.Close()
		})
		assertSSEHeaders(t, resp)
	})

	t.Run("internal/screen", func(t *testing.T) {
		t.Parallel()

		resp, err := tsServer.Client().Get(tsServer.URL + "/internal/screen")
		require.NoError(t, err)
		t.Cleanup(func() {
			_ = resp.Body.Close()
		})
		assertSSEHeaders(t, resp)
	})
}

func assertSSEHeaders(t testing.TB, resp *http.Response) {
	t.Helper()
	assert.Equal(t, "no-cache, no-store, must-revalidate", resp.Header.Get("Cache-Control"))
	assert.Equal(t, "no-cache", resp.Header.Get("Pragma"))
	assert.Equal(t, "0", resp.Header.Get("Expires"))
	assert.Equal(t, "no", resp.Header.Get("X-Accel-Buffering"))
	assert.Equal(t, "no", resp.Header.Get("X-Proxy-Buffering"))
	assert.Equal(t, "keep-alive", resp.Header.Get("Connection"))
}

func TestServer_UploadFiles(t *testing.T) {
	t.Parallel()
	ctx := logctx.WithLogger(context.Background(), slog.New(slog.NewTextHandler(os.Stdout, nil)))
	srv, err := httpapi.NewServer(ctx, httpapi.ServerConfig{
		AgentType:      msgfmt.AgentTypeClaude,
		AgentIO:        nil,
		Port:           0,
		ChatBasePath:   "/chat",
		AllowedHosts:   []string{"*"},
		AllowedOrigins: []string{"*"},
	})
	require.NoError(t, err)
	tsServer := httptest.NewServer(srv.Handler())
	t.Cleanup(tsServer.Close)

	cases := []struct {
		name               string
		filename           string
		fileContent        string
		expectedStatusCode int
		expectFilePath     bool
	}{
		{
			name:               "upload jpeg file",
			filename:           "test.jpeg",
			fileContent:        "Hello, world!",
			expectedStatusCode: http.StatusOK,
			expectFilePath:     true,
		},
		{
			name:               "upload empty file",
			filename:           "empty.txt",
			fileContent:        "",
			expectedStatusCode: http.StatusOK,
			expectFilePath:     true,
		},
		{
			name:               "upload binary file",
			filename:           "test.bin",
			fileContent:        "\x00\x01\x02\x03\xFF",
			expectedStatusCode: http.StatusOK,
			expectFilePath:     true,
		},
		{
			name:               "upload file with special characters in name",
			filename:           "test file (1).txt",
			fileContent:        "content",
			expectedStatusCode: http.StatusOK,
			expectFilePath:     true,
		},
		{
			name:               "upload file with absolute path filename",
			filename:           "/tmp/absolute-path-file.txt",
			fileContent:        "absolute path content",
			expectedStatusCode: http.StatusOK,
			expectFilePath:     true,
		},
		{
			name:               "upload file with relative path filename",
			filename:           "../relative-path-file.txt",
			fileContent:        "relative path content",
			expectedStatusCode: http.StatusOK,
			expectFilePath:     true,
		},
		{
			name:               "upload file with nested relative path",
			filename:           "nested/path/file.txt",
			fileContent:        "nested content",
			expectedStatusCode: http.StatusOK,
			expectFilePath:     true,
		},
		{
			name:               "upload file with backslash path separators",
			filename:           "windows\\style\\path.txt",
			fileContent:        "windows path content",
			expectedStatusCode: http.StatusOK,
			expectFilePath:     true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Create a buffer to write our multipart form data
			var buf bytes.Buffer
			writer := multipart.NewWriter(&buf)

			// Add the file field
			part, err := writer.CreateFormFile("file", tc.filename)
			require.NoError(t, err)
			_, err = part.Write([]byte(tc.fileContent))
			require.NoError(t, err)

			// Close the writer to finalize the form
			err = writer.Close()
			require.NoError(t, err)

			// Create the request
			req, err := http.NewRequest("POST", tsServer.URL+"/upload", &buf)
			require.NoError(t, err)
			req.Header.Set("Content-Type", writer.FormDataContentType())

			// Send the request
			client := &http.Client{}
			resp, err := client.Do(req)
			require.NoError(t, err)
			t.Cleanup(func() {
				_ = resp.Body.Close()
			})

			// Check status code
			require.Equal(t, tc.expectedStatusCode, resp.StatusCode,
				"expected status code %d, got %d", tc.expectedStatusCode, resp.StatusCode)

			if tc.expectedStatusCode == http.StatusOK {
				// Parse response body
				body, err := io.ReadAll(resp.Body)
				require.NoError(t, err)

				var uploadResp struct {
					Ok       bool   `json:"ok"`
					FilePath string `json:"filePath"`
				}
				err = json.Unmarshal(body, &uploadResp)
				require.NoError(t, err)

				// Verify response
				require.True(t, uploadResp.Ok, "expected ok to be true")

				if tc.expectFilePath {
					require.NotEmpty(t, uploadResp.FilePath, "expected file path to be non-empty")

					// Verify file was actually saved
					savedContent, err := os.ReadFile(uploadResp.FilePath)
					require.NoError(t, err)
					require.Equal(t, tc.fileContent, string(savedContent), "file content should match")

					// Verify filename is preserved in the path (only the base filename for security)
					expectedFilename := filepath.Base(tc.filename)
					if expectedFilename == "" {
						expectedFilename = "uploaded_file"
					}
					require.Contains(t, uploadResp.FilePath, expectedFilename, "file path should contain filename")

					// Clean up the uploaded file
					t.Cleanup(func() {
						_ = os.Remove(uploadResp.FilePath)
					})
				}
			}
		})
	}
}

func TestServer_UploadFiles_Errors(t *testing.T) {
	t.Parallel()
	ctx := logctx.WithLogger(context.Background(), slog.New(slog.NewTextHandler(os.Stdout, nil)))
	srv, err := httpapi.NewServer(ctx, httpapi.ServerConfig{
		AgentType:      msgfmt.AgentTypeClaude,
		AgentIO:        nil,
		Port:           0,
		ChatBasePath:   "/chat",
		AllowedHosts:   []string{"*"},
		AllowedOrigins: []string{"*"},
	})
	require.NoError(t, err)
	tsServer := httptest.NewServer(srv.Handler())
	t.Cleanup(tsServer.Close)

	t.Run("missing file field", func(t *testing.T) {
		t.Parallel()

		// Create multipart form without file field
		var buf bytes.Buffer
		writer := multipart.NewWriter(&buf)
		err := writer.WriteField("notfile", "value")
		require.NoError(t, err)
		err = writer.Close()
		require.NoError(t, err)

		req, err := http.NewRequest("POST", tsServer.URL+"/upload", &buf)
		require.NoError(t, err)
		req.Header.Set("Content-Type", writer.FormDataContentType())

		client := &http.Client{}
		resp, err := client.Do(req)
		require.NoError(t, err)
		t.Cleanup(func() {
			_ = resp.Body.Close()
		})

		require.Equal(t, http.StatusUnprocessableEntity, resp.StatusCode)
	})

	t.Run("invalid content type", func(t *testing.T) {
		t.Parallel()

		req, err := http.NewRequest("POST", tsServer.URL+"/upload", strings.NewReader("not multipart"))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")

		client := &http.Client{}
		resp, err := client.Do(req)
		require.NoError(t, err)
		t.Cleanup(func() {
			_ = resp.Body.Close()
		})

		require.Equal(t, http.StatusUnprocessableEntity, resp.StatusCode)
	})

	t.Run("file size exactly 10MB", func(t *testing.T) {
		t.Parallel()

		// Create exactly 10MB of data
		const tenMB = 10 << 20
		fileContent := make([]byte, tenMB)
		for i := range fileContent {
			fileContent[i] = byte(i % 256)
		}

		var buf bytes.Buffer
		writer := multipart.NewWriter(&buf)
		part, err := writer.CreateFormFile("file", "10mb-file.bin")
		require.NoError(t, err)
		_, err = part.Write(fileContent)
		require.NoError(t, err)
		err = writer.Close()
		require.NoError(t, err)

		req, err := http.NewRequest("POST", tsServer.URL+"/upload", &buf)
		require.NoError(t, err)
		req.Header.Set("Content-Type", writer.FormDataContentType())

		client := &http.Client{}
		resp, err := client.Do(req)
		require.NoError(t, err)
		t.Cleanup(func() {
			_ = resp.Body.Close()
		})

		require.Equal(t, http.StatusOK, resp.StatusCode)

		// Parse response to get file path for cleanup
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		var uploadResp struct {
			Ok       bool   `json:"ok"`
			FilePath string `json:"filePath"`
		}
		err = json.Unmarshal(body, &uploadResp)
		require.NoError(t, err)
		require.True(t, uploadResp.Ok)

		// Clean up the uploaded file
		t.Cleanup(func() {
			_ = os.Remove(uploadResp.FilePath)
		})
	})

	t.Run("file size exceeds 10MB limit", func(t *testing.T) {
		t.Parallel()

		// Create slightly more than 10MB of data
		const tenMBPlusOne = (10 << 20) + 1
		fileContent := make([]byte, tenMBPlusOne)
		for i := range fileContent {
			fileContent[i] = byte(i % 256)
		}

		var buf bytes.Buffer
		writer := multipart.NewWriter(&buf)
		part, err := writer.CreateFormFile("file", "large-file.bin")
		require.NoError(t, err)
		_, err = part.Write(fileContent)
		require.NoError(t, err)
		err = writer.Close()
		require.NoError(t, err)

		req, err := http.NewRequest("POST", tsServer.URL+"/upload", &buf)
		require.NoError(t, err)
		req.Header.Set("Content-Type", writer.FormDataContentType())

		client := &http.Client{}
		resp, err := client.Do(req)
		require.NoError(t, err)
		t.Cleanup(func() {
			_ = resp.Body.Close()
		})

		require.Equal(t, http.StatusBadRequest, resp.StatusCode)

		// Verify error message
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.Contains(t, string(body), "file size exceeds 10MB limit")
	})
}

// newListenerTestServer builds a server bound to the given address on an
// ephemeral port (port 0) with no agent attached, so tests can exercise the
// real listener without launching a coding agent.
func newListenerTestServer(t *testing.T, bindAddress string) *httpapi.Server {
	t.Helper()
	ctx := logctx.WithLogger(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	s, err := httpapi.NewServer(ctx, httpapi.ServerConfig{
		AgentType:      msgfmt.AgentTypeClaude,
		AgentIO:        nil,
		Port:           0,
		BindAddress:    bindAddress,
		ChatBasePath:   "/chat",
		AllowedHosts:   []string{"*"},
		AllowedOrigins: []string{"*"},
	})
	require.NoError(t, err)
	// Ensure the temp dir and any listener are cleaned up even if the test
	// returns early. Stop is idempotent, so an explicit Stop later is fine.
	t.Cleanup(func() {
		_ = s.Stop(context.Background())
	})
	return s
}

// ipv6LoopbackAvailable reports whether the host can bind the IPv6 loopback.
func ipv6LoopbackAvailable() bool {
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		return false
	}
	_ = ln.Close()
	return true
}

// startAndWait starts the server in a goroutine and blocks until it is
// listening, returning the bound address and a channel carrying Start's result.
func startAndWait(t *testing.T, s *httpapi.Server) (net.Addr, <-chan error) {
	t.Helper()
	errCh := make(chan error, 1)
	go func() {
		errCh <- s.Start()
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if addr := s.Addr(); addr != nil {
			return addr, errCh
		}
		select {
		case err := <-errCh:
			t.Fatalf("server exited before listening: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for the server to start listening")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestServer_ListenAddress exercises the listener-address construction end to
// end: each bind address must resolve to the expected kind of socket, and a
// malformed address must fail fast rather than silently binding all interfaces.
func TestServer_ListenAddress(t *testing.T) {
	ipv6 := ipv6LoopbackAvailable()

	cases := []struct {
		name        string
		bindAddress string
		wantErr     bool
		needIPv6    bool
		check       func(t *testing.T, ip net.IP)
	}{
		{
			name:        "empty binds all interfaces",
			bindAddress: "",
			check: func(t *testing.T, ip net.IP) {
				require.True(t, ip.IsUnspecified(), "expected wildcard/unspecified bind, got %s", ip)
			},
		},
		{
			name:        "ipv4 loopback",
			bindAddress: "127.0.0.1",
			check: func(t *testing.T, ip net.IP) {
				require.True(t, ip.IsLoopback(), "expected loopback, got %s", ip)
				require.NotNil(t, ip.To4(), "expected an IPv4 address, got %s", ip)
			},
		},
		{
			name:        "ipv6 loopback",
			bindAddress: "::1",
			needIPv6:    true,
			check: func(t *testing.T, ip net.IP) {
				require.True(t, ip.IsLoopback(), "expected loopback, got %s", ip)
				require.Nil(t, ip.To4(), "expected an IPv6 address, got %s", ip)
			},
		},
		{
			name:        "bracketed ipv6 loopback",
			bindAddress: "[::1]",
			needIPv6:    true,
			check: func(t *testing.T, ip net.IP) {
				require.True(t, ip.IsLoopback(), "expected loopback, got %s", ip)
				require.Nil(t, ip.To4(), "expected an IPv6 address, got %s", ip)
			},
		},
		{
			name:        "hostname localhost",
			bindAddress: "localhost",
			check: func(t *testing.T, ip net.IP) {
				require.True(t, ip.IsLoopback(), "expected loopback, got %s", ip)
			},
		},
		{
			name:        "malformed host with embedded port",
			bindAddress: "127.0.0.1:8080",
			wantErr:     true,
		},
		{
			name:        "malformed bracketed non-ip",
			bindAddress: "[not-an-ip]",
			wantErr:     true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.needIPv6 && !ipv6 {
				t.Skip("IPv6 loopback not available on this host")
			}
			s := newListenerTestServer(t, tc.bindAddress)

			if tc.wantErr {
				// A malformed bind address must return an error and must never
				// leave a listening wildcard socket behind.
				err := s.Start()
				require.Error(t, err)
				require.Nil(t, s.Addr(), "malformed bind address must not create a listener")
				return
			}

			addr, errCh := startAndWait(t, s)
			tcpAddr, ok := addr.(*net.TCPAddr)
			require.True(t, ok, "expected *net.TCPAddr, got %T", addr)
			tc.check(t, tcpAddr.IP)

			stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			require.NoError(t, s.Stop(stopCtx))

			select {
			case err := <-errCh:
				require.ErrorIs(t, err, http.ErrServerClosed)
			case <-time.After(5 * time.Second):
				t.Fatal("serving goroutine did not exit after Stop")
			}
		})
	}
}

// TestServer_BoundListener is a bounded integration test that binds a real
// listener on port 0, verifies the actual bound address, and confirms graceful
// shutdown returns without leaking the listener or the serving goroutine. It
// launches no coding agent and never binds a fixed port.
func TestServer_BoundListener(t *testing.T) {
	ipv6 := ipv6LoopbackAvailable()

	cases := []struct {
		name        string
		bindAddress string
		needIPv6    bool
	}{
		{"ipv4 loopback", "127.0.0.1", false},
		{"ipv6 loopback", "::1", true},
		{"default remains wildcard", "", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.needIPv6 && !ipv6 {
				t.Skip("IPv6 loopback not available on this host")
			}
			s := newListenerTestServer(t, tc.bindAddress)
			addr, errCh := startAndWait(t, s)

			tcpAddr, ok := addr.(*net.TCPAddr)
			require.True(t, ok, "expected *net.TCPAddr, got %T", addr)
			require.NotZero(t, tcpAddr.Port, "expected an ephemeral port to be assigned")

			switch tc.bindAddress {
			case "127.0.0.1":
				require.True(t, tcpAddr.IP.IsLoopback(), "expected loopback, got %s", tcpAddr.IP)
				require.NotNil(t, tcpAddr.IP.To4(), "expected an IPv4 address, got %s", tcpAddr.IP)
			case "::1":
				require.True(t, tcpAddr.IP.IsLoopback(), "expected loopback, got %s", tcpAddr.IP)
				require.Nil(t, tcpAddr.IP.To4(), "expected an IPv6 address, got %s", tcpAddr.IP)
			case "":
				require.True(t, tcpAddr.IP.IsUnspecified(),
					"empty bind address must remain a wildcard bind, got %s", tcpAddr.IP)
			}

			stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			require.NoError(t, s.Stop(stopCtx))

			// The serving goroutine returning http.ErrServerClosed proves both the
			// listener and the goroutine were released by Stop.
			select {
			case err := <-errCh:
				require.ErrorIs(t, err, http.ErrServerClosed)
			case <-time.After(5 * time.Second):
				t.Fatal("serving goroutine did not exit after Stop")
			}
		})
	}
}

func TestServer_Stop_Idempotency(t *testing.T) {
	t.Parallel()
	ctx := logctx.WithLogger(context.Background(), slog.New(slog.NewTextHandler(os.Stdout, nil)))

	srv, err := httpapi.NewServer(ctx, httpapi.ServerConfig{
		AgentType:      msgfmt.AgentTypeClaude,
		AgentIO:        nil,
		Port:           0,
		ChatBasePath:   "/chat",
		AllowedHosts:   []string{"*"},
		AllowedOrigins: []string{"*"},
	})
	require.NoError(t, err)

	// First call to Stop should succeed
	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = srv.Stop(stopCtx)
	require.NoError(t, err)

	// Second call to Stop should also succeed (no-op)
	stopCtx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	err = srv.Stop(stopCtx2)
	require.NoError(t, err)

	// Third call to Stop should also succeed (no-op)
	stopCtx3, cancel3 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel3()
	err = srv.Stop(stopCtx3)
	require.NoError(t, err)
}
