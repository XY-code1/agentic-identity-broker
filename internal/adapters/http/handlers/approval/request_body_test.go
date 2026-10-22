package approval

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/agentic-identity-broker/agentic-identity-broker/internal/adapters/http/requestbody"
	"github.com/agentic-identity-broker/agentic-identity-broker/internal/domain/approval/toolpattern"
	"github.com/agentic-identity-broker/agentic-identity-broker/internal/domain/principal"
	"github.com/agentic-identity-broker/agentic-identity-broker/internal/domain/storage"
	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"
)

type failingRequestBody struct {
	data string
}

func (b *failingRequestBody) Read(p []byte) (int, error) {
	n := copy(p, b.data)
	b.data = b.data[n:]
	return n, errors.New("request read failed")
}

func (*failingRequestBody) Close() error { return nil }

func TestApprovalHandlersRejectInvalidBodiesWithoutMutation(t *testing.T) {
	for _, operation := range []struct {
		name  string
		limit int
		valid string
	}{
		{"create", approvalCreateBodyLimit, `{"metadata":{"description":"review"},"tool_name":"read","arguments":{}}`},
		{"approve", approvalDecisionBodyLimit, `{"persistence":"once"}`},
		{"scope-preview", approvalDecisionBodyLimit, `{}`},
		{"deny", 4 << 10, `{}`},
	} {
		t.Run(operation.name, func(t *testing.T) {
			for _, test := range []struct {
				name      string
				body      string
				readError bool
				status    int
			}{
				{"unknown field", `{"unexpected":true}`, false, http.StatusBadRequest},
				{"trailing value", operation.valid + `{}`, false, http.StatusBadRequest},
				{"trailing junk", operation.valid + `x`, false, http.StatusBadRequest},
				{"oversize whitespace", operation.valid + strings.Repeat(" ", operation.limit), false, http.StatusRequestEntityTooLarge},
				{"oversize malformed", strings.Repeat("x", operation.limit+1), false, http.StatusRequestEntityTooLarge},
				{"read failure", "", true, http.StatusBadRequest},
				{"read failure after valid JSON", operation.valid, true, http.StatusBadRequest},
			} {
				t.Run(test.name, func(t *testing.T) {
					approve, repo, record := newApprovePatternHandler(t)
					var handler http.Handler
					switch operation.name {
					case "create":
						handler = NewCreateHandler(approve.service)
					case "approve":
						handler = approve
					case "scope-preview":
						handler = NewScopePreviewHandler(approve.service)
					case "deny":
						handler = NewDenyHandler(approve.service)
					}
					req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(test.body))
					req.ContentLength = -1
					if test.readError {
						req.Body = &failingRequestBody{data: test.body}
					}
					route := chi.NewRouteContext()
					route.URLParams.Add("id", record.ID.String())
					ctx := context.WithValue(req.Context(), chi.RouteCtxKey, route)
					req = req.WithContext(principal.WithPrincipal(ctx, string(record.Principal)))
					rec := httptest.NewRecorder()
					handler.ServeHTTP(rec, req)
					require.Equal(t, test.status, rec.Code, rec.Body.String())
					stored, err := repo.Get(context.Background(), record.ID)
					require.NoError(t, err)
					require.Equal(t, storage.ApprovalStatusPending, stored.Status)
				})
			}
		})
	}
}

func TestDenyHandlerAcceptsEmptyAndExactLimitBodies(t *testing.T) {
	for _, body := range []string{"", `{}` + strings.Repeat(" ", (4<<10)-2)} {
		approve, repo, record := newApprovePatternHandler(t)
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
		route := chi.NewRouteContext()
		route.URLParams.Add("id", record.ID.String())
		ctx := context.WithValue(req.Context(), chi.RouteCtxKey, route)
		req = req.WithContext(principal.WithPrincipal(ctx, string(record.Principal)))
		rec := httptest.NewRecorder()
		NewDenyHandler(approve.service).ServeHTTP(rec, req)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		stored, err := repo.Get(context.Background(), record.ID)
		require.NoError(t, err)
		require.Equal(t, storage.ApprovalStatusDenied, stored.Status)
	}
}

var _ io.ReadCloser = (*failingRequestBody)(nil)

func TestApprovalRequestFieldsAreClosedButMapsStayOpen(t *testing.T) {
	t.Run("nested metadata rejects unknown fields", func(t *testing.T) {
		var req createRequest
		err := requestbody.Unmarshal([]byte(`{"metadata":{"description":"review","unexpected":true},"tool_name":"read","arguments":{}}`), &req)
		require.Error(t, err)
	})
	t.Run("arguments preserve arbitrary nested values", func(t *testing.T) {
		var req createRequest
		err := requestbody.Unmarshal([]byte(`{"metadata":{"description":"review"},"tool_name":"read","arguments":{"custom":{"nested":[true,1,"value"]}}}`), &req)
		require.NoError(t, err)
		require.Equal(t, map[string]any{"nested": []any{true, float64(1), "value"}}, req.Arguments["custom"])
	})
	t.Run("parameter pattern names stay open", func(t *testing.T) {
		var req approveRequest
		require.NoError(t, requestbody.Unmarshal([]byte(`{"persistence":"session","params_pattern":{"custom.path":"*"}}`), &req))
		pattern, err := decodeParamsPattern(req.ParamsPattern)
		require.NoError(t, err)
		require.Equal(t, map[string]string{"custom.path": "*"}, pattern)
	})
}

// The ExtProc forwards MCP tool arguments to this route under its own
// authorization.max_body_size default, so the create boundary must accept them.
func TestApprovalCreateBodyLimitAcceptsExtProcSizedArguments(t *testing.T) {
	arguments := map[string]any{"content": strings.Repeat("x", 256<<10)}
	body, err := json.Marshal(map[string]any{
		"metadata":  map[string]any{"description": "large tool call"},
		"tool_name": "write_file",
		"arguments": arguments,
	})
	require.NoError(t, err)
	require.Greater(t, len(body), 64<<10)
	require.Less(t, len(body), approvalCreateBodyLimit)

	approve, _, _ := newApprovePatternHandler(t)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	NewCreateHandler(approve.service).ServeHTTP(rec, req.WithContext(principal.WithPrincipal(req.Context(), "user@example.com")))

	// Reaching approval authentication proves the boundary accepted the body.
	require.Equal(t, http.StatusServiceUnavailable, rec.Code, rec.Body.String())
	require.NotContains(t, rec.Body.String(), "too large")
}

// The consent UI posts the stored params_pattern back verbatim, so the decision body
// limit must accept the largest pattern the domain itself accepts.
func TestApprovalDecisionBodyLimitAcceptsLargestDomainValidParamsPattern(t *testing.T) {
	arguments := make(map[string]any, toolpattern.MaxParamsPatternEntries)
	for i := range toolpattern.MaxParamsPatternEntries {
		arguments[fmt.Sprintf("%0*d", toolpattern.MaxParamsPatternKeyBytes, i)] = strings.Repeat("v", toolpattern.MaxParamsPatternValueBytes)
	}
	pattern := toolpattern.ExactParams(arguments)
	require.NoError(t, toolpattern.ValidateParamsPattern(pattern))
	encoded, err := json.Marshal(pattern)
	require.NoError(t, err)
	require.Greater(t, len(encoded), 16<<10, "the fixture must exceed the former 16 KiB decision limit to guard the regression")

	for _, operation := range []struct {
		name string
		body []byte
		new  func(*ApproveHandler) http.Handler
	}{
		{"approve", fmt.Appendf(nil, `{"persistence":"permanent","params_pattern":%s}`, encoded), func(handler *ApproveHandler) http.Handler { return handler }},
		{"scope-preview", fmt.Appendf(nil, `{"params_pattern":%s}`, encoded), func(handler *ApproveHandler) http.Handler { return NewScopePreviewHandler(handler.service) }},
	} {
		t.Run(operation.name, func(t *testing.T) {
			approve, _, record := newApprovePatternHandlerWithArguments(t, arguments)
			require.Less(t, len(operation.body), approvalDecisionBodyLimit)
			req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(operation.body))
			route := chi.NewRouteContext()
			route.URLParams.Add("id", record.ID.String())
			ctx := principal.WithPrincipal(context.WithValue(req.Context(), chi.RouteCtxKey, route), string(record.Principal))
			rec := httptest.NewRecorder()
			operation.new(approve).ServeHTTP(rec, req.WithContext(ctx))
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		})
	}
}
