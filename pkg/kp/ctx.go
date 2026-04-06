package kp

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"html/template"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sing3demons/oauth_server/internal/config"
	"github.com/sing3demons/oauth_server/pkg/errors"
	"github.com/sing3demons/oauth_server/pkg/logAction"
	"github.com/sing3demons/oauth_server/pkg/logger"
	"github.com/sing3demons/oauth_server/pkg/middleware"
	"github.com/sing3demons/oauth_server/pkg/mlog"
)

const MaxBodySize = 10 << 20 // 10 MB
type ContentType string

const (
	ContentTypeJSON          ContentType = "application/json"
	ContentTypeXML           ContentType = "application/xml"
	ContentTypeForm          ContentType = "application/x-www-form-urlencoded"
	ContentTypeMultipartForm ContentType = "multipart/form-data"
	ContentTypePlainText     ContentType = "text/plain"
)

type CtxKey string

const (
	SessionID     CtxKey = "x-session-id"
	TransactionID CtxKey = "x-transaction-id"
)

type Ctx struct {
	Req           *http.Request
	Res           http.ResponseWriter
	log           *logger.CustomLogger
	cmd           string
	cfg           *config.Config
	sessionId     string
	transactionId string
}

func NewCtx(r *http.Request, w http.ResponseWriter) *Ctx {
	_log := mlog.L(r.Context())
	return &Ctx{Req: r, Res: w, log: _log}
}
func newMuxContext(r *http.Request, w http.ResponseWriter, cfg *config.Config) *Ctx {
	return &Ctx{Req: r, Res: w, log: mlog.L(r.Context()), cfg: cfg}
}
func (c *Ctx) Log(cmd string, maskOptions ...logger.MaskingOption) *logger.CustomLogger {
	c.cmd = cmd
	// copy body
	body := make(map[string]any)
	c.Bind(&body)

	// Restore body for subsequent reads (e.g., FormValue, Bind)
	incoming := map[string]any{
		"method":  c.Req.Method,
		"url":     c.Req.URL.String(),
		"headers": c.Req.Header,
		"query":   c.Req.URL.Query(),
		"body":    body,
	}

	c.ensureRequestMetadata(cmd, body)
	c.log.Info(logAction.INBOUND("Start receiving request from API : command-> "+cmd+" | method-> "+c.Req.Method+" | path-> "+c.Req.URL.Path), incoming, maskOptions...)
	return c.log
}

func (c *Ctx) ensureRequestMetadata(cmd string, body map[string]any) {
	if cmd != "" {
		c.log.Update("RecordName", cmd)
	}

	if cmd == "authorize" {
		if cookie, err := c.Req.Cookie("oidc_session"); err == nil && cookie.Value != "" {
			c.sessionId = cookie.Value
		}
	}

	if c.sessionId == "" {
		c.sessionId = c.resolveRequestID("X-Session-ID", "sid", body)
	}
	if c.transactionId == "" {
		c.transactionId = c.resolveRequestID("X-Transaction-ID", "tid", body)
	}

	c.log.Update("SessionId", c.sessionId)
	c.log.Update("TransactionId", c.transactionId)

	ctx := c.Req.Context()
	if ctx.Value(SessionID) == nil {
		ctx = context.WithValue(ctx, SessionID, c.sessionId)
	}
	if ctx.Value(TransactionID) == nil {
		ctx = context.WithValue(ctx, TransactionID, c.transactionId)
	}
	c.Req = c.Req.WithContext(ctx)
}

func (c *Ctx) resolveRequestID(headerName, paramName string, body map[string]any) string {
	if value := c.Req.Header.Get(headerName); value != "" {
		return value
	}
	if value := c.Req.URL.Query().Get(paramName); value != "" {
		return value
	}
	if value := stringifyBodyValue(body[paramName]); value != "" {
		return value
	}
	return uuid.New().String()
}

func (c *Ctx) extractBodyValue(key string, body map[string]any, bodyBytes []byte) string {
	if len(body) > 0 {
		if value := stringifyBodyValue(body[key]); value != "" {
			return value
		}
	}
	if len(bodyBytes) == 0 {
		return ""
	}

	contentType := c.Req.Header.Get("Content-Type")
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		mediaType = strings.TrimSpace(strings.Split(contentType, ";")[0])
	}

	switch mediaType {
	case string(ContentTypeForm):
		values, parseErr := url.ParseQuery(string(bodyBytes))
		if parseErr == nil {
			return values.Get(key)
		}
	case string(ContentTypeMultipartForm):
		boundary := params["boundary"]
		if boundary == "" {
			return ""
		}
		reader := multipart.NewReader(bytes.NewReader(bodyBytes), boundary)
		for {
			part, partErr := reader.NextPart()
			if partErr == io.EOF {
				break
			}
			if partErr != nil {
				return ""
			}
			if part.FormName() != key {
				continue
			}
			partBytes, readErr := io.ReadAll(part)
			if readErr != nil {
				return ""
			}
			return string(partBytes)
		}
	}

	return ""
}

func stringifyBodyValue(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case json.Number:
		return typed.String()
	case fmt.Stringer:
		return typed.String()
	case float64, float32, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, bool:
		return fmt.Sprint(typed)
	default:
		return ""
	}
}

func (c *Ctx) SessionId() string {
	return c.sessionId
}

func (c *Ctx) TransactionId() string {
	return c.transactionId
}

func (c *Ctx) Config() *config.Config {
	return c.cfg
}

func (c *Ctx) Bind(v any) error {
	// Only parse body for non-GET requests
	if c.Req.Method == http.MethodGet || c.Req.Method == http.MethodHead {
		return nil
	}

	// Get Content-Type header
	contentType := c.Req.Header.Get("Content-Type")
	if contentType == "" {
		// Default to JSON if not specified
		contentType = string(ContentTypeJSON)
	}

	// Extract base content type (remove charset, boundary, etc.)
	baseContentType := strings.Split(contentType, ";")[0]
	baseContentType = strings.TrimSpace(baseContentType)

	// Limit body size to prevent DoS
	limitedReader := io.LimitReader(c.Req.Body, MaxBodySize)
	bodyBytes, err := io.ReadAll(limitedReader)
	if err != nil {
		return fmt.Errorf("failed to read request body: %w", err)
	}

	// Check if body exceeded limit
	if int64(len(bodyBytes)) >= MaxBodySize {
		return fmt.Errorf("request body too large (max %d bytes)", MaxBodySize)
	}

	// Restore body for potential re-reads (e.g., logging middleware)
	c.Req.Body = io.NopCloser(bytes.NewReader(bodyBytes))

	// Parse based on content type
	switch ContentType(baseContentType) {
	case ContentTypeJSON:
		return c.parseJSON(bodyBytes, v)

	case ContentTypeXML:
		return c.parseXML(bodyBytes, v)

	case ContentTypeForm:
		return c.parseFormURLEncoded(bodyBytes, v)

	case ContentTypeMultipartForm:
		return c.parseMultipartForm(v)

	case ContentTypePlainText:
		return c.parsePlainText(bodyBytes, v)

	default:
		return fmt.Errorf("unsupported content type: %s", contentType)
	}
}

// parseJSON parses JSON content
func (c *Ctx) parseJSON(bodyBytes []byte, v any) error {
	if len(bodyBytes) == 0 {
		return fmt.Errorf("empty JSON body")
	}

	if err := json.Unmarshal(bodyBytes, v); err != nil {
		return fmt.Errorf("failed to unmarshal JSON: %w", err)
	}
	return nil
}

// parseXML parses XML content
func (c *Ctx) parseXML(bodyBytes []byte, v any) error {
	if len(bodyBytes) == 0 {
		return fmt.Errorf("empty XML body")
	}

	if err := xml.Unmarshal(bodyBytes, v); err != nil {
		return fmt.Errorf("failed to unmarshal XML: %w", err)
	}
	return nil
}

// parseFormURLEncoded parses application/x-www-form-urlencoded content
func (c *Ctx) parseFormURLEncoded(bodyBytes []byte, v any) error {
	if len(bodyBytes) == 0 {
		return fmt.Errorf("empty form body")
	}

	values, err := url.ParseQuery(string(bodyBytes))
	if err != nil {
		return fmt.Errorf("failed to parse form data: %w", err)
	}

	// Convert url.Values to the target type
	// If v is map[string]string or map[string][]string
	switch target := v.(type) {
	case *map[string]string:
		result := make(map[string]string)
		for key, vals := range values {
			if len(vals) > 0 {
				result[key] = vals[0]
			}
		}
		*target = result

	case *map[string][]string:
		*target = values

	case *map[string]any:
		result := make(map[string]any)
		for key, vals := range values {
			if len(vals) == 1 {
				result[key] = vals[0]
			} else {
				result[key] = vals
			}
		}
		*target = result

	default:
		// Try to convert to JSON first, then unmarshal
		jsonData, err := json.Marshal(values)
		if err != nil {
			return fmt.Errorf("failed to convert form data: %w", err)
		}
		if err := json.Unmarshal(jsonData, v); err != nil {
			return fmt.Errorf("failed to unmarshal form data to struct: %w", err)
		}
	}

	return nil
}

// parseMultipartForm parses multipart/form-data content
func (c *Ctx) parseMultipartForm(v any) error {
	// Parse multipart form (max 32MB in memory)
	if err := c.Req.ParseMultipartForm(32 << 20); err != nil {
		return fmt.Errorf("failed to parse multipart form: %w", err)
	}

	switch target := v.(type) {
	case *map[string]string:
		result := make(map[string]string)
		for key, vals := range c.Req.MultipartForm.Value {
			if len(vals) > 0 {
				result[key] = vals[0]
			}
		}
		*target = result

	case *map[string][]string:
		*target = c.Req.MultipartForm.Value

	case *map[string]any:
		result := make(map[string]any)
		// Add form values
		for key, vals := range c.Req.MultipartForm.Value {
			if len(vals) == 1 {
				result[key] = vals[0]
			} else {
				result[key] = vals
			}
		}
		// Add file info
		if c.Req.MultipartForm.File != nil {
			files := make(map[string]any)
			for key, fileHeaders := range c.Req.MultipartForm.File {
				if len(fileHeaders) == 1 {
					files[key] = map[string]any{
						"filename": fileHeaders[0].Filename,
						"size":     fileHeaders[0].Size,
						"header":   fileHeaders[0].Header,
					}
				} else {
					fileList := make([]map[string]any, len(fileHeaders))
					for i, fh := range fileHeaders {
						fileList[i] = map[string]any{
							"filename": fh.Filename,
							"size":     fh.Size,
							"header":   fh.Header,
						}
					}
					files[key] = fileList
				}
			}
			result["_files"] = files
		}
		*target = result

	default:
		return fmt.Errorf("unsupported type for multipart form data")
	}

	return nil
}

// parsePlainText parses plain text content
func (c *Ctx) parsePlainText(bodyBytes []byte, v any) error {
	switch target := v.(type) {
	case *string:
		*target = string(bodyBytes)
	case *[]byte:
		*target = bodyBytes
	default:
		return fmt.Errorf("plain text can only be parsed into *string or *[]byte")
	}
	return nil
}

// GetFile retrieves a file from multipart form
func (c *Ctx) GetFile(name string) (*multipart.FileHeader, error) {
	if c.Req.MultipartForm == nil {
		if err := c.Req.ParseMultipartForm(32 << 20); err != nil {
			return nil, fmt.Errorf("failed to parse multipart form: %w", err)
		}
	}

	files := c.Req.MultipartForm.File[name]
	if len(files) == 0 {
		return nil, fmt.Errorf("file %s not found", name)
	}

	return files[0], nil
}

// GetFiles retrieves all files from multipart form with the given name
func (c *Ctx) GetFiles(name string) ([]*multipart.FileHeader, error) {
	if c.Req.MultipartForm == nil {
		if err := c.Req.ParseMultipartForm(32 << 20); err != nil {
			return nil, fmt.Errorf("failed to parse multipart form: %w", err)
		}
	}

	files := c.Req.MultipartForm.File[name]
	if len(files) == 0 {
		return nil, fmt.Errorf("files %s not found", name)
	}

	return files, nil
}
func (c *Ctx) Context() context.Context {
	return c.Req.Context()
}

func (c *Ctx) Done() <-chan struct{} {
	return c.Context().Done()
}
func (c *Ctx) Err() error {
	return c.Context().Err()
}
func (c *Ctx) Deadline() (time.Time, bool) {
	return c.Context().Deadline()
}
func (c *Ctx) Value(key any) any {
	return c.Context().Value(key)
}

func (c *Ctx) Json(code int, v any, maskOptions ...logger.MaskingOption) error {
	c.ensureRequestMetadata(c.cmd, nil)
	c.Res.Header().Set("Content-Type", "application/json")
	c.Res.Header().Set("X-Session-ID", c.sessionId)
	c.Res.Header().Set("X-Transaction-ID", c.transactionId)
	c.Res.WriteHeader(code)
	json.NewEncoder(c.Res).Encode(v)

	outgoing := map[string]any{
		"status": code,
		"body":   v,
		"header": c.Res.Header(),
	}
	c.log.Info(logAction.OUTBOUND("response: command-> "+c.cmd+" | status-> "+fmt.Sprint(code)), outgoing, maskOptions...)
	c.log.SetDependencyMetadata(logger.LogDependencyMetadata{}) // Reset detail fields

	summaryLogger := c.Context().Value(middleware.SummaryLoggerKey).(*logger.SummaryLogger)

	params := logger.SummaryParamsType{
		AppResultHttpStatus: fmt.Sprintf("%d", code),
	}
	if code >= 400 {
		params.AppResultType = "Error"
		params.Severity = "Critical"
		params.AppResultCode = "50000"
		params.AppResult = "Failed"
	} else {
		params.AppResultType = "Healthy"
		params.Severity = "Normal"
		params.AppResultCode = "20000"
		params.AppResult = "Success"
	}

	summaryLogger.FlushWithParams(params)
	return nil
}

func (c *Ctx) JsonError(err *errors.Error, body any) error {
	c.ensureRequestMetadata(c.cmd, nil)
	c.Res.Header().Set("Content-Type", "application/json")
	c.Res.Header().Set("X-Session-ID", c.sessionId)
	c.Res.Header().Set("X-Transaction-ID", c.transactionId)
	c.Res.WriteHeader(err.LogDependencyMetadata().AppResultHttpStatus)
	json.NewEncoder(c.Res).Encode(body)

	outgoing := map[string]any{
		"status": err.LogDependencyMetadata().AppResultHttpStatus,
		"body":   body,
		"header": c.Res.Header(),
	}
	c.log.Info(logAction.OUTBOUND("response: command-> "+c.cmd), outgoing)
	c.log.SetDependencyMetadata(logger.LogDependencyMetadata{}) // Reset detail fields
	summaryLogger := c.Context().Value(middleware.SummaryLoggerKey).(*logger.SummaryLogger)
	summaryLogger.FlushError(err)
	return nil
}

func (c *Ctx) Redirect(urlStr string, code int) {
	c.Res.Header().Set("X-Session-ID", c.sessionId)
	c.Res.Header().Set("X-Transaction-ID", c.transactionId)
	c.ensureRequestMetadata(c.cmd, nil)
	http.Redirect(c.Res, c.Req, urlStr, code)
	c.log.Info(logAction.OUTBOUND("redirect: command-> "+c.cmd+" | status-> "+fmt.Sprint(code)+" | location-> "+urlStr), map[string]any{
		"status":   code,
		"location": urlStr,
		"body":     "Found. Redirecting to " + urlStr,
		"header":   c.Res.Header(),
	})
	c.log.SetDependencyMetadata(logger.LogDependencyMetadata{}) // Reset detail fields
	summaryLogger := c.Context().Value(middleware.SummaryLoggerKey).(*logger.SummaryLogger)
	params := logger.SummaryParamsType{
		AppResultHttpStatus: fmt.Sprintf("%d", code),
		AppResultType:       "Redirect",
		Severity:            "Normal",
		AppResultCode:       "30200",
		AppResult:           "Redirected",
	}
	summaryLogger.FlushWithParams(params)
}

func (c *Ctx) RenderTemplate(templateName string, data any) error {
	c.Res.Header().Set("Content-Type", "text/html")
	c.Res.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	c.Res.Header().Set("Pragma", "no-cache")
	c.Res.Header().Set("X-Session-ID", c.sessionId)
	c.Res.Header().Set("X-Transaction-ID", c.transactionId)

	c.ensureRequestMetadata(c.cmd, nil)
	c.log.Info(logAction.OUTBOUND("render template: command-> "+c.cmd+" | template-> "+templateName), map[string]any{
		"body":     data,
		"template": templateName,
		"header":   c.Res.Header(),
	})
	c.log.SetDependencyMetadata(logger.LogDependencyMetadata{}) // Reset detail fields
	summaryLogger := c.Context().Value(middleware.SummaryLoggerKey).(*logger.SummaryLogger)

	tmpl, err := template.ParseFiles(templateName)
	if err != nil {
		summaryLogger.FlushError(&errors.Error{
			Message:       "Failed to parse template",
			Err:           err,
			AppResultCode: "50000",
		})
		return fmt.Errorf("failed to parse template: %w", err)
	}

	res := tmpl.Execute(c.Res, data)
	if res != nil {
		summaryLogger.FlushError(&errors.Error{
			Message:       "Failed to execute template",
			Err:           res,
			AppResultCode: "50000",
		})
		return fmt.Errorf("failed to execute template: %w", res)
	} else {
		params := logger.SummaryParamsType{
			AppResultHttpStatus: "200",
			AppResultType:       "Healthy",
			Severity:            "Normal",
			AppResultCode:       "20000",
			AppResult:           "Success",
		}
		summaryLogger.FlushWithParams(params)
	}
	return res
}
