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
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/sing3demons/oauth_server/internal/config"
	"github.com/sing3demons/oauth_server/pkg/constants"
	"github.com/sing3demons/oauth_server/pkg/logAction"
	"github.com/sing3demons/oauth_server/pkg/logger"
	"github.com/sing3demons/oauth_server/pkg/mlog"
	"github.com/sing3demons/oauth_server/pkg/response"
	"github.com/sing3demons/oauth_server/pkg/utils"
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
	bodyBytes     []byte
	bodyMap       map[string]any
	tmpMgr        *TemplateManager
}

var ctxPool = sync.Pool{
	New: func() any {
		return &Ctx{}
	},
}

// Reset clears the state of Ctx so it can be safely reused
func (c *Ctx) Reset(r *http.Request, w http.ResponseWriter, cfg *config.Config, tmpMgr *TemplateManager) {
	c.Req = r
	c.Res = w
	if r != nil {
		c.log = mlog.L(r.Context())
	} else {
		c.log = nil
	}
	c.cmd = ""
	c.cfg = cfg
	c.sessionId = ""
	c.transactionId = ""
	c.bodyBytes = nil
	c.bodyMap = nil
	c.tmpMgr = tmpMgr
}

// AcquireCtx gets a Ctx from the pool and initializes it
func AcquireCtx(r *http.Request, w http.ResponseWriter, cfg *config.Config, tmpMgr *TemplateManager) *Ctx {
	ctx := ctxPool.Get().(*Ctx)
	ctx.Reset(r, w, cfg, tmpMgr)
	return ctx
}

// ReleaseCtx puts a Ctx back into the pool, releasing references for GC
func ReleaseCtx(c *Ctx) {
	c.Reset(nil, nil, nil, nil) // Clear references to allow GC
	ctxPool.Put(c)
}
func (c *Ctx) Log(cmd string, maskOptions ...logger.MaskingOption) *logger.CustomLogger {
	c.cmd = cmd

	// ✅ Lazy parse body into map if not already done
	if c.bodyMap == nil {
		body := make(map[string]any)
		if err := c.Bind(&body); err == nil {
			c.bodyMap = body
		}
	}
	body := c.bodyMap

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

	switch cmd {
	case "authorize":
		if cookie, err := c.Req.Cookie("oidc_session"); err == nil && cookie.Value != "" {
			c.sessionId = cookie.Value
		}
	case "token_authorization_code":
		code := c.Req.FormValue("code")
		if code != "" && len(code) <= 22 {
			c.sessionId = code[:22]
		}
	}

	if c.sessionId == "" {
		c.sessionId = c.resolveSessionId("X-Session-ID", "sid", body)
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

func (c *Ctx) UpdateSessionId(val string) string {
	c.sessionId = val
	c.log.Update("SessionId", c.sessionId)
	ctx := c.Req.Context()
	ctx = context.WithValue(ctx, SessionID, c.sessionId)
	c.Req = c.Req.WithContext(ctx)

	return c.sessionId
}

func (c *Ctx) UpdateTransactionId(val string) string {
	c.transactionId = val
	c.log.Update("TransactionId", c.transactionId)
	ctx := c.Req.Context()
	ctx = context.WithValue(ctx, TransactionID, c.transactionId)
	c.Req = c.Req.WithContext(ctx)

	return c.transactionId
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
func (c *Ctx) resolveSessionId(headerName, paramName string, body map[string]any) string {
	if value := c.Req.Header.Get(headerName); value != "" {
		return value
	}
	if value := c.Req.URL.Query().Get(paramName); value != "" {
		return value
	}
	if value := stringifyBodyValue(body[paramName]); value != "" {
		return value
	}
	return utils.NewSessionID()
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

	// Multipart requires streaming instead of loading entirely into a slice
	if ContentType(baseContentType) == ContentTypeMultipartForm {
		return c.parseMultipartForm(v)
	}

	// Limit body size to prevent DoS, load into cache if not yet read
	if c.bodyBytes == nil && c.Req.Body != nil {
		limitedReader := io.LimitReader(c.Req.Body, MaxBodySize)
		bodyBytes, err := io.ReadAll(limitedReader)
		if err != nil {
			return fmt.Errorf("failed to read request body: %w", err)
		}
		// Check if body exceeded limit
		if int64(len(bodyBytes)) >= MaxBodySize {
			return fmt.Errorf("request body too large (max %d bytes)", MaxBodySize)
		}
		c.bodyBytes = bodyBytes
		// Restore body for potential raw reads (e.g. proxying bypassing Bind)
		c.Req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}

	// Parse based on content type using cached byte array
	ctype := ContentType(baseContentType)
	if ctype == ContentTypeJSON {
		// ✅ Optimization: if already parsed into map, just copy it
		if c.bodyMap != nil {
			if m, ok := v.(*map[string]any); ok {
				*m = c.bodyMap
				return nil
			}
		}

		err := c.parseJSON(c.bodyBytes, v)
		if err == nil && c.bodyMap == nil {
			// Cache the map for future use if v is a map
			if m, ok := v.(*map[string]any); ok {
				c.bodyMap = *m
			} else {
				// If v is a struct, we could optionally parse into a map too,
				// but let's keep it simple and only cache if a map is requested.
			}
		}
		return err
	}

	switch ctype {
	case ContentTypeXML:
		return c.parseXML(c.bodyBytes, v)

	case ContentTypeForm:
		return c.parseFormURLEncoded(c.bodyBytes, v)

	case ContentTypePlainText:
		return c.parsePlainText(c.bodyBytes, v)

	default:
		return fmt.Errorf("unsupported content type: %s", contentType)
	}
}
func (c *Ctx) Query(key string) string {
	return c.Req.URL.Query().Get(key)
}
func (c *Ctx) FormValue(key string) string {
	return c.Req.FormValue(key)
}
func (c *Ctx) UserAgent() string {
	return c.Req.UserAgent()
}
func (c *Ctx) IP() string {
	ip := c.Req.RemoteAddr
	if forwarded := c.Req.Header.Get("X-Forwarded-For"); forwarded != "" {
		ip = forwarded
	}
	return ip
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

func (c *Ctx) SetHeader(key, value string) {
	c.Res.Header().Set(key, value)
}
func (c *Ctx) JSON(code int, v any, maskOptions ...logger.MaskingOption) error {
	c.ensureRequestMetadata(c.cmd, nil)
	c.SetHeader("Content-Type", "application/json")
	c.SetHeader("X-Session-ID", c.sessionId)
	c.SetHeader("X-Transaction-ID", c.transactionId)
	c.Res.WriteHeader(code)
	json.NewEncoder(c.Res).Encode(v)

	outgoing := map[string]any{
		"status": code,
		"body":   v,
		"header": c.Res.Header(),
	}
	c.log.Info(logAction.OUTBOUND("response: command-> "+c.cmd+" | status-> "+fmt.Sprint(code)), outgoing, maskOptions...)
	c.log.SetDependencyMetadata(logger.LogDependencyMetadata{}) // Reset detail fields

	summaryLogger := c.Context().Value(constants.SummaryLoggerKey).(*logger.SummaryLogger)

	params := logger.SummaryParamsType{
		AppResultHttpStatus: fmt.Sprintf("%d", code),
	}
	if code >= 400 {
		params.AppResultType = "Error"
		params.Severity = "Critical"
		params.AppResultCode = ToFiveDigitString(code)
		params.AppResult = "Failed"
	} else {
		params.AppResultType = "Healthy"
		params.Severity = "Normal"
		params.AppResultCode = ToFiveDigitString(code)
		params.AppResult = "Success"
	}

	summaryLogger.FlushWithParams(params)
	return nil
}

func (c *Ctx) JsonError(err *response.Error, body any) error {
	c.ensureRequestMetadata(c.cmd, nil)
	c.SetHeader("Content-Type", "application/json")
	c.SetHeader("X-Session-ID", c.sessionId)
	c.SetHeader("X-Transaction-ID", c.transactionId)
	c.Res.WriteHeader(err.LogDependencyMetadata().AppResultHttpStatus)
	json.NewEncoder(c.Res).Encode(body)

	outgoing := map[string]any{
		"status": err.LogDependencyMetadata().AppResultHttpStatus,
		"body":   body,
		"header": c.Res.Header(),
	}
	c.log.Info(logAction.OUTBOUND("response: command-> "+c.cmd), outgoing)
	c.log.SetDependencyMetadata(logger.LogDependencyMetadata{}) // Reset detail fields
	summaryLogger := c.Context().Value(constants.SummaryLoggerKey).(*logger.SummaryLogger)
	summaryLogger.FlushError(err)
	return nil
}

func (c *Ctx) Redirect(urlStr string, code int) {
	c.SetHeader("X-Session-ID", c.sessionId)
	c.SetHeader("X-Transaction-ID", c.transactionId)
	c.ensureRequestMetadata(c.cmd, nil)
	http.Redirect(c.Res, c.Req, urlStr, code)
	c.log.Info(logAction.OUTBOUND("redirect: command-> "+c.cmd+" | status-> "+fmt.Sprint(code)+" | location-> "+urlStr), map[string]any{
		"status":   code,
		"location": urlStr,
		"body":     "Found. Redirecting to " + urlStr,
		"header":   c.Res.Header(),
	})
	c.log.SetDependencyMetadata(logger.LogDependencyMetadata{}) // Reset detail fields
	summaryLogger := c.Context().Value(constants.SummaryLoggerKey).(*logger.SummaryLogger)
	params := logger.SummaryParamsType{
		AppResultHttpStatus: fmt.Sprintf("%d", code),
		AppResultType:       "Redirect",
		Severity:            "Normal",
		AppResultCode:       ToFiveDigitString(code),
		AppResult:           "Redirected",
	}
	summaryLogger.FlushWithParams(params)
}

// constraint: รับเฉพาะ int / int64 / string
type NumberOrString interface {
	~int | ~int64 | ~string
}

func ToFiveDigitString[T NumberOrString](v T) string {
	var s string

	switch any(v).(type) {
	case int:
		s = strconv.Itoa(any(v).(int))
	case int64:
		s = strconv.FormatInt(any(v).(int64), 10)
	case string:
		s = any(v).(string)
	}

	// เติม 0 ด้านขวาให้ครบ 5 ตัว
	for len(s) < 5 {
		s += "0"
	}

	// ตัดให้เหลือ 5 (optional)
	if len(s) > 5 {
		s = s[:5]
	}

	return s
}

func (c *Ctx) GetValUniversal(data any, key string) (string, bool) {
	// case: map
	if m, ok := data.(map[string]any); ok {
		val, exists := m[key]
		if exists {
			if str, ok := val.(string); ok {
				return str, true
			}
		}
		return "", exists
	}

	// case: struct
	v := reflect.ValueOf(data)
	if v.Kind() == reflect.Pointer {
		v = v.Elem()
	}

	if v.Kind() == reflect.Struct {
		field := v.FieldByName("Error")
		if field.IsValid() {
			if str, ok := field.Interface().(string); ok {
				return str, true
			}
		}
	}

	return "", false
}

func (c *Ctx) RenderTemplate(templateName string, data any, code int) error {
	c.SetHeader("Content-Type", "text/html")
	c.SetHeader("Cache-Control", "no-cache, no-store, must-revalidate")
	c.SetHeader("Pragma", "no-cache")
	c.SetHeader("X-Session-ID", c.sessionId)
	c.SetHeader("X-Transaction-ID", c.transactionId)

	c.ensureRequestMetadata(c.cmd, nil)
	c.log.Info(logAction.OUTBOUND("render template: command-> "+c.cmd+" | template-> "+templateName), map[string]any{
		"body":     data,
		"template": templateName,
		"header":   c.Res.Header(),
	})
	c.log.SetDependencyMetadata(logger.LogDependencyMetadata{}) // Reset detail fields
	summaryLogger := c.Context().Value(constants.SummaryLoggerKey).(*logger.SummaryLogger)

	if c.tmpMgr != nil {
		tmpl, err := c.tmpMgr.GetTemplate(templateName)
		if err == nil {
			err = tmpl.ExecuteTemplate(c.Res, filepath.Base(templateName), data)
			if err == nil {
				return nil
			}

			summaryLogger.FlushError(&response.Error{
				Message: response.SystemError,
				Err:     err,
			})
			return fmt.Errorf("failed to execute template: %w", err)
		}
	}

	// Fallback to parsing files if manager not found or failed
	tmpl, err := template.New(templateName).Funcs(template.FuncMap{
		"contains": strings.Contains,
		"substr": func(s string, start, end int) string {
			if len(s) < end {
				return s[start:]
			}
			return s[start:end]
		},
		"upper": strings.ToUpper,
	}).ParseFiles(templateName)
	if err != nil {
		summaryLogger.FlushError(&response.Error{
			Message: response.SystemError,
			Err:     err,
		})
		return fmt.Errorf("failed to parse template: %w", err)
	}

	// 🏮 ParseFiles parses only the first file as the name, we need to match it
	res := tmpl.ExecuteTemplate(c.Res, filepath.Base(templateName), data)
	if res != nil {
		summaryLogger.FlushError(&response.Error{
			Message: response.SystemError,
			Err:     res,
		})
		return fmt.Errorf("failed to execute template: %w", res)
	} else {
		// check code
		appResultCode := ToFiveDigitString(code)
		appResult := "Success"
		severity := "Normal"
		appResultType := "Healthy"
		if code >= 400 {
			appResult = "Failed"
			severity = "Critical"
			appResultType = "Error"
			if val, ok := c.GetValUniversal(data, "Error"); ok {
				appResult = val
			}

			params := logger.SummaryParamsType{
				AppResultHttpStatus: fmt.Sprintf("%d", code),
				AppResultType:       appResultType,
				Severity:            severity,
				AppResultCode:       appResultCode,
				AppResult:           appResult,
			}
			summaryLogger.FlushWithParamsError(params, appResult)
			return nil
		}
		params := logger.SummaryParamsType{
			AppResultHttpStatus: fmt.Sprintf("%d", code),
			AppResultType:       appResultType,
			Severity:            severity,
			AppResultCode:       appResultCode,
			AppResult:           appResult,
		}
		summaryLogger.FlushWithParams(params)

	}
	return res
}
