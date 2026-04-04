package logger

import (
	"context"
	"encoding/json"
	"log/slog"
)

// SlogAdapter implements BaseLoggerInterface for log/slog
type SlogAdapter struct {
	logger *slog.Logger
}

func NewSlogAdapter(l *slog.Logger) *SlogAdapter {
	return &SlogAdapter{logger: l}
}

func (s *SlogAdapter) LogInfo(dto LogDto) {
	attrs := dtoToSlogAttrs(dto)
	s.logger.LogAttrs(context.Background(), slog.LevelInfo, "", attrs...)
}

func (s *SlogAdapter) LogDebug(dto LogDto) {
	attrs := dtoToSlogAttrs(dto)
	s.logger.LogAttrs(context.Background(), slog.LevelDebug, "", attrs...)
}

func (s *SlogAdapter) LogError(dto LogDto, stack string) {
	attrs := dtoToSlogAttrs(dto)
	if stack != "" {
		attrs = append(attrs, slog.String("stack", stack))
	}
	s.logger.LogAttrs(context.Background(), slog.LevelError, "", attrs...)
}

// dtoToSlogAttrs uses json.Marshal to get correct omitempty behavior easily,
// then maps them to slog.Attr to ensure they flatten into the root JSON object
func dtoToSlogAttrs(dto LogDto) []slog.Attr {
	b, err := json.Marshal(dto)
	if err != nil {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil
	}

	attrs := make([]slog.Attr, 0, len(m))
	for k, v := range m {
		attrs = append(attrs, slog.Any(k, v))
	}
	return attrs
}
