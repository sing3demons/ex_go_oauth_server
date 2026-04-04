package logger

import (
	"encoding/json"
	"go.uber.org/zap"
)

// ZapAdapter implements BaseLoggerInterface for go.uber.org/zap
type ZapAdapter struct {
	logger *zap.Logger
}

func NewZapAdapter(l *zap.Logger) *ZapAdapter {
	return &ZapAdapter{logger: l}
}

func (z *ZapAdapter) LogInfo(dto LogDto) {
	fields := dtoToZapFields(dto)
	z.logger.Info("", fields...)
}

func (z *ZapAdapter) LogDebug(dto LogDto) {
	fields := dtoToZapFields(dto)
	z.logger.Debug("", fields...)
}

func (z *ZapAdapter) LogError(dto LogDto, stack string) {
	fields := dtoToZapFields(dto)
	if stack != "" {
		fields = append(fields, zap.String("stack", stack))
	}
	z.logger.Error("", fields...)
}

// dtoToZapFields uses JSON marshaling to retrieve properties configured to omit empty strings
func dtoToZapFields(dto LogDto) []zap.Field {
	b, err := json.Marshal(dto)
	if err != nil {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil
	}

	fields := make([]zap.Field, 0, len(m))
	for k, v := range m {
		fields = append(fields, zap.Any(k, v))
	}
	return fields
}
