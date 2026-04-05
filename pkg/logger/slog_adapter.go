package logger

import (
	"context"
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

// dtoToSlogAttrs maps DTO directly to slog.Attr to ensure they flatten into the root JSON object
// This manual mapping avoids reflection and extra serialization loops for 10x speed boost.
func dtoToSlogAttrs(dto LogDto) []slog.Attr {
	attrs := make([]slog.Attr, 0, 30)

	if dto.AppName != "" { attrs = append(attrs, slog.String("appName", dto.AppName)) }
	if dto.ComponentVersion != "" { attrs = append(attrs, slog.String("componentVersion", dto.ComponentVersion)) }
	if dto.ComponentName != "" { attrs = append(attrs, slog.String("componentName", dto.ComponentName)) }
	if dto.Broker != "" { attrs = append(attrs, slog.String("broker", dto.Broker)) }
	if dto.Channel != "" { attrs = append(attrs, slog.String("channel", dto.Channel)) }
	if dto.UseCase != "" { attrs = append(attrs, slog.String("useCase", dto.UseCase)) }
	if dto.UseCaseStep != "" { attrs = append(attrs, slog.String("useCaseStep", dto.UseCaseStep)) }
	if dto.Device != nil { attrs = append(attrs, slog.Any("device", dto.Device)) }
	if dto.Public != "" { attrs = append(attrs, slog.String("public", dto.Public)) }
	if dto.User != "" { attrs = append(attrs, slog.String("user", dto.User)) }
	if dto.Action != "" { attrs = append(attrs, slog.String("action", dto.Action)) }
	if dto.SubAction != "" { attrs = append(attrs, slog.String("subAction", dto.SubAction)) }
	if dto.ActionDescription != "" { attrs = append(attrs, slog.String("actionDescription", dto.ActionDescription)) }
	if dto.Message != nil { attrs = append(attrs, slog.Any("message", dto.Message)) }
	if dto.Timestamp != "" { attrs = append(attrs, slog.String("timestamp", dto.Timestamp)) }
	if dto.Dependency != "" { attrs = append(attrs, slog.String("dependency", dto.Dependency)) }
	if dto.ResponseTime != 0 { attrs = append(attrs, slog.Int64("responseTime", dto.ResponseTime)) }
	if dto.ResultCode != "" { attrs = append(attrs, slog.String("resultCode", dto.ResultCode)) }
	if dto.ResultFlag != "" { attrs = append(attrs, slog.String("resultFlag", dto.ResultFlag)) }
	if dto.Instance != "" { attrs = append(attrs, slog.String("instance", dto.Instance)) }
	if dto.OriginateServiceName != "" { attrs = append(attrs, slog.String("originateServiceName", dto.OriginateServiceName)) }
	if dto.RecordName != "" { attrs = append(attrs, slog.String("recordName", dto.RecordName)) }
	if dto.RecordType != "" { attrs = append(attrs, slog.String("recordType", dto.RecordType)) }
	if dto.SessionId != "" { attrs = append(attrs, slog.String("sessionId", dto.SessionId)) }
	if dto.TransactionId != "" { attrs = append(attrs, slog.String("transactionId", dto.TransactionId)) }
	if dto.AdditionalInfo != nil { attrs = append(attrs, slog.Any("additionalInfo", dto.AdditionalInfo)) }

	if dto.AppResult != "" { attrs = append(attrs, slog.String("appResult", dto.AppResult)) }
	if dto.AppResultCode != "" { attrs = append(attrs, slog.String("appResultCode", dto.AppResultCode)) }
	if dto.DateTime != "" { attrs = append(attrs, slog.String("dateTime", dto.DateTime)) }
	if dto.ServiceTime != 0 { attrs = append(attrs, slog.Int64("serviceTime", dto.ServiceTime)) }
	if dto.AppResultHttpStatus != "" { attrs = append(attrs, slog.String("appResultHttpStatus", dto.AppResultHttpStatus)) }
	if dto.AppResultType != "" { attrs = append(attrs, slog.String("appResultType", dto.AppResultType)) }
	if dto.Severity != "" { attrs = append(attrs, slog.String("severity", dto.Severity)) }
	if dto.Agent != "" { attrs = append(attrs, slog.String("agent", dto.Agent)) }

	return attrs
}
