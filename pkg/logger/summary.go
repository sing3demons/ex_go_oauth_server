package logger

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/sing3demons/oauth_server/pkg/response"
)

// SummaryParamsType defines parameters specific to summary logs
type SummaryParamsType struct {
	AppResult           string
	AppResultCode       string
	AppResultHttpStatus string
	AppResultType       string
	Severity            string
}

// SummaryLogger handles the emission of Summary logs (stripping detail-level metadata)
type SummaryLogger struct {
	baseLogger   BaseLoggerInterface
	customLogger *CustomLogger
	util         LoggerUtil
}

// LoggerUtil interface to mock or provide timestamps and service time offsets
type LoggerUtil interface {
	GetBeginTime() time.Time
}

type DefaultLoggerUtil struct {
	BeginTime time.Time
}

func (d *DefaultLoggerUtil) GetBeginTime() time.Time {
	return d.BeginTime
}

func NewSummaryLogger(base BaseLoggerInterface, detailLogger *CustomLogger, util LoggerUtil) *SummaryLogger {
	if util == nil {
		util = &DefaultLoggerUtil{BeginTime: time.Now()} // default fallback
	}
	return &SummaryLogger{
		baseLogger:   base,
		customLogger: detailLogger,
		util:         util,
	}
}

func (s *SummaryLogger) Flush() {
	dto := s.customLogger.GetLogDto()

	// Inject summary properties
	dto.RecordType = "summary"
	dto.DateTime = time.Now().Format("2006-01-02 15:04:05.000")
	dto.ServiceTime = time.Since(s.util.GetBeginTime()).Milliseconds()

	// Use generic defaults if they were unset initially
	if dto.AppResultHttpStatus == "" {
		if dto.AppResultCode != "" && len(dto.AppResultCode) >= 3 {
			dto.AppResultHttpStatus = dto.AppResultCode[:3]
		} else {
			dto.AppResultHttpStatus = "200"
		}
	}
	if dto.AppResultType == "" {
		dto.AppResultType = "Healthy"
	}
	if dto.Severity == "" {
		dto.Severity = "Normal"
	}
	if dto.AppResult == "" {
		dto.AppResult = "Success"
	}
	if dto.AppResultCode == "" {
		dto.AppResultCode = "20000"
	}

	s.clearDetailedFields(&dto)

	s.baseLogger.LogInfo(dto)
}

func (s *SummaryLogger) FlushWithParams(params SummaryParamsType) {
	dto := s.customLogger.GetLogDto()

	// Inject summary properties
	dto.RecordType = "summary"
	dto.DateTime = time.Now().Format("2006-01-02 15:04:05.000")
	dto.ServiceTime = time.Since(s.util.GetBeginTime()).Milliseconds()

	dto.AppResultHttpStatus = params.AppResultHttpStatus
	dto.AppResultType = params.AppResultType
	dto.Severity = params.Severity
	dto.AppResult = params.AppResult
	dto.AppResultCode = params.AppResultCode

	// Use generic defaults if they were unset initially
	if dto.AppResultHttpStatus == "" {
		if dto.AppResultCode != "" && len(dto.AppResultCode) >= 3 {
			dto.AppResultHttpStatus = dto.AppResultCode[:3]
		} else {
			dto.AppResultHttpStatus = "200"
		}
	}
	if dto.AppResultType == "" {
		dto.AppResultType = "Healthy"
	}
	if dto.Severity == "" {
		dto.Severity = "Normal"
	}
	if dto.AppResult == "" {
		dto.AppResult = "Success"
	}
	if dto.AppResultCode == "" {
		dto.AppResultCode = "20000"
	}

	s.clearDetailedFields(&dto)

	s.baseLogger.LogInfo(dto)
}

func (s *SummaryLogger) FlushWithParamsError(params SummaryParamsType, stack string) {
	dto := s.customLogger.GetLogDto()

	// Inject summary properties
	dto.RecordType = "summary"
	dto.DateTime = time.Now().Format("2006-01-02 15:04:05.000")
	dto.ServiceTime = time.Since(s.util.GetBeginTime()).Milliseconds()

	dto.AppResultHttpStatus = params.AppResultHttpStatus
	dto.AppResultType = params.AppResultType
	dto.Severity = params.Severity
	dto.AppResult = params.AppResult
	dto.AppResultCode = params.AppResultCode

	// Use generic defaults if they were unset initially
	if dto.AppResultHttpStatus == "" {
		if dto.AppResultCode != "" && len(dto.AppResultCode) >= 3 {
			dto.AppResultHttpStatus = dto.AppResultCode[:3]
		} else {
			dto.AppResultHttpStatus = "500"
		}
	}
	if dto.AppResultType == "" {
		dto.AppResultType = "Error"
	}
	if dto.Severity == "" {
		dto.Severity = "Error"
	}
	if dto.AppResult == "" {
		dto.AppResult = "Failed"
	}
	if dto.AppResultCode == "" {
		dto.AppResultCode = "50000"
	}

	s.clearDetailedFields(&dto)

	s.baseLogger.LogError(dto, stack)
}

func (s *SummaryLogger) FlushError(err *response.Error) {
	dto := s.customLogger.GetLogDto()

	// Inject summary properties
	dto.RecordType = "summary"
	dto.DateTime = time.Now().Format("2006-01-02 15:04:05.000")
	dto.ServiceTime = time.Since(s.util.GetBeginTime()).Milliseconds()

	errData := err.LogDependencyMetadata()

	dto.AppResultHttpStatus = fmt.Sprintf("%d", errData.AppResultHttpStatus)

	dto.AppResultType = errData.AppResultType
	dto.Severity = errData.Severity
	dto.AppResultCode = errData.AppResultCode
	dto.AppResult = errData.AppResult

	// Update the message payload if needed (usually empty for summary error or populated with basic log message)
	b, _ := json.Marshal(errData)
	dto.Message = string(b)

	s.clearDetailedFields(&dto)

	s.baseLogger.LogError(dto, err.Err.Error())
}

func getString(v any) string {
	if str, ok := v.(string); ok {
		return str
	}
	// Simple fallback format
	bytes, _ := json.Marshal(v)
	return string(bytes)
}

// clearDetailedFields strips operational metadata just like TS clearNonSummaryLogParam
func (s *SummaryLogger) clearDetailedFields(dto *LogDto) {
	dto.Action = ""
	dto.Message = nil
	dto.Timestamp = ""
	dto.Dependency = ""
	dto.ResponseTime = 0
	dto.ResultCode = ""
	dto.ResultFlag = ""
	dto.ActionDescription = ""
}
