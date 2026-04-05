package logger

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// BaseLoggerInterface abstractions the underlying logger engine (Slog, Zap, etc)
type BaseLoggerInterface interface {
	LogInfo(dto LogDto)
	LogDebug(dto LogDto)
	LogError(dto LogDto, stack string)
}

// CustomLogger replicates CustomLoggerService from TypeScript
type CustomLogger struct {
	logDto     LogDto
	baseLogger BaseLoggerInterface
	maskingSvc MaskingService
}

func NewCustomLogger(base BaseLoggerInterface, masking MaskingService, initialData LogDto) *CustomLogger {
	if masking == nil {
		masking = &DefaultMaskingService{}
	}
	return &CustomLogger{
		logDto:     initialData,
		baseLogger: base,
		maskingSvc: masking,
	}
}

// Info logs an informational message with the provided action data and options for masking sensitive information.
func (c *CustomLogger) Info(actionData LoggerAction, data any, maskOptions ...MaskingOption) {
	c.logDto.Action = actionData.Action
	c.logDto.ActionDescription = actionData.ActionDescription
	c.logDto.SubAction = actionData.SubAction
	c.logDto.Timestamp = time.Now().Format("2006-01-02 15:04:05.000")

	clonedData := DeepCloneAndMask(data, maskOptions, c.maskingSvc)

	c.logDto.Message = ToString(clonedData)

	if c.baseLogger != nil {
		c.baseLogger.LogInfo(c.logDto)
	}

	if c.logDto.SubAction != "" {
		c.logDto.SubAction = ""
	}
	c.clearDependencyMetadata()
	c.clearAdditionalInfo()
}

// Debug logs a debug message with the provided action data and options for masking sensitive information.
func (c *CustomLogger) Debug(actionData LoggerAction, data any, maskOptions ...MaskingOption) {
	c.logDto.Action = actionData.Action
	c.logDto.ActionDescription = actionData.ActionDescription
	c.logDto.SubAction = actionData.SubAction
	c.logDto.Timestamp = time.Now().Format("2006-01-02 15:04:05.000")

	clonedData := DeepCloneAndMask(data, maskOptions, c.maskingSvc)

	c.logDto.Message = ToString(clonedData)

	if c.baseLogger != nil {
		c.baseLogger.LogDebug(c.logDto)
	}

	if c.logDto.SubAction != "" {
		c.logDto.SubAction = ""
	}
	c.clearDependencyMetadata()
	c.clearAdditionalInfo()
}

// Error logs an error message with the provided action data, additional data, stack trace, and masking options.
func (c *CustomLogger) Error(actionData LoggerAction, data any, stack string, maskOptions ...MaskingOption) {
	c.logDto.Action = actionData.Action
	c.logDto.ActionDescription = actionData.ActionDescription
	c.logDto.SubAction = actionData.SubAction
	c.logDto.Timestamp = time.Now().Format("2006-01-02 15:04:05.000")

	clonedData := DeepCloneAndMask(data, maskOptions, c.maskingSvc)

	c.logDto.Message = ToString(clonedData)

	if c.baseLogger != nil {
		c.baseLogger.LogError(c.logDto, stack)
	}

	if c.logDto.SubAction != "" {
		c.logDto.SubAction = ""
	}
	c.clearDependencyMetadata()
	c.clearAdditionalInfo()
}

func (c *CustomLogger) SetDependencyMetadata(metadata LogDependencyMetadata) *CustomLogger {
	c.logDto.Dependency = metadata.Dependency
	c.logDto.ResponseTime = metadata.ResponseTime
	c.logDto.ResultCode = metadata.ResultCode
	c.logDto.ResultFlag = metadata.ResultFlag
	// Note: in TypeScript `_dependencyInvokeCall` flag is set.
	return c
}

func (c *CustomLogger) GetLogDto() LogDto {
	return c.logDto
}

func (c *CustomLogger) Update(key string, value any) {
	// A reflective mapper could be implemented. Handled per explicitly needed fields in practice.
	switch strings.ToLower(key) {
	case "sessionid":
		if v, ok := value.(string); ok {
			c.logDto.SessionId = v
		}
	case "transactionid":
		if v, ok := value.(string); ok {
			c.logDto.TransactionId = v
		}
	case "componentversion":
		if v, ok := value.(string); ok {
			c.logDto.ComponentVersion = v
		}
	case "channel":
		if v, ok := value.(string); ok {
			c.logDto.Channel = v
		}
	case "agent":
		if v, ok := value.(string); ok {
			c.logDto.Agent = v
		}
	case "recordname":
		if v, ok := value.(string); ok {
			c.logDto.RecordName = v
		}
	}
}

func (c *CustomLogger) clearDependencyMetadata() {
	if c.logDto.Dependency != "" || c.logDto.ResponseTime != 0 || c.logDto.ResultCode != "" || c.logDto.ResultFlag != "" {
		c.logDto.Dependency = ""
		c.logDto.ResponseTime = 0
		c.logDto.ResultCode = ""
		c.logDto.ResultFlag = ""
	}
}

func (c *CustomLogger) clearAdditionalInfo() {
	c.logDto.AdditionalInfo = nil
}

func ToString(v any) (result string) {
	if v == nil {
		return "null"
	}
	if s, ok := v.(string); ok {
		return s
	}

	defer func() {
		if r := recover(); r != nil {
			result = "null"
		}
	}()

	if b, err := json.Marshal(v); err == nil {
		return string(b)
	}

	return fmt.Sprintf("%v", v)
}
