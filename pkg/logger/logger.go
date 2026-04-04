package logger

import (
	"encoding/json"
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

	bytes, _ := json.Marshal(clonedData)
	c.logDto.Message = string(bytes)

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

	bytes, _ := json.Marshal(clonedData)
	c.logDto.Message = string(bytes)

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

	bytes, _ := json.Marshal(clonedData)
	c.logDto.Message = string(bytes)

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
