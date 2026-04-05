package logger

// LogDto defines the structure of the log data based on the TypeScript implementation.
// It maps directly to `LogDtoType` and uses `omitempty` to mirror optional TS fields.
type LogDto struct {
	AppName              string `json:"appName,omitempty"`
	ComponentVersion     string `json:"componentVersion,omitempty"`
	ComponentName        string `json:"componentName,omitempty"`
	Broker               string `json:"broker,omitempty"`
	Channel              string `json:"channel,omitempty"`
	UseCase              string `json:"useCase,omitempty"`
	UseCaseStep          string `json:"useCaseStep,omitempty"`
	Device               any    `json:"device,omitempty"`
	Public               string `json:"public,omitempty"`
	User                 string `json:"user,omitempty"`
	Action               string `json:"action,omitempty"`
	SubAction            string `json:"subAction,omitempty"`
	ActionDescription    string `json:"actionDescription,omitempty"`
	Message              any    `json:"message,omitempty"`
	Timestamp            string `json:"timestamp,omitempty"`
	Dependency           string `json:"dependency,omitempty"`
	ResponseTime         int64  `json:"responseTime,omitempty"`
	ResultCode           string `json:"resultCode,omitempty"`
	ResultFlag           string `json:"resultFlag,omitempty"`
	Instance             string `json:"instance,omitempty"`
	OriginateServiceName string `json:"originateServiceName,omitempty"`
	RecordName           string `json:"recordName,omitempty"`
	RecordType           string `json:"recordType,omitempty"`
	SessionId            string `json:"sessionId,omitempty"`
	TransactionId        string `json:"transactionId,omitempty"`
	AdditionalInfo       any    `json:"additionalInfo,omitempty"`

	// Summary log parameters
	AppResult           string `json:"appResult,omitempty"`
	AppResultCode       string `json:"appResultCode,omitempty"`
	DateTime            string `json:"dateTime,omitempty"`
	ServiceTime         int64  `json:"serviceTime,omitempty"`
	AppResultHttpStatus string `json:"appResultHttpStatus,omitempty"`
	AppResultType       string `json:"appResultType,omitempty"`
	Severity            string `json:"severity,omitempty"`
	Agent               string `json:"agent,omitempty"`
}

// LogDependencyMetadata holds metadata regarding a dependency action.
type LogDependencyMetadata struct {
	Dependency   string
	ResponseTime int64
	ResultCode   string
	ResultFlag   string
}

// ActionData defines context context about an action being logged.
// type ActionData struct {
// 	Action            string
// 	ActionDescription string
// 	SubAction         string
// }

type LoggerAction struct {
	Action            string `json:"action"`
	ActionDescription string `json:"actionDescription"`
	SubAction         string `json:"subAction,omitempty"`
}
