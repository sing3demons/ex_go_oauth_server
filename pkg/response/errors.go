package response

import (
	"errors"
)

var ErrNotFound = errors.New("not_found")

type SummaryParamsType struct {
	AppResult           string
	AppResultCode       string
	AppResultHttpStatus int
	AppResultType       string
	Severity            string
}

type Error struct {
	Message MessageError
	Err     error
}

func (e *Error) Error() string {
	return string(e.Message)
}

func (e *Error) Unwrap() error {
	return e.Err
}

func (e *Error) LogDependencyMetadata() SummaryParamsType {
	switch e.Message {
	case MissingOrInvalidParameter:
		return SummaryParamsType{
			AppResult:           e.Message.APIResponse().DeveloperMessage,
			AppResultCode:       e.Message.ResultCode(),
			AppResultHttpStatus: e.Message.HTTPStatus(),
			AppResultType:       "CLIENT_ERROR",
			Severity:            "MAJOR_ISSUE",
		}
	case InvalidRequest:
		return SummaryParamsType{
			AppResult:           e.Message.APIResponse().DeveloperMessage,
			AppResultCode:       e.Message.ResultCode(),
			AppResultHttpStatus: e.Message.HTTPStatus(),
			AppResultType:       "CLIENT_ERROR",
			Severity:            "MAJOR_ISSUE",
		}
	case InvalidCode:
		return SummaryParamsType{
			AppResult:           e.Message.APIResponse().DeveloperMessage,
			AppResultCode:       e.Message.ResultCode(),
			AppResultHttpStatus: e.Message.HTTPStatus(),
			AppResultType:       "CLIENT_ERROR",
			Severity:            "MAJOR_ISSUE",
		}
	case InvalidGrant:
		return SummaryParamsType{
			AppResult:           e.Message.APIResponse().DeveloperMessage,
			AppResultCode:       e.Message.ResultCode(),
			AppResultHttpStatus: e.Message.HTTPStatus(),
			AppResultType:       "CLIENT_ERROR",
			Severity:            "MAJOR_ISSUE",
		}
	case InvalidScope:
		return SummaryParamsType{
			AppResult:           e.Message.APIResponse().DeveloperMessage,
			AppResultCode:       e.Message.ResultCode(),
			AppResultHttpStatus: e.Message.HTTPStatus(),
			AppResultType:       "CLIENT_ERROR",
			Severity:            "MAJOR_ISSUE",
		}
	case UnsupportedResponseType:
		return SummaryParamsType{
			AppResult:           e.Message.APIResponse().DeveloperMessage,
			AppResultCode:       e.Message.ResultCode(),
			AppResultHttpStatus: e.Message.HTTPStatus(),
			AppResultType:       "CLIENT_ERROR",
			Severity:            "MAJOR_ISSUE",
		}
	case CodeHasBeenUsed:
		return SummaryParamsType{
			AppResult:           e.Message.APIResponse().DeveloperMessage,
			AppResultCode:       e.Message.ResultCode(),
			AppResultHttpStatus: e.Message.HTTPStatus(),
			AppResultType:       "CLIENT_ERROR",
			Severity:            "MAJOR_ISSUE",
		}
	case AccessDenied:
		return SummaryParamsType{
			AppResult:           e.Message.APIResponse().DeveloperMessage,
			AppResultCode:       e.Message.ResultCode(),
			AppResultHttpStatus: e.Message.HTTPStatus(),
			AppResultType:       "CLIENT_ERROR",
			Severity:            "MAJOR_ISSUE",
		}
	case InvalidClient:
		return SummaryParamsType{
			AppResult:           e.Message.APIResponse().DeveloperMessage,
			AppResultCode:       e.Message.ResultCode(),
			AppResultHttpStatus: e.Message.HTTPStatus(),
			AppResultType:       "CLIENT_ERROR",
			Severity:            "MAJOR_ISSUE",
		}
	case InvalidUserOrPassword:
		return SummaryParamsType{
			AppResult:           e.Message.APIResponse().DeveloperMessage,
			AppResultCode:       e.Message.ResultCode(),
			AppResultHttpStatus: e.Message.HTTPStatus(),
			AppResultType:       "CLIENT_ERROR",
			Severity:            "MAJOR_ISSUE",
		}
	case UnknownURL:
		return SummaryParamsType{
			AppResult:           e.Message.APIResponse().DeveloperMessage,
			AppResultCode:       e.Message.ResultCode(),
			AppResultHttpStatus: e.Message.HTTPStatus(),
			AppResultType:       "CLIENT_ERROR",
			Severity:            "MAJOR_ISSUE",
		}
	case DataNotFound:
		return SummaryParamsType{
			AppResult:           e.Message.APIResponse().DeveloperMessage,
			AppResultCode:       e.Message.ResultCode(),
			AppResultHttpStatus: e.Message.HTTPStatus(),
			AppResultType:       "CLIENT_ERROR",
			Severity:            "MAJOR_ISSUE",
		}
	case SubscriberNotFound:
		return SummaryParamsType{
			AppResult:           e.Message.APIResponse().DeveloperMessage,
			AppResultCode:       e.Message.ResultCode(),
			AppResultHttpStatus: e.Message.HTTPStatus(),
			AppResultType:       "CLIENT_ERROR",
			Severity:            "MAJOR_ISSUE",
		}
	case RequestTimeout:
		return SummaryParamsType{
			AppResult:           e.Message.APIResponse().DeveloperMessage,
			AppResultCode:       e.Message.ResultCode(),
			AppResultHttpStatus: e.Message.HTTPStatus(),
			AppResultType:       "CLIENT_ERROR",
			Severity:            "MAJOR_ISSUE",
		}
	case SystemError:
		return SummaryParamsType{
			AppResult:           e.Message.APIResponse().DeveloperMessage,
			AppResultCode:       e.Message.ResultCode(),
			AppResultHttpStatus: e.Message.HTTPStatus(),
			AppResultType:       "SYSTEM_ERROR",
			Severity:            "CRITICAL_ISSUE",
		}
	case TooManyRequest:
		return SummaryParamsType{
			AppResult:           e.Message.APIResponse().DeveloperMessage,
			AppResultCode:       e.Message.ResultCode(),
			AppResultHttpStatus: e.Message.HTTPStatus(),
			AppResultType:       "CLIENT_ERROR",
			Severity:            "MAJOR_ISSUE",
		}
	case TooManyInvalidCredential:
		return SummaryParamsType{
			AppResult:           e.Message.APIResponse().DeveloperMessage,
			AppResultCode:       e.Message.ResultCode(),
			AppResultHttpStatus: e.Message.HTTPStatus(),
			AppResultType:       "CLIENT_ERROR",
			Severity:            "MAJOR_ISSUE",
		}
	case TooManyIncomingRequest:
		return SummaryParamsType{
			AppResult:           e.Message.APIResponse().DeveloperMessage,
			AppResultCode:       e.Message.ResultCode(),
			AppResultHttpStatus: e.Message.HTTPStatus(),
			AppResultType:       "CLIENT_ERROR",
			Severity:            "MAJOR_ISSUE",
		}
	case ServerError:
		return SummaryParamsType{
			AppResult:           e.Message.APIResponse().DeveloperMessage,
			AppResultCode:       e.Message.ResultCode(),
			AppResultHttpStatus: e.Message.HTTPStatus(),
			AppResultType:       "SYSTEM_ERROR",
			Severity:            "CRITICAL_ISSUE",
		}
	case TemporarilyUnavailable:
		return SummaryParamsType{
			AppResult:           e.Message.APIResponse().DeveloperMessage,
			AppResultCode:       e.Message.ResultCode(),
			AppResultHttpStatus: e.Message.HTTPStatus(),
			AppResultType:       "SYSTEM_ERROR",
			Severity:            "CRITICAL_ISSUE",
		}
	case ServerUnavailable:
		return SummaryParamsType{
			AppResult:           e.Message.APIResponse().DeveloperMessage,
			AppResultCode:       e.Message.ResultCode(),
			AppResultHttpStatus: e.Message.HTTPStatus(),
			AppResultType:       "SYSTEM_ERROR",
			Severity:            "CRITICAL_ISSUE",
		}
	case ServerBusy:
		return SummaryParamsType{
			AppResult:           e.Message.APIResponse().DeveloperMessage,
			AppResultCode:       e.Message.ResultCode(),
			AppResultHttpStatus: e.Message.HTTPStatus(),
			AppResultType:       "SYSTEM_ERROR",
			Severity:            "CRITICAL_ISSUE",
		}
	case DatabaseConnectionError:
		return SummaryParamsType{
			AppResult:           e.Message.APIResponse().DeveloperMessage,
			AppResultCode:       e.Message.ResultCode(),
			AppResultHttpStatus: e.Message.HTTPStatus(),
			AppResultType:       "SYSTEM_ERROR",
			Severity:            "CRITICAL_ISSUE",
		}
	case DatabaseConnectionTimeout:
		return SummaryParamsType{
			AppResult:           e.Message.APIResponse().DeveloperMessage,
			AppResultCode:       e.Message.ResultCode(),
			AppResultHttpStatus: e.Message.HTTPStatus(),
			AppResultType:       "SYSTEM_ERROR",
			Severity:            "CRITICAL_ISSUE",
		}
	default:
		return SummaryParamsType{
			AppResult:           SystemError.APIResponse().DeveloperMessage,
			AppResultCode:       SystemError.ResultCode(),
			AppResultHttpStatus: SystemError.HTTPStatus(),
			AppResultType:       "SYSTEM_ERROR",
			Severity:            "CRITICAL_ISSUE",
		}
	}
}
