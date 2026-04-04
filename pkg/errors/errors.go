package errors

type SummaryParamsType struct {
	AppResult           string
	AppResultCode       string
	AppResultHttpStatus int
	AppResultType       string
	Severity            string
}

type Error struct {
	Message       string
	Err           error
	AppResultCode string
}

func (e *Error) Error() string {
	return e.Message
}

func (e *Error) Unwrap() error {
	return e.Err
}

//  export enum ResultType {
//     HEALTHY = 'HEALTHY',
//     CLIENT_ERROR = 'CLIENT_ERROR',
//     SYSTEM_ERROR = 'SYSTEM_ERROR',
//     BUSINESS_ERROR = 'BUSINESS_ERROR'
// }

// export enum Severity {
//     NORMAL = 'NORMAL',
//     NOTICE = 'NOTICE',
//     MINOR_ISSUE = 'MINOR_ISSUE',
//     MAJOR_ISSUE = 'MAJOR_ISSUE',
//     CRITICAL_ISSUE = 'CRITICAL_ISSUE',
//     SYSTEM_DOWN = 'SYSTEM_DOWN'
// }

func (e *Error) LogDependencyMetadata() SummaryParamsType {
	switch e.AppResultCode {
	case "40000":
		return SummaryParamsType{
			AppResult:           "missing_or_invalid_parameter",
			AppResultCode:       e.AppResultCode,
			AppResultHttpStatus: 400,
			AppResultType:       "CLIENT_ERROR",
			Severity:            "MAJOR_ISSUE",
		}
	case "40101":
		return SummaryParamsType{
			AppResult:           "access_denied",
			AppResultCode:       e.AppResultCode,
			AppResultHttpStatus: 401,
			AppResultType:       "CLIENT_ERROR",
			Severity:            "MAJOR_ISSUE",
		}
	case "40106":
		return SummaryParamsType{
			AppResult:           "invalid_credentials",
			AppResultCode:       e.AppResultCode,
			AppResultHttpStatus: 401,
			AppResultType:       "CLIENT_ERROR",
			Severity:            "MAJOR_ISSUE",
		}
	case "40401":
		return SummaryParamsType{
			AppResult:           "data_not_found",
			AppResultCode:       e.AppResultCode,
			AppResultHttpStatus: 404,
			AppResultType:       "CLIENT_ERROR",
			Severity:            "MAJOR_ISSUE",
		}
	case "40301":
		return SummaryParamsType{
			AppResult:           "data_exist",
			AppResultCode:       e.AppResultCode,
			AppResultHttpStatus: 403,
			AppResultType:       "CLIENT_ERROR",
			Severity:            "MAJOR_ISSUE",
		}
	case "50300":
		return SummaryParamsType{
			AppResult:           "server_busy",
			AppResultCode:       e.AppResultCode,
			AppResultHttpStatus: 503,
			AppResultType:       "SYSTEM_ERROR",
			Severity:            "MAJOR_ISSUE",
		}
	case "50301":
		return SummaryParamsType{
			AppResult:           "server_unavailable",
			AppResultCode:       e.AppResultCode,
			AppResultHttpStatus: 503,
			AppResultType:       "SYSTEM_ERROR",
			Severity:            "MAJOR_ISSUE",
		}
	default:
		return SummaryParamsType{
			AppResult:           "system_error",
			AppResultCode:       "50000",
			AppResultHttpStatus: 500,
			AppResultType:       "SYSTEM_ERROR",
			Severity:            "MAJOR_ISSUE",
		}
	}

}
