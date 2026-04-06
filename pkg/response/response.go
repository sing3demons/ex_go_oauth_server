package response

import "net/http"

type BodyMsg struct {
	Msg string `json:"error"`
}
type BodyAPI struct {
	ResultCode       string `json:"result_code"`
	DeveloperMessage string `json:"developer_message"`
}

type ResponseMsg struct {
	Code       int
	ResultCode string
	BodyMsg    BodyMsg
	BodyAPI    BodyAPI
}

type MessageError string

const (
	Success                   MessageError = "success"
	InvalidRequest            MessageError = "invalid_request"
	InvalidCode               MessageError = "invalid_code"
	InvalidGrant              MessageError = "invalid_grant"
	InvalidScope              MessageError = "invalid_scope"
	MissingOrInvalidParameter MessageError = "missing_or_invalid_parameter"
	UnsupportedResponseType   MessageError = "unsupported_response_type"
	CodeHasBeenUsed           MessageError = "code_has_been_used"
	AccessDenied              MessageError = "access_denied"
	InvalidClient             MessageError = "invalid_client"
	InvalidUserOrPassword     MessageError = "invalid_user_or_password"
	UnknownURL                MessageError = "unknown_url"
	DataNotFound              MessageError = "data_not_found"
	SubscriberNotFound        MessageError = "subscriber_not_found"
	RequestTimeout            MessageError = "request_timeout"
	SystemError               MessageError = "system_error"
	TooManyRequest            MessageError = "too_many_request"
	TooManyInvalidCredential  MessageError = "too_many_invalid_credential"
	TooManyIncomingRequest    MessageError = "too_many_incoming_request"
	ServerError               MessageError = "server_error"
	TemporarilyUnavailable    MessageError = "temporarily_unavailable"
	ServerUnavailable         MessageError = "server_unavailable"
	ServerBusy                MessageError = "server_busy"
	DatabaseConnectionError   MessageError = "database_connection_error"
	DatabaseConnectionTimeout MessageError = "database_connection_timeout"
)

func SUCCESS() ResponseMsg {
	return ResponseMsg{
		Code:       http.StatusOK,
		ResultCode: "20000",
		BodyMsg:    BodyMsg{Msg: "success"},
		BodyAPI:    BodyAPI{ResultCode: "20000", DeveloperMessage: "success"},
	}
}
func DATABASE_CONNECTION_ERROR() ResponseMsg {
	return ResponseMsg{
		Code:       http.StatusServiceUnavailable,
		ResultCode: "50303",
		BodyMsg:    BodyMsg{Msg: "database_connection_error"},
		BodyAPI:    BodyAPI{ResultCode: "50303", DeveloperMessage: "database_connection_error"},
	}
}
func DATABASE_CONNECTION_TIMEOUT() ResponseMsg {
	return ResponseMsg{
		Code:       http.StatusServiceUnavailable,
		ResultCode: "50304",
		BodyMsg:    BodyMsg{Msg: "database_connection_timeout"},
		BodyAPI:    BodyAPI{ResultCode: "50304", DeveloperMessage: "database_connection_timeout"},
	}
}
func SERVER_UNAVAILABLE() ResponseMsg {
	return ResponseMsg{
		Code:       http.StatusServiceUnavailable,
		ResultCode: "50301",
		BodyMsg:    BodyMsg{Msg: "server_unavailable"},
		BodyAPI:    BodyAPI{ResultCode: "50301", DeveloperMessage: "server_unavailable"},
	}
}
func SERVER_BUSY() ResponseMsg {
	return ResponseMsg{
		Code:       http.StatusServiceUnavailable,
		ResultCode: "50302",
		BodyMsg:    BodyMsg{Msg: "server_busy"},
		BodyAPI:    BodyAPI{ResultCode: "50302", DeveloperMessage: "server_busy"},
	}
}
func TEMPORARILY_UNAVAILABLE() ResponseMsg {
	return ResponseMsg{
		Code:       http.StatusServiceUnavailable,
		ResultCode: "50300",
		BodyMsg:    BodyMsg{Msg: "temporarily_unavailable"},
		BodyAPI:    BodyAPI{ResultCode: "50300", DeveloperMessage: "temporarily_unavailable"},
	}
}
func SYSTEM_ERROR() ResponseMsg {
	return ResponseMsg{
		Code:       http.StatusInternalServerError,
		ResultCode: "50000",
		BodyMsg:    BodyMsg{Msg: "system_error"},
		BodyAPI:    BodyAPI{ResultCode: "50000", DeveloperMessage: "system_error"},
	}
}
func SERVER_ERROR() ResponseMsg {
	return ResponseMsg{
		Code:       http.StatusInternalServerError,
		ResultCode: "50000",
		BodyMsg:    BodyMsg{Msg: "server_error"},
		BodyAPI:    BodyAPI{ResultCode: "50000", DeveloperMessage: "server_error"},
	}
}
func TOO_MANY_INCOMING_REQUEST() ResponseMsg {
	return ResponseMsg{
		Code:       http.StatusTooManyRequests,
		ResultCode: "42902",
		BodyMsg:    BodyMsg{Msg: "too_many_incoming_request"},
		BodyAPI:    BodyAPI{ResultCode: "42902", DeveloperMessage: "too_many_incoming_request"},
	}
}
func TOO_MANY_INVALID_CREDENTIAL() ResponseMsg {
	return ResponseMsg{
		Code:       http.StatusTooManyRequests,
		ResultCode: "42901",
		BodyMsg:    BodyMsg{Msg: "too_many_invalid_credential"},
		BodyAPI:    BodyAPI{ResultCode: "42901", DeveloperMessage: "too_many_invalid_credential"},
	}
}
func TOO_MANY_REQUEST() ResponseMsg {
	return ResponseMsg{
		Code:       http.StatusTooManyRequests,
		ResultCode: "42900",
		BodyMsg:    BodyMsg{Msg: "too_many_request"},
		BodyAPI:    BodyAPI{ResultCode: "42900", DeveloperMessage: "too_many_request"},
	}
}
func REQUEST_TIMEOUT() ResponseMsg {
	return ResponseMsg{
		Code:       http.StatusRequestTimeout,
		ResultCode: "40800",
		BodyMsg:    BodyMsg{Msg: "request_timeout"},
		BodyAPI:    BodyAPI{ResultCode: "40800", DeveloperMessage: "request_timeout"},
	}
}
func SUBSCRIBER_NOT_FOUND() ResponseMsg {
	return ResponseMsg{
		Code:       http.StatusNotFound,
		ResultCode: "40402",
		BodyMsg:    BodyMsg{Msg: "subscriber_not_found"},
		BodyAPI:    BodyAPI{ResultCode: "40402", DeveloperMessage: "subscriber_not_found"},
	}
}
func DATA_NOT_FOUND() ResponseMsg {
	return ResponseMsg{
		Code:       http.StatusNotFound,
		ResultCode: "40401",
		BodyMsg:    BodyMsg{Msg: "data_not_found"},
		BodyAPI:    BodyAPI{ResultCode: "40401", DeveloperMessage: "data_not_found"},
	}
}
func INVALID_REQUEST() ResponseMsg {
	return ResponseMsg{
		Code:       http.StatusBadRequest,
		ResultCode: "40000",
		BodyMsg:    BodyMsg{Msg: "invalid_request"},
		BodyAPI:    BodyAPI{ResultCode: "40000", DeveloperMessage: "invalid_request"},
	}
}
func INVALID_CODE() ResponseMsg {
	return ResponseMsg{
		Code:       http.StatusBadRequest,
		ResultCode: "40001",
		BodyMsg:    BodyMsg{Msg: "invalid_code"},
		BodyAPI:    BodyAPI{ResultCode: "40001", DeveloperMessage: "invalid_code"},
	}
}
func INVALID_GRANT() ResponseMsg {
	return ResponseMsg{
		Code:       http.StatusBadRequest,
		ResultCode: "40002",
		BodyMsg:    BodyMsg{Msg: "invalid_grant"},
		BodyAPI:    BodyAPI{ResultCode: "40002", DeveloperMessage: "invalid_grant"},
	}
}
func INVALID_SCOPE() ResponseMsg {
	return ResponseMsg{
		Code:       http.StatusBadRequest,
		ResultCode: "40003",
		BodyMsg:    BodyMsg{Msg: "invalid_scope"},
		BodyAPI:    BodyAPI{ResultCode: "40003", DeveloperMessage: "invalid_scope"},
	}
}
func MISSING_OR_INVALID_PARAMETER() ResponseMsg {
	return ResponseMsg{
		Code:       http.StatusBadRequest,
		ResultCode: "40004",
		BodyMsg:    BodyMsg{Msg: "missing_or_invalid_parameter"},
		BodyAPI:    BodyAPI{ResultCode: "40004", DeveloperMessage: "missing_or_invalid_parameter"},
	}
}
func UNSUPPORTED_RESPONSE_TYPE() ResponseMsg {
	return ResponseMsg{
		Code:       http.StatusBadRequest,
		ResultCode: "40005",
		BodyMsg:    BodyMsg{Msg: "unsupported_response_type"},
		BodyAPI:    BodyAPI{ResultCode: "40005", DeveloperMessage: "unsupported_response_type"},
	}
}
func CODE_HAS_BEEN_USED() ResponseMsg {
	return ResponseMsg{
		Code:       http.StatusBadRequest,
		ResultCode: "40006",
		BodyMsg:    BodyMsg{Msg: "code_has_been_used"},
		BodyAPI:    BodyAPI{ResultCode: "40006", DeveloperMessage: "code_has_been_used"},
	}
}
func ACCESS_DENIED() ResponseMsg {
	return ResponseMsg{
		Code:       http.StatusUnauthorized,
		ResultCode: "40100",
		BodyMsg:    BodyMsg{Msg: "access_denied"},
		BodyAPI:    BodyAPI{ResultCode: "40100", DeveloperMessage: "access_denied"},
	}
}
func INVALID_CLIENT() ResponseMsg {
	return ResponseMsg{
		Code:       http.StatusUnauthorized,
		ResultCode: "40101",
		BodyMsg:    BodyMsg{Msg: "invalid_client"},
		BodyAPI:    BodyAPI{ResultCode: "40101", DeveloperMessage: "invalid_client"},
	}
}
func INVALID_USER_OR_PASSWORD() ResponseMsg {
	return ResponseMsg{
		Code:       http.StatusUnauthorized,
		ResultCode: "40102",
		BodyMsg:    BodyMsg{Msg: "invalid_user_or_password"},
		BodyAPI:    BodyAPI{ResultCode: "40102", DeveloperMessage: "invalid_user_or_password"},
	}
}
func UNKNOWN_URL() ResponseMsg {
	return ResponseMsg{
		Code:       http.StatusNotFound,
		ResultCode: "40400",
		BodyMsg:    BodyMsg{Msg: "unknown_url"},
		BodyAPI:    BodyAPI{ResultCode: "40400", DeveloperMessage: "unknown_url"},
	}
}

var responseMap = map[MessageError]ResponseMsg{
	Success:                   SUCCESS(),
	InvalidRequest:            INVALID_REQUEST(),
	InvalidCode:               INVALID_CODE(),
	InvalidGrant:              INVALID_GRANT(),
	InvalidScope:              INVALID_SCOPE(),
	MissingOrInvalidParameter: MISSING_OR_INVALID_PARAMETER(),
	UnsupportedResponseType:   UNSUPPORTED_RESPONSE_TYPE(),
	CodeHasBeenUsed:           CODE_HAS_BEEN_USED(),
	AccessDenied:              ACCESS_DENIED(),
	InvalidClient:             INVALID_CLIENT(),
	InvalidUserOrPassword:     INVALID_USER_OR_PASSWORD(),
	UnknownURL:                UNKNOWN_URL(),
	DataNotFound:              DATA_NOT_FOUND(),
	SubscriberNotFound:        SUBSCRIBER_NOT_FOUND(),
	RequestTimeout:            REQUEST_TIMEOUT(),
	SystemError:               SYSTEM_ERROR(),
	TooManyRequest:            TOO_MANY_REQUEST(),
	TooManyInvalidCredential:  TOO_MANY_INVALID_CREDENTIAL(),
	TooManyIncomingRequest:    TOO_MANY_INCOMING_REQUEST(),
	ServerError:               SERVER_ERROR(),
	TemporarilyUnavailable:    TEMPORARILY_UNAVAILABLE(),
	ServerUnavailable:         SERVER_UNAVAILABLE(),
	ServerBusy:                SERVER_BUSY(),
	DatabaseConnectionError:   DATABASE_CONNECTION_ERROR(),
	DatabaseConnectionTimeout: DATABASE_CONNECTION_TIMEOUT(),
}

func (e MessageError) Response() ResponseMsg {
	if res, ok := responseMap[e]; ok {
		return res
	}

	// fallback กันพัง
	return SYSTEM_ERROR()
}
func (e MessageError) HTTPStatus() int {
	return e.Response().Code
}

func (e MessageError) APIResponse() BodyAPI {
	return e.Response().BodyAPI
}

func (e MessageError) OIDCResponse() BodyMsg {
	return e.Response().BodyMsg
}

func (e MessageError) ResultCode() string {
	return e.Response().ResultCode
}

func (e MessageError) Error() BodyMsg {
	return e.Response().BodyMsg
}
