package logAction

import (
	"strings"

	"github.com/sing3demons/tr_02_oauth/pkg/logger"
)

const (
	Consuming    = "[CONSUMING]"
	Producing    = "[PRODUCING]"
	AppLogic     = "[APP_LOGIC]"
	HttpRequest  = "[HTTP_REQUEST]"
	HttpResponse = "[HTTP_RESPONSE]"
	DbRequest    = "[DB_REQUEST]"
	DbResponse   = "[DB_RESPONSE]"
	Exception    = "[EXCEPTION]"
	Inbound      = "[INBOUND]"
	Outbound     = "[OUTBOUND]"
	System       = "[SYSTEM]"
	Produced     = "[PRODUCED]"
)

type DBActionEnum string

const (
	DB_CREATE DBActionEnum = "CREATE"
	DB_READ   DBActionEnum = "READ"
	DB_UPDATE DBActionEnum = "UPDATE"
	DB_DELETE DBActionEnum = "DELETE"
	DB_NONE   DBActionEnum = "NONE"
)

func CONSUMING(desc string, subAction ...string) logger.LoggerAction {
	return logger.LoggerAction{
		Action:            Consuming,
		ActionDescription: desc,
		SubAction:         strings.Join(subAction, ", "),
	}
}

func PRODUCING(desc string, subAction ...string) logger.LoggerAction {
	return logger.LoggerAction{
		Action:            Producing,
		ActionDescription: desc,
		SubAction:         strings.Join(subAction, ", "),
	}
}

func INBOUND(desc string, subAction ...string) logger.LoggerAction {
	return logger.LoggerAction{
		Action:            Inbound,
		ActionDescription: desc,
		SubAction:         strings.Join(subAction, ", "),
	}
}

func OUTBOUND(desc string, subAction ...string) logger.LoggerAction {
	return logger.LoggerAction{
		Action:            Outbound,
		ActionDescription: desc,
		SubAction:         strings.Join(subAction, ", "),
	}
}

func APP_LOGIC(desc string, subAction ...string) logger.LoggerAction {
	return logger.LoggerAction{
		Action:            AppLogic,
		ActionDescription: desc,
		SubAction:         strings.Join(subAction, ", "),
	}
}

func HTTP_REQUEST(desc string, subAction ...string) logger.LoggerAction {
	return logger.LoggerAction{
		Action:            HttpRequest,
		ActionDescription: desc,
		SubAction:         strings.Join(subAction, ", "),
	}
}

func HTTP_RESPONSE(desc string, subAction ...string) logger.LoggerAction {
	return logger.LoggerAction{
		Action:            HttpResponse,
		ActionDescription: desc,
		SubAction:         strings.Join(subAction, ", "),
	}
}

func DB_REQUEST(operation DBActionEnum, subAction string) logger.LoggerAction {
	return logger.LoggerAction{
		Action:            DbRequest,
		ActionDescription: subAction,
		SubAction:         string(operation),
	}
}

func DB_RESPONSE(operation DBActionEnum, subAction string) logger.LoggerAction {
	return logger.LoggerAction{
		Action:            DbResponse,
		ActionDescription: subAction,
		SubAction:         string(operation),
	}
}

func EXCEPTION(desc string, subAction ...string) logger.LoggerAction {
	return logger.LoggerAction{
		Action:            Exception,
		ActionDescription: desc,
		SubAction:         strings.Join(subAction, ", "),
	}
}

func SYSTEM(desc string, subAction ...string) logger.LoggerAction {
	return logger.LoggerAction{
		Action:            System,
		ActionDescription: desc,
		SubAction:         strings.Join(subAction, ", "),
	}
}

func PRODUCED(desc string, subAction ...string) logger.LoggerAction {
	return logger.LoggerAction{
		Action:            Produced,
		ActionDescription: desc,
		SubAction:         strings.Join(subAction, ", "),
	}
}
