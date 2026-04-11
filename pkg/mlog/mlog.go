package mlog

import (
	"context"

	"github.com/sing3demons/oauth_server/pkg/constants"
	"github.com/sing3demons/oauth_server/pkg/logger"
)

func L(ctx context.Context) *logger.CustomLogger {
	if ctx == nil {
		return logger.NewCustomLogger(nil, nil, logger.LogDto{})
	}
	l, ok := ctx.Value(constants.DetailLoggerKey).(*logger.CustomLogger)
	if !ok || l == nil {
		return logger.NewCustomLogger(nil, nil, logger.LogDto{})
	}

	return l
}
