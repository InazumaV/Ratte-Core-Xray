package limiter

import (
	"context"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"golang.org/x/time/rate"
)

type LimitedIoWriter struct {
	writer  buf.Writer
	limiter *rate.Limiter
}

func NewRateLimitWriter(writer buf.Writer, limiter *rate.Limiter) buf.Writer {
	return &LimitedIoWriter{
		writer:  writer,
		limiter: limiter,
	}
}

func (w *LimitedIoWriter) Close() error {
	return common.Close(w.writer)
}

func (w *LimitedIoWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	_ = w.limiter.WaitN(context.Background(), int(mb.Len()))
	return w.writer.WriteMultiBuffer(mb)
}
