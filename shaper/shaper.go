package shaper

import (
	"io"
	"time"
)

func LimitWriter(w io.Writer, span time.Duration, maxRatePerSpan int64) io.Writer {
	return &Shaper{
		wrapped: w,
		limit:   maxRatePerSpan,
		span:    span,
	}
}

type Shaper struct {
	wrapped  io.Writer
	interval time.Time
	span     time.Duration
	written  int64
	limit    int64
}

func (self *Shaper) Write(p []byte) (n int, err error) {
	inNextInterval := false
	if self.written >= self.limit {
		current := time.Now().Truncate(self.span)
		for current.Equal(self.interval) {
			current = time.Now().Truncate(self.span)
			// busy wait until we're in the next interval
		}
		self.interval = current
		inNextInterval = true
	}

	n, err = self.wrapped.Write(p)
	if inNextInterval {
		self.written = int64(n)
	} else if current := time.Now().Truncate(self.span); current != self.interval {
		self.written = int64(n)
		self.interval = current
	} else {
		self.written += int64(n)
	}

	return n, err
}
