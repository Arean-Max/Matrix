package licensing

import (
	"context"
	"fmt"
	"runtime/debug"
	"time"
)

func (s *Service) RunJanitor(ctx context.Context, every time.Duration, onErr func(error)) {
	if every <= 0 {
		every = time.Minute
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.janitorTick(time.Now().Unix(), onErr)
		}
	}
}

func (s *Service) janitorTick(now int64, onErr func(error)) {
	defer func() {
		if rec := recover(); rec != nil && onErr != nil {
			onErr(fmt.Errorf("janitor panic: %v\n%s", rec, debug.Stack()))
		}
	}()
	if _, err := s.store.DeleteStaleNonces(now); err != nil && onErr != nil {
		onErr(err)
	}
	if _, err := s.store.DeleteStaleOOB(now); err != nil && onErr != nil {
		onErr(err)
	}
}
