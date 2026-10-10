package licensing

import (
	"context"
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
			now := time.Now().Unix()
			if _, err := s.store.DeleteStaleNonces(now); err != nil && onErr != nil {
				onErr(err)
			}
			if _, err := s.store.DeleteStaleOOB(now); err != nil && onErr != nil {
				onErr(err)
			}
		}
	}
}
