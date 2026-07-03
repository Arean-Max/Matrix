package licensing

import (
	"strings"
	"testing"
)

func TestJanitorRecoversFromPanic(t *testing.T) {
	s := &Service{}
	var got error
	s.janitorTick(0, func(err error) {
		got = err
	})
	if got == nil || !strings.Contains(got.Error(), "janitor panic") {
		t.Fatalf("panic was not contained: %v", got)
	}
}
