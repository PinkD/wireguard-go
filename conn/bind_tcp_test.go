package conn

import (
	"testing"
)

func Equal[T int](t *testing.T, a T, b T) {
	if a != b {
		t.Errorf("%v != %v", a, b)
	}
}

func TestReqLen(t *testing.T) {
	var l reqLen
	l.FromLen(0)
	Equal(t, l.Len(), 0)
	l.FromLen(123456789)
	Equal(t, l.Len(), 123456789)
	l.FromLen(65535)
	Equal(t, l.Len(), 65535)
	l.FromLen(0xFFFFFFFF)
	Equal(t, l.Len(), 0xFFFFFFFF)
}
