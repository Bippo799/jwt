package token_test

import (
	"testing"

	"github.com/wiowou/jwt-verify-go/token"
)

func TestSegment(t *testing.T) {
	var v interface{}
	var ok bool
	segment := token.NewSegment()
	segment.Add("f1", 345)
	if v, ok = segment.Get("f1"); !ok {
		t.Error()
	}
	if got, ok := v.(int); ok {
		if got != 345 {
			t.Error()
		}
	} else {
		t.Error()
	}

	segment.Add("f1", "abc")
	if v, ok = segment.Get("f1"); !ok {
		t.Error()
	}
	if got, ok := v.(string); ok {
		if got != "abc" {
			t.Error()
		}
	} else {
		t.Error()
	}

	segment.Remove("f1")
	if _, ok = segment.Get("f1"); ok {
		t.Error()
	}
}
