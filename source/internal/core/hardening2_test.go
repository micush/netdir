package core

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestMinPasswordLengthConfig(t *testing.T) {
	w := DefaultWeb()
	if w.MinPassword() != 8 || w.Validate() != nil {
		t.Fatalf("default: %d %v", w.MinPassword(), w.Validate())
	}
	for _, bad := range []int{-1, 129, 100000} {
		w.MinPasswordLength = bad
		if w.Validate() == nil {
			t.Errorf("min_password_length %d accepted", bad)
		}
	}
	for _, good := range []int{0, 1, 8, 128} {
		w.MinPasswordLength = good
		if err := w.Validate(); err != nil {
			t.Errorf("min_password_length %d refused: %v", good, err)
		}
	}
	// an unset value is not written, so an older version can still read the file
	b, _ := json.Marshal(DefaultWeb())
	if strings.Contains(string(b), "min_password_length") {
		t.Fatalf("the default is written to the config: %s", b)
	}
	var back WebConfig
	if err := json.Unmarshal([]byte(`{"min_password_length": 10}`), &back); err != nil || back.MinPassword() != 10 {
		t.Fatalf("reading it back: %v %d", err, back.MinPassword())
	}
}
