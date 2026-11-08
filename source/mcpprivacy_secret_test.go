package main

import (
	"strings"
	"testing"
)

func TestNormPrivacySecretWords(t *testing.T) {
	got, err := normPrivacy(&PrivacyConfig{SecretWords: []string{" PassKey ", "vault", "VAULT", ""}})
	if err != nil || got == nil || strings.Join(got.SecretWords, ",") != "passkey,vault" {
		t.Fatalf("%v %+v", err, got)
	}
	for _, bad := range []string{"ab", strings.Repeat("x", 65), `a"b`, "a\x01b"} {
		if _, err := normPrivacy(&PrivacyConfig{SecretWords: []string{bad}}); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if got, err := normPrivacy(&PrivacyConfig{}); err != nil || got != nil {
		t.Errorf("nothing set: %v %+v", err, got)
	}
}
