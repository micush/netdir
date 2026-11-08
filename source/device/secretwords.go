package device

import (
	"regexp"
	"strings"
	"sync/atomic"
)

// The words of your own that mark a secret (Configure ▸ Privacy ▸ Secret words, settings.privacy.secret_words), on top of the built-in
// ones.  One list for every filter: a key whose name holds one has its value hidden (Redact), a word of a line of text that holds
// one hides the rest of the line (RedactText), a member of a JSON text is hidden the same way, and a path or an XPath segment that
// holds one is refused (secretSegment).  It does not depend on the privacy level: secrets are hidden at "none" too.

type extraSecrets struct {
	words []string       // lower case
	re    *regexp.Regexp // "name" : value, for a name that holds a word; nil without words
}

var extraSecret atomic.Pointer[extraSecrets]

// SetSecretWords sets the words; nil or empty takes them away.  Safe to call while answers are being made.
func SetSecretWords(list []string) {
	var ws []string
	var qs []string
	for _, w := range list {
		w = strings.ToLower(strings.TrimSpace(w))
		if w != "" {
			ws = append(ws, w)
			qs = append(qs, regexp.QuoteMeta(w))
		}
	}
	e := &extraSecrets{words: ws}
	if len(qs) > 0 {
		e.re = regexp.MustCompile(`(?i)("[^"]*(` + strings.Join(qs, "|") + `)[^"]*"\s*[:=]\s*)("([^"\\]|\\.)*"|[^,}\s{\[][^,}\s]*)`)
	}
	extraSecret.Store(e)
}

func secretExtras() *extraSecrets {
	if e := extraSecret.Load(); e != nil {
		return e
	}
	return &extraSecrets{}
}

// holdsExtra says whether s (any case) holds one of the words of your own.
func holdsExtra(s string) bool {
	s = strings.ToLower(s)
	for _, w := range secretExtras().words {
		if strings.Contains(s, w) {
			return true
		}
	}
	return false
}
