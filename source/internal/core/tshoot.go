package core

import (
	"regexp"
)

const tshootRedacted = "<removed>"

// A key whose value is a secret: passwords, the gateway key, tokens, join codes, private keys.
var tshootSecretKey = regexp.MustCompile(`(?i)(^|_)(pass|passwd|password|secret|token|key|psk|private|cookie|csrf|code|auth|community|communities|keys)($|_)`)

// A secret written in free text (an FRR configuration, a command's output).
var tshootSecretText = regexp.MustCompile(`(?i)\b(password|passwd|secret|md5|community|key|auth-key)([ =:]+)(?:[0-9] )?(\S+)`)

// redactJSON returns v with the value of every secret key replaced, however deep.
func RedactJSON(v any) (any, int) {
	n := 0
	var walk func(any) any
	walk = func(x any) any {
		switch t := x.(type) {
		case map[string]any:
			for k, val := range t {
				if tshootSecretKey.MatchString(k) {
					switch tv := val.(type) {
					case nil:
					case string:
						if tv != "" {
							t[k], n = tshootRedacted, n+1
						}
					case bool, float64:
					default:
						t[k], n = tshootRedacted, n+1
					}
					continue
				}
				t[k] = walk(val)
			}
			return t
		case []any:
			for i := range t {
				t[i] = walk(t[i])
			}
			return t
		}
		return x
	}
	return walk(v), n
}

// redactText removes the secrets written in free text.
func RedactText(s string) (string, int) {
	n := 0
	out := tshootSecretText.ReplaceAllStringFunc(s, func(m string) string {
		n++
		p := tshootSecretText.FindStringSubmatch(m)
		return p[1] + p[2] + tshootRedacted
	})
	return out, n
}
