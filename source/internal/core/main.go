// netdir — MCP Network Director: a highly available MCP gateway to the network's switches and firewalls.  A cluster of
// nodes shares a VIP (the Distributed Gateway Load Balancing Protocol) and anycast addresses, and every node answers
// MCP on them and reaches the managed devices for its callers.
package core

import (
	"fmt"
	"os"
)

func Fatal(err error)           { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
func Fatalf(f string, a ...any) { fmt.Fprintf(os.Stderr, f+"\n", a...); os.Exit(1) }
