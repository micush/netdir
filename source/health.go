package main

import "sync/atomic"

// Gateway health.  What a gateway's addresses carry is the MCP endpoint, on a listener of its own per address (mcplisten.go;
// the GUI does not answer there).  A node is fit to carry them while those listeners are serving; when they are not (no
// certificate, the port taken, the server stopped), the anycast addresses are withdrawn and the engines report the service down, so
// the traffic goes to a node that can answer it.
//
// web.go sets webServing when the listener starts and clears it when it stops.

var webServing atomic.Bool

// mcpServing is true while the MCP listeners on the gateways' addresses (mcplisten.go) are up.
var mcpServing atomic.Bool

// serviceUpFn reports whether this node can answer on a gateway's addresses now (replaceable in tests).
var serviceUpFn = func() bool { return mcpServing.Load() }
