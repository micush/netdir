package core

import (
	"errors"
)

// ErrConfigChanged is a save refused because the shared settings changed after the copy it was made from was read.
var ErrConfigChanged = errors.New("the configuration changed after this page loaded it (another page, another user, an import or another node): it was not saved, so nothing is overwritten; the page now shows what is saved, make the change again")

// configBase is the token a page keeps with the configuration it read: it changes whenever the shared settings do (the devices, the
// gateways, the keys, everything every node shares), and not for what is only this node's own.
func ConfigBase(dc *DaemonConfig) string { return SharedOf(dc).Hash() }

type AdminCert struct {
	CertPEM string `json:"cert_pem"`
	KeyPEM  string `json:"key_pem"`
}

type UpdateNode struct {
	Addr      string `json:"addr"`
	Self      bool   `json:"self"`
	Reachable bool   `json:"reachable"`
	Running   string `json:"running"`
	Source    string `json:"source"`
	Queued    bool   `json:"queued"`
	Updating  bool   `json:"updating"`
	Failed    string `json:"failed,omitempty"`
	SoakSec   int    `json:"soak_sec,omitempty"`
	// Restarting: not answering, but it was installing an update when last seen (see PeerView.Restarting)
	Restarting bool `json:"restarting,omitempty"`
	Behind     bool `json:"behind"`
}
