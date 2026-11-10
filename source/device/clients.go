package device

import "context"

// What the troubleshooting of a user needs from two platforms (source/devtroubleshoot.go joins them): Entra says which devices a user
// has and when each was last used, Meraki says where a device of that name was seen on the network and how it did.

// UserDeviceLooker is a directory that knows a user's devices (Entra).
type UserDeviceLooker interface {
	// UserDevices finds one user (a sign-in name, an object ID or a name) and returns the user and the devices, most recently
	// signed in first.
	UserDevices(ctx context.Context, who string) (user map[string]any, devices []map[string]any, err error)
}

// ClientQuery is what to look for on a network: clients with one of these names (a DHCP host name, with or without a domain) or MACs,
// seen in the last Hours hours, in one network or in all of them.
type ClientQuery struct {
	Names   []string
	MACs    []string
	Hours   int
	Network string
}

// ClientReporter is a network platform that can say how a client has been doing (Meraki, an organization device).
type ClientReporter interface {
	ClientReport(ctx context.Context, q ClientQuery) (map[string]any, error)
}

// DeviceUserLooker is a directory that knows who uses a device (Entra): the devices of that name, each with the users registered
// on it and its owners.
type DeviceUserLooker interface {
	DeviceUsers(ctx context.Context, name string) ([]map[string]any, error)
}

// LogSearcher is a firewall or its manager whose logs can be searched (PAN-OS, Panorama): the newest n entries of one log that
// match a filter, newest first.
type LogSearcher interface {
	LogSearch(ctx context.Context, logType, query string, n int) ([]map[string]any, error)
}
