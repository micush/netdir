// devprobe asks devices what the gateway would ask them, without the gateway: the same drivers (netdir/device), the
// same inventory format (the "devices" and "device_credentials" of the ntp block), on any OS.  It is for trying a
// driver against real gear before the devices go into a gateway's configuration.
//
//	go run ./tools/devprobe -inventory lab.json -target all -op facts
//	go run ./tools/devprobe -inventory lab.json -target cat9300 -op neighbors
//
// A password or token written as "env:NAME" is read from the environment variable NAME, so the file need not hold it.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"netdir/device"
)

func main() {
	inv := flag.String("inventory", "", "the inventory file: {\"devices\": [...], \"device_credentials\": [...]}")
	target := flag.String("target", "all", "the devices: a name, tag:TAG, platform:PLATFORM or all, comma-separated")
	op := flag.String("op", "facts", "facts, interfaces, neighbors, config or show")
	cmd := flag.String("cmd", "", "the command for -op show")
	timeout := flag.Duration("timeout", 30*time.Second, "the time each device has")
	flag.Parse()
	if *inv == "" {
		fmt.Fprintln(os.Stderr, "devprobe: -inventory FILE is needed (platforms: "+strings.Join(device.Platforms(), ", ")+")")
		os.Exit(2)
	}
	b, err := os.ReadFile(*inv)
	if err != nil {
		fail(err)
	}
	var f struct {
		Devices     []device.Device     `json:"devices"`
		Credentials []device.Credential `json:"device_credentials"`
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		fail(fmt.Errorf("%s: %v", *inv, err))
	}
	for i := range f.Credentials {
		c := &f.Credentials[i]
		c.Password, c.Token = fromEnv(c.Password), fromEnv(c.Token)
	}
	if err := device.Validate(f.Devices, f.Credentials); err != nil {
		fail(err)
	}
	picked, err := device.Select(f.Devices, *target)
	if err != nil {
		fail(err)
	}
	if *op == "show" {
		if *cmd, err = device.CheckShow(*cmd); err != nil {
			fail(err)
		}
	}
	res := device.Fanout(context.Background(), picked, f.Credentials, 16, *timeout, func(ctx context.Context, d device.Driver) (any, error) {
		switch *op {
		case "facts":
			return d.Facts(ctx)
		case "interfaces":
			return d.Interfaces(ctx)
		case "neighbors":
			return d.Neighbors(ctx)
		case "config":
			return d.Config(ctx)
		case "show":
			return d.Show(ctx, *cmd)
		}
		return nil, fmt.Errorf("op %q: facts, interfaces, neighbors, config or show", *op)
	})
	failed := 0
	for _, r := range res {
		if !r.OK {
			failed++
		}
	}
	if *op == "config" && len(res) == 1 && res[0].OK { // one configuration: as the device sent it, ready to save
		fmt.Print(res[0].Data)
		return
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	fmt.Println(string(out))
	if failed > 0 {
		os.Exit(1)
	}
}

func fromEnv(s string) string {
	if name, ok := strings.CutPrefix(s, "env:"); ok {
		return os.Getenv(name)
	}
	return s
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "devprobe:", err)
	os.Exit(2)
}
