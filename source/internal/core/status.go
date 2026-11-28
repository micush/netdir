package core

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"time"
)

func StatusRequestTimeout(path string, cmd map[string]any, timeout time.Duration) (map[string]any, error) {
	d := net.Dialer{Timeout: 3 * time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	c, err := d.DialContext(ctx, "unix", path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, errors.New("netdir is not running (status socket not found)")
		}
		return nil, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(timeout))
	b, _ := json.Marshal(cmd)
	if _, err := c.Write(append(b, '\n')); err != nil {
		return nil, err
	}
	var res map[string]any
	if err := json.NewDecoder(c).Decode(&res); err != nil {
		return nil, err
	}
	return res, nil
}
