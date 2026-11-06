package main

import (
	"fmt"
	"math"
	"strconv"
	"time"
)

// The time ranges and resolutions the history graphs (Monitor ▸ Host, Monitor ▸ Node) are read with.

// maxPoints is the most points a graph is sent.
const maxPoints = 800

// stepFor is the resolution, in seconds, a graph over span is drawn at.
func stepFor(span time.Duration) int64 {
	switch {
	case span <= 2*time.Hour:
		return 60
	case span <= 36*time.Hour:
		return 600
	case span <= 7*24*time.Hour:
		return 3600
	}
	return 10800
}

// statsRange reads a requested range: from is "now", a duration back from the end (1h, 1d, 7d, 30d) or unix seconds;
// to is unix seconds, or "" for now.
func statsRange(from, to string) (time.Time, time.Time, error) {
	now := time.Now()
	end := now
	if to != "" {
		n, err := strconv.ParseInt(to, 10, 64)
		if err != nil || n <= 0 {
			return time.Time{}, time.Time{}, fmt.Errorf("%q is not a time (unix seconds)", to)
		}
		end = time.Unix(n, 0)
	}
	if from == "" || from == "now" {
		return end.Add(-time.Hour), end, nil
	}
	if n, err := strconv.ParseInt(from, 10, 64); err == nil && n > 1e9 {
		return time.Unix(n, 0), end, nil
	}
	d, err := parseSince(from)
	if err != nil || d == 0 {
		return time.Time{}, time.Time{}, fmt.Errorf("%q is not a range: use now, 1h, 1d, 7d, 30d or unix seconds", from)
	}
	return end.Add(-d), end, nil
}

func round2(f float64) float64 { return math.Round(f*100) / 100 }
