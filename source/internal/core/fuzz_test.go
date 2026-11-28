package core

import (
	"crypto/hmac"
	"crypto/sha256"
	"testing"
	"time"
)

func FuzzEngineAndFrames(f *testing.F) {
	e0 := newTestEngine()
	for _, ip := range []string{"10.0.0.9"} {
		g := e0.cfg
		if b, err := buildPacket(&g, pktHello, AfIPv4, 1, 0, ip); err == nil {
			f.Add(b[:headerSize], []byte("frame"))
		}
	}
	f.Add(make([]byte, headerSize), make([]byte, 64))
	f.Fuzz(func(t *testing.T, hdr, frame []byte) {
		t0 := time.Now()
		defer func() {
			if d := time.Since(t0); d > 2*time.Second {
				t.Fatalf("slow input: %v", d)
			}
		}()
		e := newTestEngine()
		e.cfg.RealMACs = len(frame)%2 == 0
		if len(hdr) == headerSize {
			// a correctly signed packet with arbitrary header fields
			mac := hmac.New(sha256.New, e.cfg.keyBytes())
			mac.Write(hdr)
			pkt := append(append([]byte(nil), hdr...), mac.Sum(nil)...)
			for _, st := range []State{stateInit, stateListen, stateSpeak, stateActive, stateForward} {
				e.Mu.Lock()
				e.state = st
				e.onPacketLocked(pkt, nil)
				e.Mu.Unlock()
			}
		}
		e.onPacketLocked(hdr, nil)
		self := [6]byte{2, 0, 0, 0, 0, 1}
		e.arpAnswerAny(frame, self, [][4]byte{{10, 0, 0, 123}})
		e.nsAnswerAny(frame, self, [][16]byte{{0x20, 1, 0xd, 0xb8, 15: 1}})
		for _, lt := range []int{1, 101, 0, 113, 228} {
			parsePkt(lt, frame)
			summarizePacket(lt, frame)
		}
		ReadPcap(frame)
		isARPReplyTo(frame, self, [4]byte{10, 0, 0, 1})
		isNAReplyTo(frame, self, [16]byte{1})
	})
}
