package core

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"strconv"
	"testing"
	"time"
)

func mustInt(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		panic(err)
	}
	return n
}

func makeTgz(t *testing.T, files []SrcFile) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, f := range files {
		if err := tw.WriteHeader(&tar.Header{Name: f.Name, Mode: int64(f.Mode), Size: int64(len(f.Data)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		tw.Write(f.Data)
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

func timeNow() time.Time { return time.Now().UTC() }
