package server

import (
	"bytes"
	"encoding/base64"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSSEUTF8AndLegacyCarriageReturns(t *testing.T) {
	recorder := httptest.NewRecorder()
	stream := &sseWriter{w: recorder, flusher: recorder}
	out := stream.channel("stdout")
	for _, part := range [][]byte{[]byte("progress\r"), []byte("\nnext\revent: injected\n"), {0xe2}, {0x82}, {0xac}} {
		if n, err := out.Write(part); err != nil || n != len(part) {
			t.Fatal(n, err)
		}
	}
	stream.finishOutput()
	wire := recorder.Body.String()
	if !strings.Contains(wire, "progress\r") || !strings.Contains(wire, "next\revent: injected") || strings.Contains(wire, "�") {
		t.Fatalf("unsafe or corrupted frame: %q", wire)
	}
	if !strings.Contains(wire, "data: €\n") {
		t.Fatalf("split rune corrupted: %q", wire)
	}
}
func TestSSEBase64PreservesArbitraryBytes(t *testing.T) {
	recorder := httptest.NewRecorder()
	stream := &sseWriter{w: recorder, flusher: recorder, encoding: "base64"}
	want := []byte("progress\r\nnext\r\xff\xe2\x82\xac")
	if _, err := stream.channel("stdout").Write(want); err != nil {
		t.Fatal(err)
	}
	data := strings.TrimPrefix(strings.Split(recorder.Body.String(), "\n")[1], "data: ")
	got, err := base64.StdEncoding.DecodeString(data)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("roundtrip %q %v", got, err)
	}
}
