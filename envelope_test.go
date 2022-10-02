package main

import (
	"encoding/hex"
	"fmt"
	"testing"
)

func TestNewEnvelope(t *testing.T) {
	key, err := hex.DecodeString("56e47a38c5598974bc46903dba290349")
	if err != nil {
		panic(err)
	}
	data, err := hex.DecodeString("a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf")
	if err != nil {
		panic(err)
	}
	envelope, _ := NewEnvelope("AES_128_CBC")
	encrypted, _ := envelope.encrypt(key, "AES_128_CBC", data)
	fmt.Print(string(encrypted))

	decrypted, e := decrypt(key, encrypted)
	if e != nil {
		return
	}
	if hex.EncodeToString(data) != hex.EncodeToString(decrypted) {
		t.Errorf("result must be = %s, not %s", data, encrypted)
	}

}
