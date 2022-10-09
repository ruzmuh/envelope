package envelope

import (
	"encoding/hex"
	"testing"

	log "github.com/sirupsen/logrus"
)

func TestNewEnvelope(t *testing.T) {
	testCases := []struct {
		key  string
		data string
		ph1  string
		ph2  string
	}{
		{
			key:  "56e47a38c5598974bc46903dba290349",
			data: "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf",
			ph1:  "AES_128_CBC",
			ph2:  "AES_128_CBC",
		},
		{
			key:  "56e47a38c5598974bc46903dba290349",
			data: "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdd",
			ph1:  "AES_128_CBC",
			ph2:  "AES_128_CBC",
		},
		{
			key:  "56e47a38c5598974bc46903dba290349",
			data: "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdd",
			ph1:  "AES_128_CFB",
			ph2:  "AES_128_CFB",
		},
		{
			key:  "56e47a38c5598974bc46903dba290349",
			data: "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdd",
			ph1:  "AES_128_CTR",
			ph2:  "AES_128_CTR",
		},
		{
			key:  "56e47a38c5598974bc46903dba290349",
			data: "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdd",
			ph1:  "AES_128_OFB",
			ph2:  "AES_128_OFB",
		},
		{
			key:  "56e47a38c5598974bc46903dba290349",
			data: "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdd",
			ph1:  "AES_128_OFB",
			ph2:  "AES_128_CBC",
		},
	}
	for k, v := range testCases {
		log.Infof("CASE #%v", k)
		key, err := hex.DecodeString(v.key)
		if err != nil {
			panic(err)
		}
		data, err := hex.DecodeString(v.data)
		if err != nil {
			panic(err)
		}
		envelope, _ := NewEnvelope(v.ph1)
		encrypted, _ := envelope.Encrypt(key, v.ph2, data)

		decrypted, e := Decrypt(key, encrypted)
		if e != nil {
			return
		}
		if hex.EncodeToString(data) != hex.EncodeToString(decrypted) {
			t.Errorf("result must be = %s, not %s", data, encrypted)
		}
		log.Infof("END OF CASE #%v", k)
	}

}
