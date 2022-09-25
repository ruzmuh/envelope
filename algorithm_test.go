package main

import (
	"encoding/hex"
	"fmt"
	"testing"
)

func Test_aes_ecb_encrypt(t *testing.T) {
	data, err := hex.DecodeString("a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf")
	if err != nil {
		panic(err)
	}
	key, err := hex.DecodeString("56e47a38c5598974bc46903dba290349")
	if err != nil {
		panic(err)
	}
	iv, err := hex.DecodeString("8ce82eefbea0da3c44699ed7db51b7d9")
	if err != nil {
		panic(err)
	}

	bc, err := NewBlockCipher("AES", key, 128, "CBC", iv)
	if err != nil {
		panic(err)
	}
	result, err := bc.encrypt(data)
	if err != nil {
		panic(err)
	}
	hexResult := hex.EncodeToString(result)

	expectedResult := "c30e32ffedc0774e6aff6af0869f71aa0f3af07a9a31a9c684db207eb0ef8e4e35907aa632c3ffdf868bb7b29d3d46ad83ce9f9a102ee99d49a53e87f4c3da55"

	if expectedResult != hexResult {
		t.Errorf("Test vector encyption result must be = %s, not %s", expectedResult, hexResult)
	}
	fmt.Println(hexResult)

}
