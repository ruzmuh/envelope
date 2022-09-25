package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"strings"
)

type BlockEncrypter struct {
	id             string
	keySize        int
	iv             []byte
	block          cipher.Block
	BlockEncrypter cipher.BlockMode
	BlockDecrypter cipher.BlockMode
}

func NewBlockCipher(cipherName string, key []byte, blockSize int, blockMode string, iv []byte) (result *BlockEncrypter, err error) {
	block, err := parseBlockCipher(cipherName, key)
	if err != nil {
		return
	}
	if iv == nil {
		iv = getRandomBlock(blockSize / 8)
	}
	blockModeEncrypter, err := parseBlockModeEncrypter(blockMode, block, iv)
	if err != nil {
		return
	}
	blockModeDecrypter, err := parseBlockModeDecrypter(blockMode, block, iv)
	if err != nil {
		return
	}
	result = &BlockEncrypter{
		id:             fmt.Sprintf("%s_%v_%s", cipherName, len(key)*8, blockMode),
		keySize:        len(key) * 8,
		iv:             iv,
		block:          block,
		BlockEncrypter: blockModeEncrypter,
		BlockDecrypter: blockModeDecrypter,
	}
	return
}

func (be *BlockEncrypter) getID() string {
	return be.id
}

func (be *BlockEncrypter) getIV() []byte {
	return be.iv
}
func (be *BlockEncrypter) encrypt(data []byte) (result []byte, err error) {
	result = make([]byte, len(data))
	be.BlockEncrypter.CryptBlocks(result, data)
	return
}
func (be *BlockEncrypter) decrypt(data []byte) (result []byte, err error) {
	result = make([]byte, len(data))
	be.BlockDecrypter.CryptBlocks(result, data)
	return
}

func parseBlockCipher(blockCipherName string, key []byte) (block cipher.Block, err error) {
	blockCipherName = strings.ToUpper(blockCipherName)
	switch blockCipherName {
	case "AES":
		block, err = aes.NewCipher(key)
		return
	default:
		return nil, fmt.Errorf("unknown cipher %v", blockCipherName)
	}
}

func parseBlockModeEncrypter(modeName string, block cipher.Block, iv []byte) (blockMode cipher.BlockMode, err error) {
	modeName = strings.ToUpper(modeName)
	switch modeName {
	case "CBC":
		blockMode = cipher.NewCBCEncrypter(block, iv)
		return
	default:
		err = fmt.Errorf("unknown block mode %v", blockMode)
	}
	return
}

func parseBlockModeDecrypter(modeName string, block cipher.Block, iv []byte) (blockMode cipher.BlockMode, err error) {
	modeName = strings.ToUpper(modeName)
	switch modeName {
	case "CBC":
		blockMode = cipher.NewCBCDecrypter(block, iv)
		return
	default:
		err = fmt.Errorf("unknown block mode %v", blockMode)
	}
	return
}
