package envelope

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"math/rand"
	"strconv"
	"strings"
	"time"
)

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

func parsePhaseString(phase string) (result phaseParameterSet, err error) {
	ph1Slice := strings.Split(phase, "_")
	if len(ph1Slice) != 3 {
		err = fmt.Errorf("phase 1 string is %s, must be ALG_SIZE_MODE", phase)
		return
	}
	result.alg = ph1Slice[0]
	result.blockSize, err = strconv.Atoi(ph1Slice[1])
	if err != nil {
		return
	}
	result.mode = ph1Slice[2]
	return
}

func getRandomBlock(bytesBlockSize int) (result []byte) {
	rand.Seed(time.Now().UnixNano())
	result = make([]byte, bytesBlockSize)
	rand.Read(result)
	return
}
