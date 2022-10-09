package envelope

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"math/rand"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
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

func parseBlockModeEncrypter(modeName string, block cipher.Block, iv []byte) (blockMode interface{}, err error) {
	modeName = strings.ToUpper(modeName)
	switch modeName {
	case "CBC":
		blockMode = cipher.NewCBCEncrypter(block, iv)
		return
	case "CFB":
		blockMode = cipher.NewCFBEncrypter(block, iv)
		return
	case "CTR":
		blockMode = cipher.NewCTR(block, iv)
		return
	case "OFB":
		blockMode = cipher.NewOFB(block, iv)
		return
	default:
		err = fmt.Errorf("unknown block mode %v", blockMode)
	}
	return
}

func parseBlockModeDecrypter(modeName string, block cipher.Block, iv []byte) (blockMode interface{}, err error) {
	modeName = strings.ToUpper(modeName)
	switch modeName {
	case "CBC":
		blockMode = cipher.NewCBCDecrypter(block, iv)
		return
	case "CFB":
		blockMode = cipher.NewCFBDecrypter(block, iv)
		return
	case "CTR":
		blockMode = cipher.NewCTR(block, iv)
		return
	case "OFB":
		blockMode = cipher.NewOFB(block, iv)
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

func padOneAndZeroes(blockSizeInBytes int, data []byte) (result []byte) {
	lastBlockLength := len(data) % blockSizeInBytes
	log.Infof("lastblock size=%v bytes, let's put pad %v bytes", lastBlockLength, blockSizeInBytes-lastBlockLength)
	padding := make([]byte, blockSizeInBytes-lastBlockLength)
	padding[0] = 0x80
	result = append(data, padding...)
	return result
}

func stripOneAndZeroes(blockSizeInBytes int, data []byte) (result []byte, err error) {
	log.Info("striping OneAndZeroes")
	for i := len(data) - 1; i >= 0; i-- {
		if data[i] == 0x80 {
			result = data[:i]
			return
		}
	}
	return data, nil
}
