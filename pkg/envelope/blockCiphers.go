package envelope

import (
	"crypto/cipher"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	log "github.com/sirupsen/logrus"
)

type BlockEncrypter struct {
	cipherName string
	blockSize  int
	blockMode  string
	iv         []byte
}

func NewBlockCipher(cipherName string, blockSize int, blockMode string) (result *BlockEncrypter, err error) {
	result = &BlockEncrypter{
		cipherName: cipherName,
		blockSize:  blockSize,
		blockMode:  blockMode,
		iv:         getRandomBlock(blockSize / 8),
	}
	return
}

func (be *BlockEncrypter) getID() string {
	return fmt.Sprintf("%s_%v_%s", be.cipherName, be.blockSize, be.blockMode)
}

func (be *BlockEncrypter) encrypt(key, data []byte) (result []byte, err error) {
	block, err := parseBlockCipher(be.cipherName, key)
	if err != nil {
		return
	}
	bm, err := parseBlockModeEncrypter(be.blockMode, block, be.iv)
	if err != nil {
		return
	}

	switch v := bm.(type) {
	case cipher.BlockMode:
		log.Infof("Encryption mode is BlockMode")
		padedData := padOneAndZeroes(be.blockSize/8, data)
		result = make([]byte, len(padedData))
		v.CryptBlocks(result, padedData)
		return
	case cipher.Stream:
		log.Infof("Encryption mode is Stream")
		result = make([]byte, len(data))
		v.XORKeyStream(result, data)
		return
	}
	return
}

func (be *BlockEncrypter) decrypt(key, data []byte) (result []byte, err error) {

	block, err := parseBlockCipher(be.cipherName, key)
	if err != nil {
		return
	}
	bm, err := parseBlockModeDecrypter(be.blockMode, block, be.iv)
	if err != nil {
		return
	}
	switch v := bm.(type) {
	case cipher.BlockMode:
		log.Infof("Decryption mode is Block")
		result = make([]byte, len(data))
		v.CryptBlocks(result, data)
		result, err = stripOneAndZeroes(be.blockSize/8, result)
		return
	case cipher.Stream:
		log.Infof("Decryption mode is Stream")
		result = make([]byte, len(data))
		v.XORKeyStream(result, data)
		return
	}
	return
}

func (m *BlockEncrypter) MarshalCBOR() (data []byte, err error) {
	t := struct {
		CipherName string
		BlockSize  int
		BlockMode  string
		Iv         []byte
	}{
		CipherName: m.cipherName,
		BlockSize:  m.blockSize,
		BlockMode:  m.blockMode,
		Iv:         m.iv,
	}
	return cbor.Marshal(t)
}

func (m *BlockEncrypter) UnmarshalCBOR(data []byte) (err error) {
	var t struct {
		CipherName string
		BlockSize  int
		BlockMode  string
		Iv         []byte
	}
	if err := cbor.Unmarshal(data, &t); err != nil {
		return err
	}
	*m = BlockEncrypter{
		cipherName: t.CipherName,
		blockSize:  t.BlockSize,
		blockMode:  t.BlockMode,
		iv:         t.Iv,
	}
	return
}
