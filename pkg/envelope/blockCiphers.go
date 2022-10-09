package envelope

import (
	"crypto/cipher"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	log "github.com/sirupsen/logrus"
)

type BlockEncrypter struct {
	id      string
	keySize int
	iv      []byte
}

func NewBlockCipher(cipherName string, blockSize int, blockMode string) (result *BlockEncrypter, err error) {
	result = &BlockEncrypter{
		id:      fmt.Sprintf("%s_%v_%s", cipherName, blockSize, blockMode),
		keySize: blockSize,
		iv:      getRandomBlock(blockSize / 8),
	}
	return
}
func (be *BlockEncrypter) getID() string {
	return be.id
}
func (be *BlockEncrypter) encrypt(key, data []byte) (result []byte, err error) {

	phParam, err := parsePhaseString(be.id)
	if err != nil {
		return
	}
	block, err := parseBlockCipher(phParam.alg, key)
	if err != nil {
		return
	}
	bm, err := parseBlockModeEncrypter(phParam.mode, block, be.iv)
	if err != nil {
		return
	}

	switch v := bm.(type) {
	case cipher.BlockMode:
		log.Infof("Encryption mode is BlockMode")
		padedData := padOneAndZeroes(phParam.blockSize/8, data)
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
	phParam, err := parsePhaseString(be.id)
	if err != nil {
		return
	}

	block, err := parseBlockCipher(phParam.alg, key)
	if err != nil {
		return
	}
	bm, err := parseBlockModeDecrypter(phParam.mode, block, be.iv)
	if err != nil {
		return
	}
	switch v := bm.(type) {
	case cipher.BlockMode:
		log.Infof("Decryption mode is Block")
		result = make([]byte, len(data))
		v.CryptBlocks(result, data)
		result, err = stripOneAndZeroes(phParam.blockSize/8, result)
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
		Id      string
		KeySize int
		Iv      []byte
	}{
		Id:      m.id,
		KeySize: m.keySize,
		Iv:      m.iv,
	}
	return cbor.Marshal(t)
}

func (m *BlockEncrypter) UnmarshalCBOR(data []byte) (err error) {
	var t struct {
		Id      string
		KeySize int
		Iv      []byte
	}
	if err := cbor.Unmarshal(data, &t); err != nil {
		return err
	}
	*m = BlockEncrypter{
		id:      t.Id,
		keySize: t.KeySize,
		iv:      t.Iv,
	}
	return
}
