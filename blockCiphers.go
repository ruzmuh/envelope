package main

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
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
	result = make([]byte, len(data))
	bm.CryptBlocks(result, data)
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
	result = make([]byte, len(data))
	bm.CryptBlocks(result, data)
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
