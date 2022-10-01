package main

import (
	"fmt"
	"math/rand"
	"strconv"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
)

type phaseParameterSet struct {
	alg       string
	blockSize int
	mode      string
}
type Envelope struct {
	phase1        Encrypter
	phase2        Encrypter
	plainData     []byte
	encryptedData []byte
	encryptedDEK  []byte
}

func NewEnvelope(ph1 string, ph1key []byte) (result Envelope, err error) {
	ph1params, err := parsePhaseString(ph1)
	if err != nil {
		return
	}

	result.phase1, err = NewBlockCipher(ph1params.alg, ph1key, ph1params.blockSize, ph1params.mode, nil)
	if err != nil {
		return
	}
	return
}

func (m *Envelope) MarshalCBOR() (data []byte, err error) {
	t := struct {
		Phase1        Encrypter
		Phase2        Encrypter
		EncryptedDEK  []byte
		EncryptedData []byte
	}{
		Phase1:        m.phase1,
		Phase2:        m.phase2,
		EncryptedDEK:  m.encryptedDEK,
		EncryptedData: m.encryptedData,
	}
	return cbor.Marshal(t)
}

func parsePhaseString(phase string) (result phaseParameterSet, err error) {
	ph1Slice := strings.Split(phase, "_")
	if len(ph1Slice) != 3 {
		err = fmt.Errorf("phase 1 string is %s, must be ALG_SIZE_MODE", phase)
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

func (envelope *Envelope) encrypt(ph2 string, data []byte) (result []byte, err error) {
	ph2params, err := parsePhaseString(ph2)
	if err != nil {
		return
	}

	ph2Key := getRandomBlock(ph2params.blockSize / 8)
	if err != nil {
		return
	}
	envelope.encryptedDEK, err = envelope.phase1.encrypt(ph2Key)
	if err != nil {
		return
	}

	envelope.phase2, err = NewBlockCipher(ph2params.alg, ph2Key, ph2params.blockSize, ph2params.mode, nil)
	if err != nil {
		return
	}

	envelope.encryptedData, err = envelope.phase2.encrypt(data)
	if err != nil {
		return
	}
	envelope.plainData = data
	result, err = cbor.Marshal(*envelope)
	fmt.Print(string(result))
	return
}
