package envelope

import (
	"github.com/fxamacker/cbor/v2"
	log "github.com/sirupsen/logrus"
)

type phaseParameterSet struct {
	alg       string
	blockSize int
	mode      string
}
type Envelope struct {
	phase1        Encrypter
	phase2        Encrypter
	encryptedData []byte
	encryptedDEK  []byte
}

func NewEnvelope(ph1 string) (result Envelope, err error) {
	log.Infof("Creating a new envelope with ph1=%s", ph1)
	ph1params, err := parsePhaseString(ph1)
	if err != nil {
		return
	}

	result.phase1, err = NewBlockCipher(ph1params.alg, ph1params.blockSize, ph1params.mode)
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

func (m *Envelope) UnmarshalCBOR(data []byte) (err error) {
	var t struct {
		Phase1 struct {
			Id string
		}
		Phase2 struct {
			Id string
		}
	}
	if err := cbor.Unmarshal(data, &t); err != nil {
		return err
	}

	var envelope struct {
		Phase1        Encrypter
		Phase2        Encrypter
		EncryptedDEK  []byte
		EncryptedData []byte
	}

	ph1, err := parsePhaseString(t.Phase1.Id)
	if err != nil {
		return
	}
	if ph1.alg == "AES" {
		envelope.Phase1 = &BlockEncrypter{}
	}

	ph2, err := parsePhaseString(t.Phase2.Id)
	if err != nil {
		return
	}
	if ph2.alg == "AES" {
		envelope.Phase2 = &BlockEncrypter{}
	}

	if err := cbor.Unmarshal(data, &envelope); err != nil {
		return err
	}
	*m = Envelope{
		phase1:        envelope.Phase1,
		phase2:        envelope.Phase2,
		encryptedData: envelope.EncryptedData,
		encryptedDEK:  envelope.EncryptedDEK,
	}
	return
}

func (envelope *Envelope) Encrypt(ph1key []byte, ph2 string, data []byte) (result []byte, err error) {
	log.Infof("Encrypting data with ph2=%s", ph2)
	ph2params, err := parsePhaseString(ph2)
	if err != nil {
		return
	}
	log.Infof("Generating phase2 random key with size=%v", ph2params.blockSize)
	ph2Key := getRandomBlock(ph2params.blockSize / 8)
	if err != nil {
		return
	}
	log.Infof("Encrypting KEK with ph1 key")
	envelope.encryptedDEK, err = envelope.phase1.encrypt(ph1key, ph2Key)
	if err != nil {
		return
	}

	envelope.phase2, err = NewBlockCipher(ph2params.alg, ph2params.blockSize, ph2params.mode)
	if err != nil {
		return
	}
	log.Infof("Encrypting data with ph2 key")
	envelope.encryptedData, err = envelope.phase2.encrypt(ph2Key, data)
	if err != nil {
		return
	}
	log.Infof("Marshaling envelope")
	result, err = cbor.Marshal(*envelope)
	return
}

func Decrypt(ph1key []byte, encryptedContainer []byte) (result []byte, err error) {
	envelope := Envelope{}
	log.Infof("Unmarshaling envelope")
	err = cbor.Unmarshal(encryptedContainer, &envelope)
	if err != nil {
		return
	}
	log.Infof("Decrypting KEK with ph1 key")
	plainDEK, err := envelope.phase1.decrypt(ph1key, envelope.encryptedDEK)
	if err != nil {
		return
	}
	log.Infof("Decrypting data with ph2=%s", envelope.phase2.getID())
	result, err = envelope.phase2.decrypt(plainDEK, envelope.encryptedData)
	return
}
