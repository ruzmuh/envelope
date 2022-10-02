package envelope

type Encrypter interface {
	encrypt(key, data []byte) (result []byte, err error)
	decrypt(key, data []byte) (result []byte, err error)
	MarshalCBOR() (data []byte, err error)
	UnmarshalCBOR(data []byte) (err error)
}
