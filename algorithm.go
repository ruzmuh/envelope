package main

type Encrypter interface {
	getID() string
	getIV() []byte
	encrypt(data []byte) (result []byte, err error)
	decrypt(data []byte) (result []byte, err error)
}
