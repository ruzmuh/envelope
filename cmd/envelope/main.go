package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"os"

	"github.com/pborman/getopt/v2"
	"github.com/ruzmuh/envelope/pkg/envelope"
)

func main() {
	optPh1Alg := getopt.StringLong("ph1alg", '1', "AES_128_CBC", "Phase 1 algorithm")
	optPh2Alg := getopt.StringLong("ph2alg", '2', "AES_128_CBC", "Phase 2 algorithm")
	optKEK := getopt.StringLong("kek", 'k', "", "KEK key value in base64 format")
	optInputFile := getopt.StringLong("in", 'i', "", "Input file to process")
	optOutputFile := getopt.StringLong("out", 'o', "", "Output file to process")
	optDecrypt := getopt.BoolLong("decrypt", 'd', "whether to decrypt")
	optHelp := getopt.BoolLong("help", 0, "Help")
	getopt.Parse()

	if *optHelp {
		getopt.Usage()
		os.Exit(0)
	}

	dat, err := os.ReadFile(*optInputFile)
	if err != nil {
		panic("cant open file: " + err.Error())
	}

	f, err := os.Create(*optOutputFile)
	if err != nil {
		log.Fatal(err)
	}

	defer f.Close()

	key, err := base64.StdEncoding.DecodeString(*optKEK)
	if err != nil {
		panic("can't decode key: " + err.Error())
	}
	if *optDecrypt {
		fmt.Println("Decrypt")
		result, err := envelope.Decrypt(key, dat)
		if err != nil {
			panic(err)
		}
		f.Write(result)

	}

	if !*optDecrypt {
		envelopeObject, _ := envelope.NewEnvelope(*optPh1Alg)
		result, _ := envelopeObject.Encrypt(key, *optPh2Alg, dat)
		f.Write(result)
	}

}

// func main() {
// 	e := Envelope{}
// 	fmt.Println(e.plainDEK)
// }
