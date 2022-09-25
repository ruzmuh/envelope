package main

import (
	"fmt"
	"os"

	"github.com/pborman/getopt/v2"
)

func main() {
	optPh1Alg := getopt.StringLong("ph1alg", '1', "AES_128_CBC", "Phase 1 algorithm")
	optPh2Alg := getopt.StringLong("ph2alg", '2', "AES_128_CBC", "Phase 2 algorithm")
	optKEK := getopt.StringLong("kek", 'k', "", "KEK key value")
	optInputFile := getopt.StringLong("in", 'i', "", "Input file to process")
	optOutputFile := getopt.StringLong("out", 'o', "", "Output file to process")
	optDecrypt := getopt.BoolLong("decrypt", 'd', "whether to decrypt")
	optHelp := getopt.BoolLong("help", 0, "Help")
	getopt.Parse()

	if *optHelp {
		getopt.Usage()
		os.Exit(0)
	}

	fmt.Println("Hello " + *optPh1Alg + *optPh2Alg + *optKEK + *optInputFile + *optOutputFile + "!")
	if *optDecrypt {
		fmt.Println("Decrypt")
	}

	dat, err := os.ReadFile(*optInputFile)
	if err != nil {
		panic("cant open file: " + err.Error())

	}

	if !*optDecrypt {
		envelope, _ := NewEnvelope(*optPh1Alg, []byte(*optKEK))
		result, _ := envelope.encrypt(*optPh2Alg, dat)
		fmt.Print(result)
	}
}

// func main() {
// 	e := Envelope{}
// 	fmt.Println(e.plainDEK)
// }
