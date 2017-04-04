package main

import (
	"fmt"
	"bufio"
	"os"; "regexp"
	"encoding/hex"
)

type dataLine struct {
	loaded bool
	offset uint16
	data []byte
}

func main() {
	fmt.Println("PAGO \x1B[32m>\x1B[0m")

	reader := bufio.NewReader(os.Stdin)

	var line string
	var ok error
	ok = nil
	
	for ok == nil {
		line, ok = reader.ReadString('\n')
		fmt.Printf("%v", line)
		analyze(line)
	}	
	
	fmt.Printf("END %v", ok)
}

func analyze(line string) dataLine {
	regex, _ := regexp.Compile("^\\s*0x([0-9a-fA-F]{4}):\\s+(.*)\\s*$")
//	regex, _ := regexp.Compile("^\\s*0x([0-9a-fA-F]{4}):\\s+([0-9a-fA-F]+\\s+)+\\s*$")

	sms := regex.FindStringSubmatch(line)
	if len(sms) == 0 {
		return dataLine{loaded: false}
	}

	// todo: sms[1] to uint16
	
	dl := dataLine{loaded: true, offset: /*sms[1]*/0}


	//var dst [20]byte 
	sms1dec, _ := hex.DecodeString(sms[1])


	
	var data string
	data = sms[2]

	fmt.Printf("__%v__; %v, %v\n", sms[1], len(sms1dec),sms1dec)

	// todo: skip whitespaces, read 2 bytes, if hexabytes, convert to byte, skip, continue until end of string
	// or bad character encountered
	fmt.Printf("DATA=%v\n", data)

	kkt, _ := hex.DecodeString(data[:4])
	fmt.Printf("%v, %v, %v\n",data[:4], len(kkt),kkt)
	
	
	return dl
}
