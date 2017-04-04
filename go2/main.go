package main

import (
	"fmt"
	"bufio"
	"os"; "regexp"
	"encoding/hex"
	"encoding/binary"
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
		a := analyze(line)
		if a.loaded {
			fmt.Printf("Offset = %v; Data: %v\n", a.offset, a.data)
		}
	}	
	
	fmt.Printf("END %v", ok)
}

func analyze(line string) dataLine {
	regex, _ := regexp.Compile("^\\s*0x([0-9a-fA-F]{4}):\\s+(.*)\\s*$")
	
	dataLineMatch := regex.FindStringSubmatch(line)
	if len(dataLineMatch) == 0 {
		return dataLine{loaded: false}
	}
	
	offsetBytes, _ := hex.DecodeString(dataLineMatch[1])
	dl := dataLine{loaded: true, offset: binary.BigEndian.Uint16(offsetBytes)}
	
	data := dataLineMatch[2]

	dataRegex, _ := regexp.Compile("^\\s*([0-9a-fA-F]{2})(.*)$")

	var tgt []byte
	nonempry := true
	for nonempry {
		onebyte := dataRegex.FindStringSubmatch(data)
		if len(onebyte) > 0 {
			//fmt.Printf("\t1: %v ; %v\n", onebyte[1], len(onebyte))
			deko, _ := hex.DecodeString(onebyte[1])
			tgt = append(tgt, deko[0])
			if(len(onebyte) > 2) {
				data = onebyte[2]
			}			
		} else {
			nonempry=false
		}
	}

	dl.data = tgt	
	return dl
}
