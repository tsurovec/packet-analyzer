package main

import (
	"fmt"
	"bufio"
	"os"; "regexp"
	"encoding/hex"
	"encoding/binary"
	"reflect"
)

type dataLine struct {
	loaded bool
	offset uint16
	data []byte
}

type layer interface {
	load([]byte) (layer, uint16)
	getName() string
	getColor() string
	
	// get fields/print
}

type ethernet_frame struct {
	mac_dest [6]byte
	mac_src [6]byte
	ethertype uint16
	// payload 46-1500 octets
	// 32 bits frame check seq
}

type ip_header struct {
	version_ihl uint8;
	dscp_ecn uint8;
	total_length uint16;
	identification uint16;
	flags_f_offset uint16;
	ttl uint8;
	protocol uint8;
	header_checksum uint16;
	ip_src uint32;
	ip_dst uint32;	
}

type colored_data struct {
	offset uint16
	color string
}

// todo: groupBy N bytes, perLine N bytes
func printColored(boundaries []colored_data, data []byte) []string {
	grouping := 2
	per_line := 16
	// 16 bytes per line, grouped by 2 bytes
	nlines := len(data) / 16
	if len(data) % 16 > 0 {
		nlines++
	}
	out := make([]string, nlines)

	kolo := "\x1B[0m"
	
	for line := 0; line < nlines; line++ {
//		line_data := data[per_line * line:per_line]

		s := "\t0x"
		xy := make([]byte, 2)
		line_offset := line * per_line
		xy[0] = byte(line_offset >> 8)
		xy[1] = byte(line_offset & 0xff)
		s = s + hex.EncodeToString(xy) + ":\t" + kolo


		line_length := per_line
		if line == nlines -1 {
			line_length = len(data) % 16
		}

		for b := 0; b < line_length; b++ {
			total_offset := line * per_line + b

			// inserting coulourings
			for x := 0; x < len(boundaries); x++ {
				//fmt.Println("!")
				if(boundaries[x].offset == uint16(total_offset)) {
					s = s + boundaries[x].color
					kolo =  boundaries[x].color
				}
			}
	
			// add byte from total_offset
			xxx := make([]byte, 1)
			xxx[0] = data[total_offset]
			s = s + hex.EncodeToString(xxx)
			
			// if b > 0 && b % grouping == 0, insert space
			
//		fmt.Printf("(b=%v, s=%v)",b, s)
			if b > 0 && (b-1) % grouping == 0 {
				s = s + " "
//				fmt.Printf("(%v)",b)
			}
			
		}
		
		out[line] = s + "\x1B[0m"
	}
	
	return out
}

func main() {
	fmt.Println("PAGO \x1B[32m>\x1B[0m")
	coloring := []colored_data{ colored_data{offset: 0, color: "\x1B[32m"},
		colored_data{offset: 14, color: "\x1B[33m"},
		colored_data{offset: 34, color: "\x1B[36m"},
		colored_data{offset: 54, color: "\x1B[35m"},
	}
	reader := bufio.NewReader(os.Stdin)
	//var l2 layer
	//layer = ethernet_frame{}
	var line string
	var ok error
	ok = nil
	ll := false
	var packet []byte 
	var data_lines []dataLine
	//var wasdataline boolean
	for ok == nil {
		line, ok = reader.ReadString('\n')
		
		a := analyze(line)		
		if a.loaded {
			ll = true
			packet = append(packet, a.data...)
			data_lines = append(data_lines, a)
		}


		if (!a.loaded && ll) || (a.loaded && len(a.data) < 16) {
			clines := printColored(coloring, packet)
			for i := 0; i< len(clines); i++ {
				fmt.Println(clines[i])
			}
			
			ll = false
			fmt.Printf("Interpreting packet, len = %v\n", len(packet))
			// todo: interpretation

			ef, r := get_l2(packet)
			fmt.Printf("EtherType = %v; Rest (L3): %v bytes\n", ef.ethertype, len(r))

			iph, r2 := get_l3(ef.ethertype, r)
			fmt.Printf("%v.%v.%v.%v; Rest (L4): %v bytes\n", iph.ip_src >> 24,
				0xff&(iph.ip_src >> 16),
				(iph.ip_src >> 8)&0xff,
				iph.ip_src & 0xff, len(r2))
			

			packet = packet[:0]
			data_lines = data_lines[:0]
		}

		if(!a.loaded){
			fmt.Printf("%v", line)
		}

		
	}	
	
	fmt.Printf("END %v\n\n", ok)

	var x ip_header
	sf := reflect.Type.Field(reflect.TypeOf(x), 0)
	fmt.Println(sf)
}

func get_l2(data []byte) (ethernet_frame, []byte) {
	ef := ethernet_frame{}


	for i := 0 ; i < 6; i++ {
		ef.mac_dest[i] = data[i]
	}
	for i := 0 ; i < 6; i++ {
		ef.mac_src[i] = data[6 + i]
	}
	ef.ethertype = binary.BigEndian.Uint16(data[12:14])	
	return ef, data[14:]
}

func get_l3(ethertype uint16, data []byte) (ip_header, []byte) {
	ip := ip_header{}

	ip.version_ihl = data[0]
	ip.dscp_ecn = data[1]
	ip.total_length = binary.BigEndian.Uint16(data[1:3])
	// etc.
	ip.ip_src = binary.BigEndian.Uint32(data[12:16])
	ip.ip_dst = binary.BigEndian.Uint32(data[16:20])
/*	for i := 0 ; i < 6; i++ {
		ef.mac_dest[i] = data[i]
	}
	for i := 0 ; i < 6; i++ {
		ef.mac_src[i] = data[6 + i]
	}
	ef.ethertype = binary.BigEndian.Uint16(data[12:14])	
	return ef, data[14:]*/

	l4offset := 20 // default ip header length
	return ip, data[l4offset:]
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
