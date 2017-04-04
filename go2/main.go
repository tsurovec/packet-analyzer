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

type layer_data interface {
	
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

func main() {
	fmt.Println("PAGO \x1B[32m>\x1B[0m")

	reader := bufio.NewReader(os.Stdin)

	var line string
	var ok error
	ok = nil
	ll := false
	var packet []byte 
	for ok == nil {
		line, ok = reader.ReadString('\n')
		
		fmt.Printf("%v", line)
		a := analyze(line)
		if a.loaded {
			ll = true
			packet = append(packet, a.data...)
//			fmt.Printf("Offset = %v; Data: %v\n", a.offset, a.data)
//			if a.offset == 0 {
//				ef, r := get_l2(a.data)
//				fmt.Printf("EtherType = %v; %v\n", ef.ethertype, len(r))
			
//			}			
		}


		if (!a.loaded && ll) || (a.loaded && len(a.data) < 16) {
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
			

			packet =packet [:0]

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
