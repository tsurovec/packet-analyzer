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
	// loads from data, returns this and number of bytes loaded
	load([]byte) (layer, uint16)
	getName() string
	next_layer_hint() int
	get_lines() []string
	set_color(string) layer
 	get_color() string
}

const (
	COLOR_NORMAL = "\x1B[0m"
	COLOR_RED = "\x1B[31m"
	COLOR_GREEN = "\x1B[32m"
	COLOR_YELLOW = "\x1B[33m"
	COLOR_BLUE = "\x1B[34m"
	COLOR_MAGENTA = "\x1B[35m"
	COLOR_CYAN = "\x1B[36m"
	COLOR_WHITE = "\x1B[37m"
)

type colored_data struct {
	offset uint16
	color string
}

const (
	ETHERNET = iota
	ARP = iota
	IP = iota
	ICMP = iota
	TCP = iota
	UDP = iota
	HTTP = iota
	TLS_RECORD = iota
	TLS_HANDSHAKE = iota
	TLS_CLIENT_HELLO = iota
	UNKNOWN = iota
)

func load_layer(type_hint int, data []byte) (layer, uint16) {
	var r layer
	var bytes_loaded uint16
	switch type_hint {
	case ETHERNET:
		r = ethernet_frame{}
	case ARP:
		r = arp{}
	case IP:
		r = ip_packet{}
	case ICMP:
		r = icmp{}
	case TCP:
		r = tcp_packet{}
	case UDP:
		r = udp_datagram{}
	case TLS_RECORD:
		r = tls_record{}
	case TLS_HANDSHAKE:
		r = tls_handshake{}
	case TLS_CLIENT_HELLO:
		r = tls_client_hello{}
	default:
		r = unknown_layer{} 
	}
	
	r, bytes_loaded = r.load(data)
	return r, bytes_loaded	
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
		s := "\t0x"
		xy := make([]byte, 2)
		line_offset := line * per_line
		xy[0] = byte(line_offset >> 8)
		xy[1] = byte(line_offset & 0xff)
		s = s + hex.EncodeToString(xy) + ":\t" + kolo


		line_length := per_line
		if line == nlines - 1 && len(data) % 16 > 0 {
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
			
			if b > 0 && (b-1) % grouping == 0 {
				s = s + " "
			}
			
		}
		
		out[line] = s + COLOR_NORMAL
	}
	
	return out
}

func main() {
	colors := []string {COLOR_RED,
		COLOR_GREEN,
		COLOR_YELLOW,
		COLOR_MAGENTA,
		COLOR_CYAN,
		COLOR_BLUE,}
	
	coloring := []colored_data{}
	reader := bufio.NewReader(os.Stdin)
	var line string
	var ok error
	ok = nil
	ll := false
	var packet []byte 
	var data_lines []dataLine
	for ok == nil {
		line, ok = reader.ReadString('\n')
		a := analyze(line)		
		if a.loaded {
			ll = true
			packet = append(packet, a.data...)
			data_lines = append(data_lines, a)
		}


		if (!a.loaded && ll) || (a.loaded && len(a.data) < 16) {
			current_color := colors[0]
			coloring = []colored_data{colored_data{offset: 0, color: current_color}}
			i := 1

			layers := []layer{}
			
			// interpretation
			offset := 0
			var current_layer layer
			var bytes_loaded uint16
			layer_hint := ETHERNET
			for offset < len(packet) {
				current_layer, bytes_loaded = load_layer(layer_hint, packet[offset:])
				layer_hint = current_layer.next_layer_hint()
				offset = offset + int(bytes_loaded)
				
				current_layer = current_layer.set_color(current_color)
				
				coloring = append(coloring, colored_data{offset: uint16(offset), color:
					colors[i]})
				current_color = colors[i]
				layers = append(layers, current_layer)
				i = (i + 1) % len(colors)
			} 

			// Colored lines with data
			clines := printColored(coloring, packet)
			for i := 0; i< len(clines); i++ {
				fmt.Println(clines[i])
			}

			// Textual lines
			for i = 0; i < len(layers); i++ {
				fmt.Printf("\tLayer %s%s%s:\n", layers[i].get_color(), layers[i].getName(), COLOR_NORMAL)
				for j := 0; j < len(layers[i].get_lines()); j++ {
					fmt.Printf("\t\t%s\n", layers[i].get_lines()[j])
				} 
			}
			
			ll = false			
			packet = packet[:0]
			data_lines = data_lines[:0]
		}

		if(!a.loaded){
			fmt.Printf("%v", line)
		}

		
	}	
	
	fmt.Printf("END %v\n\n", ok)

	var x ip_packet
	sf := reflect.Type.Field(reflect.TypeOf(x), 0)
	fmt.Println(sf)
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
