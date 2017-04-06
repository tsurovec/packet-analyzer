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

type unknown_layer struct {color string}
func (this unknown_layer)load(data []byte) (layer, uint16) {
	return this, uint16(len(data))
}
func (this unknown_layer)getName() string {
	return "UNKNOWN"
}
func (this unknown_layer)get_lines() []string  {
	return []string { "-- no interpretation --" }
}
func (this unknown_layer)next_layer_hint() int {
	return UNKNOWN
}
func (this unknown_layer) set_color(color string) layer {
	this.color = color
	return this
}
func (this unknown_layer)get_color() string {
	return this.color
}

func (this ethernet_frame) get_lines() []string {
	return []string {
		fmt.Sprintf("Destionation MAC = %x", this.mac_dest),
		fmt.Sprintf("Source MAC = %x", this.mac_src),
		fmt.Sprintf("Ethertype = 0x%04x", this.ethertype),
	}
}
func(this ethernet_frame) set_color(clr string) layer {
	this.color = clr
	return this
}
func(this ethernet_frame) get_color() string {
	return this.color
}
func (this ethernet_frame) load(data []byte) (layer, uint16) {
	// todo: assert(len(data) >= 14)
	
	for i := 0 ; i < 6; i++ {
		this.mac_dest[i] = data[i]
	}
	for i := 0 ; i < 6; i++ {
		this.mac_src[i] = data[6 + i]
	}
	
	this.ethertype = binary.BigEndian.Uint16(data[12:14])	
	
	return this, 14 
}

func (this ethernet_frame) getName() string {
	return "Ethernet"
}
func (this ethernet_frame)next_layer_hint() int {
	if this.ethertype == 0x800 {
		return IP
	}
//todo: if ethertype == 0x800, then ip; 806->arp,etc
	return UNKNOWN
}

type ethernet_frame struct {
	color string
	
	mac_dest [6]byte
	mac_src [6]byte
	ethertype uint16
	// payload 46-1500 octets
	// 32 bits frame check seq
}

type ip_packet struct {
	// header
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

	// other
	color string
}

func (this ip_packet)load(data []byte) (layer, uint16) {
	this.version_ihl = uint8(data[0])
	this.dscp_ecn = uint8(data[1])
	
	return this, uint16((this.version_ihl & 0xf) << 2)
}
func (this ip_packet)getName() string {
	return "IP"
}
func (this ip_packet)next_layer_hint() int {
	return UNKNOWN
}
func (this ip_packet)get_lines() []string {
	return []string {
		fmt.Sprintf("Version: %d", this.version_ihl >> 4),
		fmt.Sprintf("IHL: %d", this.version_ihl & 0x0f),
	}
}
func (this ip_packet)set_color(color string) layer {
	this.color = color
	return this
}
func (this ip_packet)get_color() string {
	return this.color
}



type colored_data struct {
	offset uint16
	color string
}

const (
	ETHERNET = iota
	IP = iota
	ARP = iota
	TCP = iota
	HTTP = iota
	TLS_RECORD = iota
	UNKNOWN = iota
)

func load_layer(type_hint int, data []byte) (layer, uint16) {
	var r layer
	var bytes_loaded uint16
	switch type_hint {
	case ETHERNET:
		r = ethernet_frame{}
	case IP:
		r = ip_packet{}
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
	colors := []string {COLOR_RED,
		COLOR_GREEN,
		COLOR_YELLOW,
		COLOR_BLUE,
		COLOR_MAGENTA,
		COLOR_CYAN}
	
	fmt.Println("PAGO \x1B[32m>\x1B[0m")
	coloring := []colored_data{
		colored_data{offset: 0, color: "\x1B[32m"},
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
				i++
			} 

			// Colored lines with data
			clines := printColored(coloring, packet)
			for i := 0; i< len(clines); i++ {
				fmt.Println(clines[i])
			}

			// Textual lines
			for i = 0; i < len(layers); i++ {
				fmt.Printf("Layer %s%s%s:\n", layers[i].get_color(), layers[i].getName(), COLOR_NORMAL)
				for j := 0; j < len(layers[i].get_lines()); j++ {
					fmt.Printf("\t%s\n", layers[i].get_lines()[j])
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

/*func get_l3(ethertype uint16, data []byte) (ip_header, []byte) {
	ip := ip_header{}

	ip.version_ihl = data[0]
	ip.dscp_ecn = data[1]
	ip.total_length = binary.BigEndian.Uint16(data[1:3])
	// etc.
	ip.ip_src = binary.BigEndian.Uint32(data[12:16])
	ip.ip_dst = binary.BigEndian.Uint32(data[16:20])
//	for i := 0 ; i < 6; i++ {
//		ef.mac_dest[i] = data[i]
//	}
//	for i := 0 ; i < 6; i++ {
//		ef.mac_src[i] = data[6 + i]
//	}
//	ef.ethertype = binary.BigEndian.Uint16(data[12:14])	
//	return ef, data[14:]

	l4offset := 20 // default ip header length
	return ip, data[l4offset:]
}*/

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
