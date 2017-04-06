package main

import ("fmt"; "encoding/binary")


type ethernet_frame struct {
	color string
	
	mac_dest [6]byte
	mac_src [6]byte
	ethertype uint16
	// payload 46-1500 octets
	// 32 bits frame check seq
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
	switch this.ethertype {
	case 0x800:
		return IP
	case 0x806:
		return ARP
	default:
		return UNKNOWN
	}
}
