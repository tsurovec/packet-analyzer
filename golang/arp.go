package main

import ("fmt";"encoding/binary")

type arp struct {
	htype uint16
	ptype uint16
	hlen uint8
	plen uint8
	oper uint16 // operation
	sha [6]byte // sender hardware address
	spa uint32 // sender protocol address
	tha [6]byte // target hardware address
	tpa uint32
	
	// other
	color string
}

func (this arp)load(data []byte) (layer, uint16) {
	this.htype = binary.BigEndian.Uint16(data[0:2])
	this.ptype = binary.BigEndian.Uint16(data[2:4])
	this.hlen = uint8(data[4])
	this.plen = uint8(data[5])
	this.oper = binary.BigEndian.Uint16(data[6:8])
	for i:=0;i<6;i++ {
		this.sha[i] = data[8 + i]
	}
	this.spa = binary.BigEndian.Uint32(data[14:18])
	for i:=0;i<6;i++ {
		this.tha[i] = data[18 + i]
	}
	this.tpa = binary.BigEndian.Uint32(data[24:26])
	
	return this, uint16(26)
}
func (this arp)getName() string {
	return "ARP"
}
func (this arp)next_layer_hint() int {
	return UNKNOWN
}
func (this arp)get_lines() []string {
	return []string {
		fmt.Sprintf("Hardware type: (%d); Protocol Type: (%d)",
			this.htype, this.ptype),
	}
}
func (this arp)set_color(color string) layer {
	this.color = color
	return this
}
func (this arp)get_color() string {
	return this.color
}
func (this arp)get_type_string(t uint8) string {
	switch t {
	case 0:
		return "Echo reply"
	case 3:
		return "Destination unreachable"
	case 4:
		return "Source quench"
	case 8:
		return "Echo request"
	default:
		return "?"
	}
}
