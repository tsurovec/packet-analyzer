package main

import ("fmt";"encoding/binary")

type icmp struct {
	// header
	icmp_type uint8
	code uint8
	checksum uint16
	rest_of_header uint32
	
	// other
	color string
}

func (this icmp)load(data []byte) (layer, uint16) {
	this.icmp_type = uint8(data[0])
	this.code = uint8(data[1])
	this.checksum = binary.BigEndian.Uint16(data[2:4])
	this.rest_of_header = binary.BigEndian.Uint32(data[4:8])
		
	return this, uint16(8)
}
func (this icmp)getName() string {
	return "ICMP"
}
func (this icmp)next_layer_hint() int {
	return UNKNOWN
}
func (this icmp)get_lines() []string {
	return []string {
		fmt.Sprintf("Type: %s (%d); Code: (%d)",
			this.get_type_string(this.icmp_type), this.icmp_type, this.code),
		fmt.Sprintf("Rest of header: %x", this.rest_of_header),
	}
}
func (this icmp)set_color(color string) layer {
	this.color = color
	return this
}
func (this icmp)get_color() string {
	return this.color
}
func (this icmp)get_type_string(t uint8) string {
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
