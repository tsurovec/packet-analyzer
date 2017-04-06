package main

import ("fmt";"encoding/binary")

type udp_datagram struct {
	// header
	source_port uint16
	dest_port uint16
	length uint16
	checksum uint16
	
	// other
	color string
}

func (this udp_datagram)load(data []byte) (layer, uint16) {
	this.source_port = binary.BigEndian.Uint16(data[0:2])
	this.dest_port = binary.BigEndian.Uint16(data[2:4])
	this.length = binary.BigEndian.Uint16(data[4:6])
	this.checksum = binary.BigEndian.Uint16(data[6:8])
		
	return this, uint16(8)
}
func (this udp_datagram)getName() string {
	return "UDP"
}
func (this udp_datagram)next_layer_hint() int {
	return UNKNOWN
}
func (this udp_datagram)get_lines() []string {
	return []string {
		fmt.Sprintf("Source port: %d; Destination port: %d",
			this.source_port, this.dest_port),
		fmt.Sprintf("Length: %d; Checksum: %d", this.length, this.checksum),
	}
}
func (this udp_datagram)set_color(color string) layer {
	this.color = color
	return this
}
func (this udp_datagram)get_color() string {
	return this.color
}
