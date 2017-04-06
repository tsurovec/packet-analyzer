package main

import ("fmt";"encoding/binary")

type tcp_packet struct {
	// header
	source_port uint16
	dest_port uint16
	seq_num uint32
	ack_num uint32
	dataoffset_000_ns uint8
	flags uint8
	window_size uint16
	checksum uint16
	urgent_ptr uint16

	// todo options
	
	// other
	color string
}

func (this tcp_packet)load(data []byte) (layer, uint16) {
	this.source_port = binary.BigEndian.Uint16(data[0:2])
	this.dest_port = binary.BigEndian.Uint16(data[2:4])
	this.dataoffset_000_ns = uint8(data[12])
	
	return this, uint16((this.dataoffset_000_ns & 0xf0) >> 2)
}
func (this tcp_packet)getName() string {
	return "TCP"
}
func (this tcp_packet)next_layer_hint() int {
	if this.source_port == 443 || this.dest_port == 443 {
		return TLS_RECORD
	} 
	return UNKNOWN
}
func (this tcp_packet)get_lines() []string {
	return []string {
		fmt.Sprintf("Source port: %d; Destination port: %d",
			this.source_port, this.dest_port),
		fmt.Sprintf("Data offse (= TCP header size): %d", (0xf0&this.dataoffset_000_ns) >> 2),
	}
}
func (this tcp_packet)set_color(color string) layer {
	this.color = color
	return this
}
func (this tcp_packet)get_color() string {
	return this.color
}
