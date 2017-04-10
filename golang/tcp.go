package main

import ("fmt";"encoding/binary")

type tcp_packet struct {
	// header
	source_port uint16
	dest_port uint16
	seq_num uint32
	ack_num uint32
	
	dataoffset uint8
	flags uint16

	window_size uint16
	checksum uint16
	urgent_ptr uint16

	// todo options
options []string
	
	
	
	// other
	color string
}

func (this tcp_packet)load(data []byte) (layer, uint16) {
	this.source_port = binary.BigEndian.Uint16(data[0:2])
	this.dest_port = binary.BigEndian.Uint16(data[2:4])
	this.seq_num = binary.BigEndian.Uint32(data[4:8])
	this.ack_num = binary.BigEndian.Uint32(data[8:12])
	this.dataoffset = uint8(data[12] >> 4)

	this.flags = uint16(((data[12] & 0x01) << 8) | data[13])
	this.window_size = binary.BigEndian.Uint16(data[14:16])
	this.checksum = binary.BigEndian.Uint16(data[16:18])
	this.urgent_ptr = binary.BigEndian.Uint16(data[18:20])

	this.options = this.readOptions(data[20:(this.dataoffset*4)])
	
	return this, uint16(this.dataoffset << 2)
}

func (this tcp_packet)readOptions(data []byte) []string {
	if(len(data) == 0) {
		return []string{}
	}

	if(data[0] == 0) {
		return []string{"END"}
	}


	var oook []string
	read := 1
	if(data[0] == 1) {
		read = 1
		oook = []string{"NOP"}
	}

	if(data[0] == 2 && data[1] == 4) {
		read = 4
		oook = []string{fmt.Sprintf("Max Segment Size: %v", binary.BigEndian.Uint16(data[2:4]))}
	}

	if(data[0] == 3 && data[1] == 3) {
		read = 3
		oook = []string{fmt.Sprintf("Windows scale: %v", uint8(data[3]))}
	}

	if(data[0] == 4 && data[1] == 2) {
		read = 2
		oook = []string{fmt.Sprintf("Selective Acknowledgement permitted")}
	}

	if(data[0] == 5) {
		read = int(data[1])
		oook = []string{fmt.Sprintf("SACK-todo")}
	}

	if(data[0] == 8 && data[1] == 10) {
		read = 4
		oook = []string{fmt.Sprintf("TS and ECHO todo")}
	}
	
	return append(oook, this.readOptions(data[read:])...)
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
		fmt.Sprintf("Data offset (= TCP header size): %d", this.dataoffset << 2),
		fmt.Sprintf("Options: %v", this.options),
	}
}
func (this tcp_packet)set_color(color string) layer {
	this.color = color
	return this
}
func (this tcp_packet)get_color() string {
	return this.color
}
