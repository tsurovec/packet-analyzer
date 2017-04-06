package main

import ("fmt";"encoding/binary")

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

	this.total_length = binary.BigEndian.Uint16(data[2:4])
	this.identification = binary.BigEndian.Uint16(data[4:6])
	this.flags_f_offset = binary.BigEndian.Uint16(data[6:8])
	this.ttl = uint8(data[8])
	this.protocol = uint8(data[9])
	this.header_checksum = binary.BigEndian.Uint16(data[10:12])
	this.ip_src = binary.BigEndian.Uint32(data[12:16])
	this.ip_dst = binary.BigEndian.Uint32(data[16:20])
	
	return this, uint16((this.version_ihl & 0xf) << 2)
}
func (this ip_packet)getName() string {
	return "IP"
}
func (this ip_packet)next_layer_hint() int {
	switch this.protocol {
	case 1:
		return ICMP
	case 6:
		return TCP
	case 17:
		return UDP
	default:
		return UNKNOWN
	}
}
func (this ip_packet)get_lines() []string {
	return []string {
		fmt.Sprintf("Version: %d; IHL: %d; DSCP_ECN: %d", this.version_ihl >> 4, this.version_ihl & 0x0f, this.dscp_ecn),
		fmt.Sprintf("Total length: %d; Id: %d", this.total_length, this.identification),
		fmt.Sprintf("FlagFOffset = %d; TTL = %d; Protocol: %d", this.flags_f_offset, this.ttl, this.protocol),
		fmt.Sprintf("Source IP: %s", this.get_ip_string(this.ip_src)),
		fmt.Sprintf("Destination IP: %s", this.get_ip_string(this.ip_dst)),
	}
}
func (this ip_packet)set_color(color string) layer {
	this.color = color
	return this
}
func (this ip_packet)get_color() string {
	return this.color
}
func (this ip_packet)get_ip_string(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",ip >> 24, 0xff&(ip>>16), 0xff&(ip>>8), 0xff&ip)
}
