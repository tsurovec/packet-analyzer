package main

import ("fmt")

type tls_handshake struct {
	// header
	message_type uint8

	datalen uint32 // actualy 24-bits
	
	// other
	color string
}

func (this tls_handshake)load(data []byte) (layer, uint16) {
	this.message_type = uint8(data[0])
	this.datalen = uint32((data[1] << 16) | (data[2] << 8) | data[3])
	
	return this, uint16(4 /*+ this.datalen*/)
}
func (this tls_handshake)getName() string {
	return "TLS HANDSHAKE"
}
func (this tls_handshake)next_layer_hint() int {
	switch this.message_type {
	case 1:
		return TLS_CLIENT_HELLO
	default:		
		return UNKNOWN
	}
	
}
func (this tls_handshake)get_lines() []string {
	return []string {
		fmt.Sprintf("Message type: %s (%d); Data length: %d",
			this.get_message_string(this.message_type), this.message_type, this.datalen),
	}
}
func (this tls_handshake)set_color(color string) layer {
	this.color = color
	return this
}
func (this tls_handshake)get_color() string {
	return this.color
}
func (this tls_handshake)get_message_string(msg uint8) string {
	switch msg {
	case 0:
		return "Hello Request"
	case 1:
		return "Client Hello"
	case 2:
		return "Server Hello"
	case 4:
		return "New Session Ticket"
	case 14:
		return "Server Hello Done"
	default:
		return "?"

	}
}
