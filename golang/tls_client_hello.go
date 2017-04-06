package main

import ("fmt";"encoding/binary";"time")

type tls_client_hello struct {
	// header
	timestamp uint32

//	randombytes [28]byte
	
	// other
	color string
}

func (this tls_client_hello)load(data []byte) (layer, uint16) {
	this.timestamp = binary.BigEndian.Uint32(data[0:4])
	
	return this, uint16(32)
}
func (this tls_client_hello)getName() string {
	return "TLS CLIENT HELLO"
}
func (this tls_client_hello)next_layer_hint() int {
	switch 0 {
	default:		
		return UNKNOWN
	}
	
}
func (this tls_client_hello)get_lines() []string {
	return []string {
		fmt.Sprintf("Timestamp: %v", time.Unix(int64(this.timestamp), 0)),
	}
}
func (this tls_client_hello)set_color(color string) layer {
	this.color = color
	return this
}
func (this tls_client_hello)get_color() string {
	return this.color
}
