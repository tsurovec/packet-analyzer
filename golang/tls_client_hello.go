package main

import ("fmt";"encoding/binary";"time")

type tls_random struct {
	timestamp uint32
	random []byte // 28
}

func (this *tls_random)load(data []byte) {
	this.timestamp = binary.BigEndian.Uint32(data[0:4])
	copy(this.random, data[4:32])
}

type tls_client_hello struct {
	// header
	protocol_version uint16
	random tls_random

	/*
struct {
          ProtocolVersion client_version;
          Random random;
          SessionID session_id;
          CipherSuite cipher_suites<2..2^16-2>;
          CompressionMethod compression_methods<1..2^8-1>;
          select (extensions_present) {
              case false:
                  struct {};
              case true:
                  Extension extensions<0..2^16-1>;
          };
      } ClientHello;
*/
	
	
	// other
	color string
}

func (this tls_client_hello)load(data []byte) (layer, uint16) {
	//this.timestamp = binary.BigEndian.Uint32(data[0:4])
	this.protocol_version = binary.BigEndian.Uint16(data[0:2])
	this.random = tls_random{}
	this.random.load(data[2:34])
	
	return this, uint16(2+32)//
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
		fmt.Sprintf("Protocol version: %04x", this.protocol_version/*time.Unix(int64(this.timestamp), 0)*/),
		fmt.Sprintf("Random timestamp: %v", time.Unix(int64(this.random.timestamp), 0)),
	}
}
func (this tls_client_hello)set_color(color string) layer {
	this.color = color
	return this
}
func (this tls_client_hello)get_color() string {
	return this.color
}
