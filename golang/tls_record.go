package main

import ("fmt";"encoding/binary")

type tls_record struct {
	// header
	content_type uint8
	version uint16
	length uint16

	// other
	color string
}

func (this tls_record)load(data []byte) (layer, uint16) {
	this.content_type = uint8(data[0])
	
	this.version = binary.BigEndian.Uint16(data[1:3])
	this.length = binary.BigEndian.Uint16(data[3:5])
	
	return this, uint16(this.length)
}
func (this tls_record)getName() string {
	return "TLS RECORD"
}
func (this tls_record)next_layer_hint() int {
	return UNKNOWN
}
func (this tls_record)get_lines() []string {
	return []string {
		fmt.Sprintf("Content type: %s (%d, 0x%x); Version: %s (0x%04x); Length: %d",
			this.get_content_string(this.content_type), this.content_type, this.content_type,
			this.get_version_string(this.version), this.version,
		this.length),
	}
}
func (this tls_record)set_color(color string) layer {
	this.color = color
	return this
}
func (this tls_record)get_color() string {
	return this.color
}
func (this tls_record)get_version_string(version uint16) string {
	switch version {
	case 0x300:
		return "SSL 3.0"
	case 0x301:
		return "TLS 1.0"
	case 0x302:
		return "TLS 1.1"
	case 0x303:
		return "TLS 1.2"
	default:
		return "?"

	}
}
func (this tls_record)get_content_string(content uint8) string {
	switch content {
	case 0x14:
		return "ChangecipherSpec"
	case 0x15:
		return "Alert"
	case 0x16:
		return "Handshake"
	case 0x17:
		return "Application"
	case 0x18:
		return "Heartbeat"
	default:
		return "?"

	}
}
