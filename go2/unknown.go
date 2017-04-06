package main

type unknown_layer struct {color string}
func (this unknown_layer)load(data []byte) (layer, uint16) {
	return this, uint16(len(data))
}
func (this unknown_layer)getName() string {
	return "UNKNOWN"
}
func (this unknown_layer)get_lines() []string  {
	return []string { "-- no interpretation --" }
}
func (this unknown_layer)next_layer_hint() int {
	return UNKNOWN
}
func (this unknown_layer) set_color(color string) layer {
	this.color = color
	return this
}
func (this unknown_layer)get_color() string {
	return this.color
}
