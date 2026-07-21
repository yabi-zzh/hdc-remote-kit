package model

import "testing"

func TestDeviceSerial(t *testing.T) {
	if got := DeviceSerial("local:4ABVB24A10014201"); got != "4ABVB24A10014201" {
		t.Fatalf("DeviceSerial() = %q", got)
	}
	if got := DeviceSerial("alone"); got != "alone" {
		t.Fatalf("DeviceSerial(alone) = %q", got)
	}
}
