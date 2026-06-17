//go:build !windows

package main

import (
	"golang.zx2c4.com/wireguard/device"
)

func upDeviceForWindows(device *device.Device) int {
	// do nothing, only windows need to up device
	return ExitSetupSuccess
}
