package main

import (
	"golang.zx2c4.com/wireguard/device"
)

func upDeviceForWindows(device *device.Device) int {
	logger.Verbosef("Up device")
	err := device.Up()
	if err != nil {
		logger.Errorf("Failed to bring up device: %v", err)
		return ExitSetupFailed
	}
	return ExitSetupSuccess
}
