package corplink

import (
	"errors"
	"net/netip"

	"golang.org/x/sys/windows"

	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

func SetInterfaceUp(_ string, _ bool) error {
	// on windows, once the link is created, it is up
	return nil
}

func SetInterfaceMTU(_ string, mtu int) error {
	tryLoadTun()
	luid := winipcfg.LUID(tunDev.LUID())
	ipInterface, err := luid.IPInterface(windows.AF_INET)
	if err != nil {
		return err
	}
	ipInterface.NLMTU = uint32(mtu)
	err = ipInterface.Set()
	if err != nil {
		return err
	}
	return nil
}

func SetInterfaceAddress(_, addr string) error {
	tryLoadTun()
	prefixAddr, err := netip.ParsePrefix(addr)
	if err != nil {
		return err
	}
	address := prefixAddr.Addr()
	tunAddr = &address
	luid := winipcfg.LUID(tunDev.LUID())
	return luid.AddIPAddress(prefixAddr)
}

func AddInterfaceRoute(_, network string) error {
	tryLoadTun()
	dst, err := netip.ParsePrefix(network)
	if err != nil {
		return err
	}
	if tunAddr == nil {
		return errors.New("please set address for interface first")
	}
	luid := winipcfg.LUID(tunDev.LUID())
	return luid.AddRoute(dst, *tunAddr, 1)
}
