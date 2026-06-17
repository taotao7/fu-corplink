package corplink

import (
	"net/netip"

	"golang.zx2c4.com/wireguard/tun"
)

var tunDev *tun.NativeTun
var tunAddr *netip.Addr

func tryLoadTun() {
	if tunDev != nil {
		return
	}
	tunDev = tun.CurrentTun
}
