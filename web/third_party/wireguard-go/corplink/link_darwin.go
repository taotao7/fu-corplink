package corplink

import (
	"fmt"
	"net"
	"os/exec"
	"reflect"
	"syscall"

	"golang.org/x/sys/unix"
)

var ioctlFD int
var interfaceIP net.IP
var interfaceIPv6 net.IP

func loadFD() (err error) {
	if ioctlFD != 0 {
		return nil
	}
	ioctlFD, err = syscall.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	return err
}

func devName(name string) (devName [unix.IFNAMSIZ]byte) {
	copy(devName[:], name)
	return
}

type IfAliasReq struct {
	Name [unix.IFNAMSIZ]byte
	Addr unix.RawSockaddrInet4
}

type IfReq struct {
	Name [unix.IFNAMSIZ]byte
	Flag int
}

func SetInterfaceUp(name string, up bool) error {
	err := loadFD()
	if err != nil {
		return err
	}
	devName := devName(name)
	ifReq := IfReq{
		Name: devName,
	}
	// get flags
	err = unix.IoctlSetInt(ioctlFD, unix.SIOCGIFFLAGS, toInt(&ifReq))
	if err != nil {
		return err
	}
	if up {
		ifReq.Flag |= unix.IFF_UP
	} else {
		ifReq.Flag ^= unix.IFF_UP
	}
	// set up flag
	err = unix.IoctlSetInt(ioctlFD, unix.SIOCSIFFLAGS, toInt(&ifReq))
	return err
}

func SetInterfaceMTU(name string, mtu int) error {
	err := loadFD()
	if err != nil {
		return err
	}
	devName := devName(name)
	err = unix.IoctlSetIfreqMTU(ioctlFD, &unix.IfreqMTU{
		Name: devName,
		MTU:  int32(mtu),
	})
	return err
}

func SetInterfaceAddress(name, addr string) error {
	err := loadFD()
	if err != nil {
		return err
	}
	ip, _, err := net.ParseCIDR(addr)
	if err != nil {
		return err
	}
	devName := devName(name)

	// set addr
	var req IfAliasReq
	if len(ip.To4()) == net.IPv4len {
		interfaceIP = ip
		var realIP [4]byte
		copy(realIP[:], ip.To4())
		req = IfAliasReq{
			Name: devName,
			Addr: unix.RawSockaddrInet4{
				Len:    16,
				Family: unix.AF_INET,
				Addr:   realIP,
			},
		}
	} else {
		// TODO(ManiaciaChao): implement with ioctl
		interfaceIPv6 = ip
		cmd := exec.Command("ifconfig", name, "inet6", addr)
		err = cmd.Run()
		if err != nil {
			return fmt.Errorf("failed to set IPv6 address: %v", err)
		}
		return nil
	}
	err = unix.IoctlSetInt(ioctlFD, unix.SIOCSIFADDR, toInt(&req))
	if err != nil {
		println(err.Error())
		panic(err)
	}
	return nil
}

func toInt(data any) int {
	v := reflect.ValueOf(data)
	return int(v.Pointer())
}

func AddInterfaceRoute(name, network string) error {
	ip, _, err := net.ParseCIDR(network)
	if err != nil {
		return fmt.Errorf("failed to parse network CIDR %q: %v", network, err)
	}

	isIPv4 := ip.To4() != nil
	ifIP := interfaceIPv6
	if isIPv4 {
		ifIP = interfaceIP
	}

	args := []string{
		"add",
		fmt.Sprintf("-inet%s", map[bool]string{true: "", false: "6"}[isIPv4]),
		"-net",
		network,
		ifIP.String(),
	}
	// TODO: replace with native implement like the others
	if output, err := exec.Command("route", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("failed to add route: %v (output: %s)", err, output)
	}
	return nil
}
