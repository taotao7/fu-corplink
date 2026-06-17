module corplink-web

go 1.23.1

require (
	golang.org/x/crypto v0.37.0
	golang.zx2c4.com/wireguard v0.0.0-20231211153847-12269c276173
)

replace golang.zx2c4.com/wireguard => ./third_party/wireguard-go

require (
	github.com/google/btree v1.1.2 // indirect
	github.com/vishvananda/netlink v1.1.1-0.20211118161826-650dca95af54 // indirect
	github.com/vishvananda/netns v0.0.0-20211101163701-50045581ed74 // indirect
	golang.org/x/net v0.39.0 // indirect
	golang.org/x/sys v0.32.0 // indirect
	golang.org/x/time v0.7.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	golang.zx2c4.com/wireguard/windows v0.5.3 // indirect
	gvisor.dev/gvisor v0.0.0-20250503011706-39ed1f5ac29c // indirect
)
