package corplink

import (
	"github.com/vishvananda/netlink"

	"golang.zx2c4.com/wireguard/common"
)

var linkMap common.SyncMap[string, netlink.Link]

func loadLink(name string) (netlink.Link, error) {
	var err error
	link, ok := linkMap.Load(name)
	if !ok {
		link, err = netlink.LinkByName(name)
		if err != nil {
			return nil, err
		}
	}
	return link, nil
}

func SetInterfaceUp(name string, up bool) error {
	link, err := loadLink(name)
	if err != nil {
		return err
	}
	if up {
		return netlink.LinkSetUp(link)
	}
	return netlink.LinkSetDown(link)
}

func SetInterfaceMTU(name string, mtu int) error {
	link, err := loadLink(name)
	if err != nil {
		return err
	}
	return netlink.LinkSetMTU(link, mtu)
}

func SetInterfaceAddress(name, addr string) error {
	address, err := netlink.ParseAddr(addr)
	if err != nil {
		return err
	}
	link, err := loadLink(name)
	if err != nil {
		return err
	}
	return netlink.AddrAdd(link, address)
}

func AddInterfaceRoute(name, network string) error {
	net, err := netlink.ParseIPNet(network)
	if err != nil {
		return err
	}
	link, err := loadLink(name)
	if err != nil {
		return err
	}
	route := &netlink.Route{
		Dst:       net,
		LinkIndex: link.Attrs().Index,
	}
	return netlink.RouteAdd(route)
}
