//go:build cgo

package main

import (
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

type pcapInterfaceAddress struct {
	IP      net.IP
	Netmask net.IPMask
}

type pcapInterfaceDev struct {
	Name        string
	Description string
	Addresses   []pcapInterfaceAddress
}

func pcapFindAllDevs() ([]pcapInterfaceDev, error) {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}
	var out []pcapInterfaceDev
	for _, d := range devs {
		var addrs []pcapInterfaceAddress
		for _, a := range d.Addresses {
			addrs = append(addrs, pcapInterfaceAddress{
				IP:      a.IP,
				Netmask: a.Netmask,
			})
		}
		out = append(out, pcapInterfaceDev{
			Name:        d.Name,
			Description: d.Description,
			Addresses:   addrs,
		})
	}
	return out, nil
}

type pcapLiveHandle struct {
	h *pcap.Handle
}

func pcapOpenLive(device string, snaplen int32, promisc bool, timeout time.Duration) (packetHandle, error) {
	h, err := pcap.OpenLive(device, snaplen, promisc, timeout)
	if err != nil {
		return nil, err
	}
	return &pcapLiveHandle{h: h}, nil
}

func (p *pcapLiveHandle) Close() {
	if p.h != nil {
		p.h.Close()
	}
}

func (p *pcapLiveHandle) WritePacketData(data []byte) error {
	return p.h.WritePacketData(data)
}

func (p *pcapLiveHandle) SetBPFFilter(filter string) error {
	return p.h.SetBPFFilter(filter)
}

func (p *pcapLiveHandle) Packets() <-chan gopacket.Packet {
	src := gopacket.NewPacketSource(p.h, p.h.LinkType())
	return src.Packets()
}
