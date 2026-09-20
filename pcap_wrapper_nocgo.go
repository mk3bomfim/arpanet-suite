//go:build !cgo

package main

import (
	"errors"
	"net"
	"time"

	"github.com/google/gopacket"
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
	return nil, errors.New("pcap requires CGO (compiled in pure socket mode)")
}

type noCgoHandle struct{}

func pcapOpenLive(device string, snaplen int32, promisc bool, timeout time.Duration) (packetHandle, error) {
	return nil, errors.New("pcap requires CGO (compiled in pure socket mode)")
}

func (n *noCgoHandle) Close() {}
func (n *noCgoHandle) WritePacketData(data []byte) error { return errors.New("cgo disabled") }
func (n *noCgoHandle) SetBPFFilter(filter string) error { return errors.New("cgo disabled") }
func (n *noCgoHandle) Packets() <-chan gopacket.Packet { return nil }
