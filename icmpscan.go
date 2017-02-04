package icmpscan

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"math/rand"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jpillora/ipmath"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

const protocolICMP = 1

//Spec defined a given ICMP sweep
type Spec struct {
	Interface string
	Networks  []string
	Timeout   time.Duration
	UseUDP    bool
}

//Host is a ICMP reponder
type Host struct {
	Active bool          `json:"active"`
	Error  string        `json:"error,omitempty"`
	IP     net.IP        `json:"ip"`
	RTT    time.Duration `json:"rtt,omitempty"`
}

//Hosts is a slice of Host
type Hosts []Host

//Sort by IP
func (h Hosts) Len() int      { return len(h) }
func (h Hosts) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h Hosts) Less(i, j int) bool {
	return binary.BigEndian.Uint32([]byte(h[i].IP.To4())) < binary.BigEndian.Uint32([]byte(h[j].IP.To4()))
}

//Run performs an ICMP scan/sweep with the given spec
func Run(s Spec) (Hosts, error) {
	//settings
	timeout := s.Timeout
	if timeout == 0 {
		timeout = 15 * time.Second
	}
	networks := make([]*net.IPNet, len(s.Networks))
	for i, str := range s.Networks {
		ip, net, err := net.ParseCIDR(str)
		if err != nil {
			return nil, err
		}
		if ip.To4() == nil {
			return nil, fmt.Errorf("only ipv4 networks supported (%s)", str)
		}
		networks[i] = net
	}
	//results
	allHosts := Hosts{}
	//check all interfaces
	intfs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	//auto-choose source IP
	srcIP := ""
	if s.Interface != "" {
		for _, intf := range intfs {
			if intf.Name == s.Interface {
				//check all interface addresses
				addrs, err := intf.Addrs()
				if err != nil {
					return nil, err
				}
				for _, addr := range addrs {
					src, _, _ := net.ParseCIDR(addr.String())
					if src.To4() != nil {
						//first ipv4 address on interface
						srcIP = src.String()
						break
					}
				}
				break
			}
		}
	}
	//auto-choose destination networks
	if len(networks) == 0 {
		for _, intf := range intfs {
			name := intf.Name
			//skip loopback
			if name == "lo0" {
				continue
			}
			//dont auto-select tun/taps
			if strings.HasPrefix(name, "tun") ||
				strings.HasPrefix(name, "tap") {
				continue
			}
			//check all interface addresses
			addrs, err := intf.Addrs()
			if err != nil {
				return nil, err
			}
			for _, addr := range addrs {
				src, net, _ := net.ParseCIDR(addr.String())
				if src.To4() == nil {
					continue
				}
				networks = append(networks, net)
			}
		}
	}
	//scan all chosen networks
	for _, network := range networks {
		hosts, err := scanNetwork(s.UseUDP, srcIP, network, timeout)
		if err != nil {
			return nil, err
		}
		allHosts = append(allHosts, hosts...)
	}
	if len(allHosts) >= 2 {
		sort.Sort(&allHosts)
	}
	return allHosts, nil
}

func scanNetwork(udp bool, srcIP string, network *net.IPNet, timeout time.Duration) (Hosts, error) {
	hosts := []Host{}
	rtts := map[int]time.Time{}
	rttsMut := sync.Mutex{}
	//icmp socket
	srcProto := "ip4:icmp"
	if udp {
		srcProto = "udp4"
	}
	conn, err := icmp.ListenPacket(srcProto, srcIP)
	if err != nil {
		return nil, err
	}
	sentCount := 0
	//channel open while reading responses
	recievedAll := make(chan struct{})
	//receive
	readErr := make(chan error)
	go func() {
		for {
			buff := make([]byte, 512)
			n, ra, err := conn.ReadFrom(buff)
			if err != nil {
				readErr <- err
				return
			}
			srcStr := ra.String()
			if udp {
				srcStr = strings.TrimSuffix(srcStr, ":0")
			}
			src := net.ParseIP(srcStr)
			if src == nil {
				log.Printf("source address err: %s", srcStr)
				continue
			}
			b := buff[:n]
			msg, err := icmp.ParseMessage(protocolICMP, b)
			if err != nil {
				log.Printf("msg err: %s", err)
				continue
			}
			reply, ok := msg.Body.(*icmp.Echo)
			if !ok {
				continue
			}
			if !bytes.Equal(ipmath.Hash(src), reply.Data) {
				log.Printf("hash mismatch: %s", src)
				continue
			}
			// switch b := msg.Body.(type) {
			// case *icmp.Echo:
			// case *icmp.DstUnreach:
			//unknown
			// case *icmp.PacketTooBig:
			//unknown
			// default:
			//unknown
			// }
			rttsMut.Lock()
			t0 := rtts[reply.Seq]
			rttsMut.Unlock()

			hosts = append(hosts, Host{
				Active: true,
				IP:     src,
				RTT:    time.Now().Sub(t0),
			})

			//signal all hosts recieved
			if len(hosts) == sentCount {
				close(recievedAll)
			}
		}
	}()
	//loop through all unicast addresses
	//send icmp echo request
	id := rand.Int()
	for curr := network.IP; network.Contains(curr); curr = ipmath.NextIP(curr) {
		if !curr.IsGlobalUnicast() ||
			ipmath.IsNetworkAddress(curr, network) ||
			ipmath.IsBroadcastAddress(curr, network) {
			continue
		}
		//build icmp
		buff, _ := (&icmp.Message{
			Type: ipv4.ICMPTypeEcho,
			Code: 0,
			Body: &icmp.Echo{
				ID:   id,
				Seq:  sentCount,
				Data: ipmath.Hash(curr),
			},
		}).Marshal(nil)
		//write to socket
		var a net.Addr
		if srcProto == "udp4" {
			a = &net.UDPAddr{IP: curr}
		} else {
			a = &net.IPAddr{IP: curr}
		}
		_, err := conn.WriteTo(buff, a)
		if err != nil {
			// log.Printf("send err: %s", err)
			continue
		}
		rttsMut.Lock()
		rtts[sentCount] = time.Now()
		rttsMut.Unlock()
		sentCount++
	}

	select {
	case err := <-readErr:
		return hosts, err
	case <-time.After(timeout):
		return hosts, nil
	case <-recievedAll:
		return hosts, nil
	}
}
