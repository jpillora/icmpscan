package icmpscan

import (
	"bytes"
	"fmt"
	"log"
	"math/rand"
	"net"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jpillora/arp"
	"github.com/jpillora/ipmath"
	"github.com/miekg/dns"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/sync/errgroup"
)

const protocolICMP = 1

//Spec defined a given ICMP sweep
type Spec struct {
	Interface string
	Networks  []string
	Timeout   time.Duration
	UseUDP    bool
	Hostnames bool
	MACs      bool
	DNSServer string
	Log       bool
}

//Run performs an ICMP scan/sweep with the given spec
func Run(spec Spec) (Hosts, error) {
	s, err := newScan(spec)
	if err != nil {
		return nil, err
	}
	err = s.run()
	if err != nil {
		return nil, err
	}
	return s.hosts, nil
}

type scan struct {
	Spec
	id          int
	eg          errgroup.Group
	networks    []*net.IPNet
	srcIP       string
	srcProto    string
	sentSuccess uint32
	sentTotal   uint32
	recvSuccess uint32
	resultsMut  sync.Mutex
	results     map[string]*Host
	hostsMut    sync.Mutex
	hosts       Hosts
	dns         dns.Client
}

func newScan(spec Spec) (*scan, error) {
	s := &scan{}
	s.id = rand.Int()
	s.Spec = spec
	s.results = map[string]*Host{}
	//set default timeout
	if s.Timeout == 0 {
		s.Timeout = 15 * time.Second
	}
	s.srcProto = "ip4:icmp"
	if s.UseUDP {
		s.srcProto = "udp4"
	}
	if s.Log {
		log.Printf("[icmpscan] create, id: %d, timeout: %s, protocol: %s", s.id, s.Timeout, s.srcProto)
	}
	//convert string networks to net.networks
	s.networks = make([]*net.IPNet, len(s.Networks))
	hasSubnet := regexp.MustCompile(`\/\d{1,3}$`)
	for i, str := range s.Networks {
		if !hasSubnet.MatchString(str) {
			str += "/32"
		}
		ip, net, err := net.ParseCIDR(str)
		if err != nil {
			return nil, err
		}
		if ip.To4() == nil {
			return nil, fmt.Errorf("only ipv4 networks supported (%s)", str)
		}
		s.networks[i] = net
	}
	//manually choose source IP
	intfs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
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
						s.srcIP = src.String()
						break
					}
				}
				break
			}
		}
	}
	//auto-choose destination networks
	if len(s.networks) == 0 {
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
				if ipmath.NetworkSize(net) > 256 {
					continue
				}
				s.networks = append(s.networks, net)
			}
		}
	}
	return s, nil
}

func (s *scan) getHost(ip net.IP) *Host {
	s.resultsMut.Lock()
	defer s.resultsMut.Unlock()
	ipstr := ip.String()
	h, ok := s.results[ipstr]
	if !ok {
		h = &Host{IP: ip}
		s.results[ipstr] = h
	}
	return h
}

func (s *scan) run() error {
	//scan all chosen networks
	for _, network := range s.networks {
		s.goNetwork(network)
	}
	if err := s.eg.Wait(); err != nil {
		return err
	}
	//include mac addresses where known
	if s.MACs {
		t := arp.Table()
		for _, h := range s.hosts {
			h.MAC = t[h.IP.String()]
		}
	}
	//sort by ip
	sort.Sort(&s.hosts)
	//log
	if s.Log {
		log.Printf("[icmpscan] complete. found #%d hosts", len(s.hosts))
	}
	return nil
}

func (s *scan) goNetwork(network *net.IPNet) {
	s.eg.Go(func() error {
		return s.network(network)
	})
}

func (s *scan) network(network *net.IPNet) error {
	if s.Log {
		log.Printf("[icmpscan] start: scan network %s", network)
		defer log.Printf("[icmpscan] end: scan network %s", network)
	}
	//icmp socket
	conn, err := icmp.ListenPacket(s.srcProto, s.srcIP)
	if err != nil {
		return err
	}
	defer conn.Close()
	//loop through all unicast addresses
	//send icmp echo request
	for curr := network.IP; network.Contains(curr); curr = ipmath.NextIP(curr) {
		if !curr.IsGlobalUnicast() ||
			ipmath.IsNetworkAddress(curr, network) ||
			ipmath.IsBroadcastAddress(curr, network) {
			continue
		}
		//build icmp
		go s.sendICMP(conn, curr)
	}
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
			go func(ra net.Addr, b []byte) {
				ipStr := ra.String()
				if s.UseUDP {
					ipStr = strings.TrimSuffix(ipStr, ":0")
				}
				ip := net.ParseIP(ipStr)
				if ip == nil {
					log.Printf("[icmpscan] invalid ip: %s", ipStr)
					return
				}
				//parse response
				if err := s.receiveICMP(ip, network, b); err != nil {
					if s.Log {
						log.Printf("[icmpscan] icmp error from %s: %s", ipStr, err)
					}
					return
				}
				//signal all hosts recieved
				if atomic.AddUint32(&s.recvSuccess, 1) == s.sentSuccess {
					close(recievedAll)
				}
			}(ra, buff[:n])
		}
	}()
	//wait
	select {
	case <-recievedAll:
		return nil
	case <-time.After(s.Timeout):
		return nil
	case <-readErr:
		return err
	}
}

func (s *scan) sendICMP(conn *icmp.PacketConn, ip net.IP) {
	h := s.getHost(ip)
	//lock/unlock
	h.meta.Lock()
	defer h.meta.Unlock()
	//already sent?
	if h.meta.send {
		return
	}
	h.meta.send = true
	seq := int(atomic.AddUint32(&s.sentTotal, 1))
	//build icmp
	buff, _ := (&icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   s.id, //scan id
			Seq:  seq,  //echo id
			Data: ipmath.Hash(ip),
		},
	}).Marshal(nil)
	//write to socket
	var a net.Addr
	if s.srcProto == "udp4" {
		a = &net.UDPAddr{IP: ip}
	} else {
		a = &net.IPAddr{IP: ip}
	}
	_, err := conn.WriteTo(buff, a)
	if err != nil {
		h.meta.sendErr = err
		return
	}
	h.meta.sentAt = time.Now()
	atomic.AddUint32(&s.sentSuccess, 1)
}

func (s *scan) receiveICMP(ip net.IP, network *net.IPNet, buff []byte) error {
	receivedAt := time.Now()
	//parse icmp buffer
	msg, err := icmp.ParseMessage(protocolICMP, buff)
	if err != nil {
		return fmt.Errorf("icmp message err: %s", err)
	}
	reply, ok := msg.Body.(*icmp.Echo)
	if !ok {
		switch b := msg.Body.(type) {
		case *icmp.DstUnreach:
			dest := ""
			switch msg.Code {
			case 0:
				dest = "network"
			case 1:
				dest = "host"
			case 2:
				dest = "protocol"
			case 3:
				dest = "port"
			case 4:
				dest = "must-fragment"
			default:
				dest = "dest"
			}
			return fmt.Errorf("icmp %s-unreachable", dest)
		case *icmp.PacketTooBig:
			return fmt.Errorf("icmp packet-too-big (mtu %d)", b.MTU)
		default:
			return fmt.Errorf("icmp non-echo response")
		}
	}
	if !bytes.Equal(ipmath.Hash(ip), reply.Data) {
		return fmt.Errorf("icmpscan hash mismatch: %s", ip)
	}
	//echo reply! success
	h := s.getHost(ip)
	h.meta.Lock()
	defer h.meta.Unlock()
	if h.meta.receive {
		return fmt.Errorf("icmp message double receive")
	}
	h.meta.receive = true
	//mark time
	h.Active = true
	h.RTT = receivedAt.Sub(h.meta.sentAt)
	if s.Hostnames {
		name := s.lookupHostname(ip)
		if name != "" {
			h.Hostname = name
		}
	}
	//include in final result
	s.hostsMut.Lock()
	s.hosts = append(s.hosts, h)
	s.hostsMut.Unlock()
	return nil
}
