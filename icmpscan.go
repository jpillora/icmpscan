package icmpscan

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

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
	DNSServer string
}

//Host is a ICMP reponder
type Host struct {
	Active   bool          `json:"active"`
	Error    string        `json:"error,omitempty"`
	IP       net.IP        `json:"ip"`
	Hostname string        `json:"hostname,omitempty"`
	RTT      time.Duration `json:"rtt,omitempty"`
	//private fields
	meta struct {
		sync.Mutex
		send    bool
		sendErr error
		sentAt  time.Time
	}
}

//Hosts is a slice of Host
type Hosts []*Host

//Sort by IP
func (h Hosts) Len() int      { return len(h) }
func (h Hosts) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h Hosts) Less(i, j int) bool {
	return binary.BigEndian.Uint32([]byte(h[i].IP.To4())) < binary.BigEndian.Uint32([]byte(h[j].IP.To4()))
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

func (s *scan) run() error {
	//scan all chosen networks
	for _, network := range s.networks {
		s.goNetwork(network)
	}
	if err := s.eg.Wait(); err != nil {
		return err
	}
	sort.Sort(&s.hosts)
	return nil
}

func (s *scan) goNetwork(network *net.IPNet) {
	s.eg.Go(func() error {
		return s.network(network)
	})
}

func (s *scan) network(network *net.IPNet) error {
	//
	// log.Printf("[icmpscan] start: scan network %s", network)
	// defer log.Printf("[icmpscan] end: scan network %s", network)
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
					return
				}
				//parse response
				if err := s.receiveICMP(ip, network, b); err != nil {
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
	h := s.resultHost(ip)
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
			ID:   s.id,
			Seq:  seq,
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
	h := s.resultHost(ip)
	h.meta.Lock()
	h.RTT = time.Now().Sub(h.meta.sentAt)
	defer h.meta.Unlock()
	msg, err := icmp.ParseMessage(protocolICMP, buff)
	if err != nil {
		err = fmt.Errorf("icmp message err: %s", err)
		h.Error = err.Error()
		return err
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
	reply, ok := msg.Body.(*icmp.Echo)
	if !ok {
		err = fmt.Errorf("icmp non-echo response")
		h.Error = err.Error()
		return err
	}
	h.Active = true
	if !bytes.Equal(ipmath.Hash(ip), reply.Data) {
		err = fmt.Errorf("icmpscan hash mismatch: %s", ip)
		h.Error = err.Error()
		return err
	}

	if s.Hostnames {
		server := s.DNSServer
		if server == "" {
			b := make([]byte, 4)
			copy(b, []byte(ip.To4()))
			b[3] = 1
			server = net.IP(b).String()
		}
		m := dns.Msg{}
		ipRev := strings.Split(ip.String(), ".")
		for i, j := 0, len(ipRev)-1; i < j; i, j = i+1, j-1 {
			ipRev[i], ipRev[j] = ipRev[j], ipRev[i]
		}
		target := strings.Join(ipRev, ".") + ".in-addr.arpa."
		m.SetQuestion(target, dns.TypePTR)
		r, _, err := s.dns.Exchange(&m, server+":53")
		if err == nil {
			if len(r.Answer) > 0 {
				p := r.Answer[0].(*dns.PTR)
				h.Hostname = strings.TrimSuffix(p.Ptr, ".")
			}
		}
	}
	return nil
}

func (s *scan) resultHost(ip net.IP) *Host {
	s.resultsMut.Lock()
	defer s.resultsMut.Unlock()
	ipstr := ip.String()
	h, ok := s.results[ipstr]
	if !ok {
		h = &Host{IP: ip}
		s.results[ipstr] = h
		s.hosts = append(s.hosts, h)
	}
	return h
}
