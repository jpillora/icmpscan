package icmpscan

import (
	"encoding/binary"
	"net"
	"sync"
	"time"
)

//Host is a ICMP reponder
type Host struct {
	Active   bool          `json:"active"`
	IP       net.IP        `json:"ip"`
	MAC      string        `json:"mac,omitempty"`
	Hostname string        `json:"hostname,omitempty"`
	RTT      time.Duration `json:"rtt,omitempty"`
	//private fields
	meta struct {
		sync.Mutex
		send    bool
		sendErr error
		sentAt  time.Time
		receive bool
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
