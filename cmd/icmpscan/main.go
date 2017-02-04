package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/jpillora/icmpscan"
	"github.com/jpillora/opts"
)

var VERSION = "0.0.0-src"

func main() {
	c := struct {
		Interface string        `help:"Source interface" default:"chosen by OS"`
		Networks  []string      `type:"args" help:"<networks> is a list of subnets to scan (defaults to all interface subnets)"`
		Timeout   time.Duration `help:"Scan timeout"`
		UseUDP    bool          `help:"Use UDP (auto-enabled for non-root users)"`
		Hostnames bool          `short:"n" help:"Reverse DNS lookup hostnames"`
		DNSServer string        `help:"Server to perform DNS lookup hostnames against (defaults to X.X.X.1)"`
		JSON      bool          `help:"Output results in JSON"`
	}{
		Timeout: 1000 * time.Millisecond,
	}

	opts.New(&c).Name("icmpscan").Version(VERSION).Parse()

	if !c.UseUDP && os.Getuid() != 0 {
		c.UseUDP = true
	}

	hosts, err := icmpscan.Run(icmpscan.Spec{
		Interface: c.Interface,
		Networks:  c.Networks,
		Timeout:   c.Timeout,
		UseUDP:    c.UseUDP,
		Hostnames: c.Hostnames,
		DNSServer: c.DNSServer,
	})
	if err != nil {
		log.Fatal(err)
	}

	if c.JSON {
		e := json.NewEncoder(os.Stdout)
		e.SetIndent("", "  ")
		e.Encode(hosts)
		return
	}

	for i, host := range hosts {
		if host.Active {
			fmt.Printf("[%03d] %15s", i+1, host.IP)
			if host.Hostname != "" {
				fmt.Printf(" %25s", host.Hostname)
			}
			fmt.Printf(" (%s)\n", host.RTT)
		}
	}
}
