package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"regexp"
	"time"

	"github.com/jpillora/icmpscan"
	"github.com/jpillora/opts"
)

//VERSION is set at compile time
var VERSION = "0.0.0-src"

func main() {
	c := struct {
		Interface string        `help:"Source interface" default:"chosen by OS"`
		Networks  []string      `mode:"arg" help:"[network] is a subnet to scan (defaults to all interface subnets)"`
		Timeout   time.Duration `help:"Scan timeout"`
		DNSServer string        `help:"Server to perform reverse DNS lookups against (defaults to X.X.X.1)"`
		JSON      bool          `help:"Output results in JSON"`
		Log       bool          `help:"Log actions to stderr"`
	}{
		Timeout: 1000 * time.Millisecond,
	}

	opts.New(&c).Name("icmpscan").Version(VERSION).Parse()

	useUDP := os.Getuid() != 0

	hosts, err := icmpscan.Run(icmpscan.Spec{
		Interface: c.Interface,
		Networks:  c.Networks,
		Timeout:   c.Timeout,
		UseUDP:    useUDP,
		Hostnames: true,
		MACs:      true,
		DNSServer: c.DNSServer,
		Log:       c.Log,
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

	decimals := regexp.MustCompile(`\.\d+`)
	for i, host := range hosts {
		if host.Active {
			if host.MAC == "" {
				host.MAC = "-"
			}
			if host.Hostname == "" {
				host.Hostname = "-"
			}
			rtt := decimals.ReplaceAllString(host.RTT.String(), "")
			fmt.Printf("[%03d] %15s, %6s, %17s, %s\n", i+1, host.IP, rtt, host.MAC, host.Hostname)
		}
	}
}
