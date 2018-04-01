// This program synchronizes a whitelist based firewall with IPs found from
// resolving a DNS record.
//
// I want to allow all IPs associated with a given host on a given port.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"time"

	iptablesmanage "github.com/horgh/iptables-manage"
)

func main() {
	// We could check we're running as root, but user.Current() is not
	// implemented on linux/arm apparently. (Try running the program from cron to
	// see the error).

	args, err := getArgs()
	if err != nil {
		log.Fatalf("%s", err)
	}

	ctx := context.Background()

	if args.Verbose {
		log.Printf("Resolving IPs from host %s", args.Host)
	}

	ips, err := getIPs(ctx, args.Host)
	if err != nil {
		log.Fatalf("error resolving hostname: %s", err)
	}

	if len(ips) == 0 {
		log.Fatalf("no IPs found")
	}

	if args.Verbose {
		log.Printf("Found %d IPs:", len(ips))
		for _, ip := range ips {
			log.Printf("%s", ip)
		}
	}

	if err := iptablesmanage.Sync(args.Verbose, ips, args.Ports); err != nil {
		log.Fatalf("error syncing rules: %s", err)
	}
}

// Args are command line arguments.
type Args struct {
	Verbose bool
	Ports   []int
	Host    string
}

func getArgs() (Args, error) {
	verbose := flag.Bool("verbose", false, "Toggle verbose output.")
	portsString := flag.String("ports", "22",
		"Ports to grant access to. Comma separated.")
	host := flag.String("host", "",
		"Hostname to resolve and whitelist its IPs.")

	flag.Parse()

	ports, err := iptablesmanage.CSVToPorts(*portsString)
	if err != nil {
		return Args{}, fmt.Errorf("error parsing ports: %s", err)
	}
	if len(ports) == 0 {
		return Args{}, fmt.Errorf("you must provide a port")
	}

	if *host == "" {
		return Args{}, fmt.Errorf("you must provide a hostname")
	}

	return Args{
		Verbose: *verbose,
		Ports:   ports,
		Host:    *host,
	}, nil
}

func getIPs(ctx context.Context, host string) ([]*net.IPNet, error) {
	resolver := &net.Resolver{
		PreferGo:     true,
		StrictErrors: true,
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	ips, err := resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("error looking up IP: %s", err)
	}

	// Currently I only bother with IPv4
	var ipv4IPs []*net.IPNet
	for _, ip := range ips {
		if ip := ip.IP.To4(); ip == nil {
			continue
		}
		ipv4IPs = append(ipv4IPs, &net.IPNet{
			IP:   ip.IP,
			Mask: net.CIDRMask(32, 32),
		})
	}

	return ipv4IPs, nil
}
