// Package cidrlist interacts with a CIDR list suitable for the iptables-manage
// program.
//
// It provides functionality such as adding CIDRs to this file, checking if a
// CIDR is in the file, etc.
//
// Programs that need to update such files should use this package.
package cidrlist

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"syscall"
)

// RecordIP records the IP to the CIDR file.
//
// The format for the IP is a line by itself containing:
// ip/32
//
// We do not write anything to the file if the IP is already present.
func RecordIP(file, ipStr, comment string) error {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return fmt.Errorf("invalid IP: %s", ipStr)
	}

	alreadyRecorded, err := ipIsInFile(file, ip)
	if err != nil {
		return fmt.Errorf("unable to check if IP is in file: %s", err)
	}

	if alreadyRecorded {
		return nil
	}

	fh, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("unable to open: %s: %s", file, err)
	}

	flockt := syscall.Flock_t{
		Type: syscall.F_WRLCK,
	}
	err = syscall.FcntlFlock(fh.Fd(), syscall.F_SETLKW, &flockt)
	if err != nil {
		return fmt.Errorf("unable to lock file: %s: %s", file, err)
	}

	output := fmt.Sprintf("# %s\n%s/32\n", comment, ip)

	sz, err := fh.WriteString(output)
	if err != nil {
		_ = fh.Close()
		return fmt.Errorf("unable to write: %s", err)
	}

	if sz != len(output) {
		_ = fh.Close()
		return fmt.Errorf("short write")
	}

	if err := fh.Close(); err != nil {
		return fmt.Errorf("close failed: %s: %s", file, err)
	}

	return nil
}

// ipIsInFile checks if the IP is listed in the file.
func ipIsInFile(file string, ip net.IP) (bool, error) {
	nets, err := LoadCIDRsFromFile(file)
	if err != nil {
		return false, fmt.Errorf("unable to load CIDRs: %s", err)
	}

	for _, n := range nets {
		if n.Contains(ip) {
			return true, nil
		}
	}

	return false, nil
}

// LoadCIDRsFromFile opens and parse the CIDR file.
//
// We ignore # comments and blank lines.
//
// All other lines must be full CIDRs. We parse them.
func LoadCIDRsFromFile(file string) ([]*net.IPNet, error) {
	fh, err := os.Open(file)
	if err != nil {
		return nil, fmt.Errorf("unable to open file: %s: %s", file, err)
	}

	defer func() {
		err := fh.Close()
		if err != nil {
			log.Printf("close failure: %s: %s", file, err)
		}
	}()

	scanner := bufio.NewScanner(fh)

	var cidrs []*net.IPNet

	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		if line[0] == '#' {
			continue
		}

		_, ipNet, err := net.ParseCIDR(line)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR: %s: %s", line, err)
		}

		cidrs = append(cidrs, ipNet)
	}

	if scanner.Err() != nil {
		return nil, fmt.Errorf("file scan error: %s", scanner.Err())
	}

	return cidrs, nil
}
