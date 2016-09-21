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
func RecordIP(file, ip, comment string) error {
	alreadyRecorded, err := ipIsInFile(file, ip)
	if err != nil {
		return fmt.Errorf("Unable to check if IP is in file: %s", err)
	}

	if alreadyRecorded {
		return nil
	}

	fh, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("Unable to open: %s: %s", file, err)
	}

	flockt := syscall.Flock_t{
		Type: syscall.F_WRLCK,
	}
	err = syscall.FcntlFlock(fh.Fd(), syscall.F_SETLKW, &flockt)
	if err != nil {
		return fmt.Errorf("Unable to lock file: %s: %s", file, err)
	}

	defer fh.Close()

	output := fmt.Sprintf("# %s\n%s/32\n", comment, ip)

	sz, err := fh.WriteString(output)
	if err != nil {
		return fmt.Errorf("Unable to write: %s", err)
	}

	if sz != len(output) {
		return fmt.Errorf("Short write")
	}

	return nil
}

// ipIsInFile checks if the IP is in the file.
//
// To be in the file, we say there must be a line like so:
// ip/32
func ipIsInFile(file string, ip string) (bool, error) {
	_, err := os.Lstat(file)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("Unable to stat file: %s", err)
	}

	fh, err := os.Open(file)
	if err != nil {
		return false, fmt.Errorf("Unable to open: %s", err)
	}

	defer fh.Close()

	scanner := bufio.NewScanner(fh)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == ip+"/32" {
			return true, nil
		}
	}

	if scanner.Err() != nil {
		return false, fmt.Errorf("Scanner error: %s", scanner.Err())
	}

	return false, nil
}

// LoadCIDRsFromFile opens and parse the CIDR file.
// We ignore # comments and blank lines.
// Other lines must be full CIDRs. We parse them.
func LoadCIDRsFromFile(file string) ([]*net.IPNet, error) {
	fh, err := os.Open(file)
	if err != nil {
		return nil, fmt.Errorf("Unable to open file: %s: %s", file, err)
	}

	defer fh.Close()

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
			return nil, fmt.Errorf("Invalid CIDR: %s: %s", line, err)
		}

		cidrs = append(cidrs, ipNet)
	}

	if scanner.Err() != nil {
		return nil, fmt.Errorf("File scan error: %s", scanner.Err())
	}

	return cidrs, nil
}
