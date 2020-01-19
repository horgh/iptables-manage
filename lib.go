// Package iptablesmanage provides functionality to interact with iptables
// rules. You can use it to sync rules with CIDR list files.
package iptablesmanage

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/horgh/iptables-manage/cidrlist"
	"github.com/pkg/errors"
)

// IPTablesRule holds an iptables rule.
type IPTablesRule struct {
	// Source CIDR.
	Source *net.IPNet

	// Destination port.
	DestPort int

	// Line number.
	Line int
}

func (i IPTablesRule) String() string {
	return fmt.Sprintf("%s:%d", i.Source, i.DestPort)
}

// ApplyUpdatesFromCIDRFile ensures the iptables rules match what is in the
// CIDR file.
func ApplyUpdatesFromCIDRFile(
	cidrFile string,
	verbose bool,
	ports []int,
) error {
	fileRecords, err := cidrlist.LoadCIDRsFromFile(cidrFile)
	if err != nil {
		return fmt.Errorf("unable to load CIDRs: %s", err)
	}

	var fileCIDRs []*net.IPNet
	for _, r := range fileRecords {
		fileCIDRs = append(fileCIDRs, r.Net)
	}

	return Sync(verbose, fileCIDRs, ports)
}

// Sync takes a list of networks that should be allowed and ensures the
// iptables rules match that.
//
// We remove any rules for CIDRs not in the list and add any CIDRs not in the
// rules that are in the list.
func Sync(
	verbose bool,
	networks []*net.IPNet,
	ports []int,
) error {
	rules, err := getCurrentRules(verbose)
	if err != nil {
		return fmt.Errorf("unable to determine current rules: %s", err)
	}

	if err := removeUnlistedRules(networks, ports, rules, verbose); err != nil {
		return fmt.Errorf(
			"unable to remove rules that are not in the rule file: %s", err)
	}

	if err := addMissingRules(networks, ports, rules, verbose); err != nil {
		return fmt.Errorf("unable to add missing rules: %s", err)
	}

	return nil
}

// getCurrentRules runs iptables -L and collects rules into memory.
//
// At this time it only records ACCEPT and tcp rules. It is rather specific
// for what this program currently manages.
//
// It also records each rule's line number.
func getCurrentRules(verbose bool) ([]IPTablesRule, error) {
	cmd := exec.Command("iptables", "-nL", "INPUT", "--line-numbers")
	output, err := cmd.Output()
	if err != nil {
		return nil, errors.Wrapf(err, "unable to run iptables -nL: %s", output)
	}

	buf := bytes.NewBuffer(output)
	scanner := bufio.NewScanner(buf)

	var rules []IPTablesRule

	for scanner.Scan() {
		pieces := strings.Fields(scanner.Text())
		if len(pieces) != 8 {
			if verbose {
				log.Printf("Ignoring line due to column count %d: %s", len(pieces),
					scanner.Text())
			}
			continue
		}

		num := pieces[0]
		target := pieces[1]
		prot := pieces[2]
		source := pieces[4]
		dpt := pieces[7]

		numInt, err := strconv.Atoi(num)
		if err != nil {
			return nil, errors.Wrap(err, "unable to parse number")
		}

		if target != "ACCEPT" {
			if verbose {
				log.Printf("Ignoring non-ACCEPT rule: %s", scanner.Text())
			}
			continue
		}
		if prot != "tcp" {
			if verbose {
				log.Printf("Ignoring non-tcp rule: %s", scanner.Text())
			}
			continue
		}

		// TODO(horgh): Assumes IPv4
		if strings.Index(source, "/") == -1 {
			source = source + "/32"
		}

		_, ipNet, err := net.ParseCIDR(source)
		if err != nil {
			return nil, errors.Wrapf(err, "unable to parse source as CIDR: %s", source)
		}

		re := regexp.MustCompile(`^dpt:(\d+)$`)
		matches := re.FindStringSubmatch(dpt)
		if matches == nil {
			return nil, errors.Errorf("unexpected dpt value: %s", dpt)
		}

		port, err := strconv.Atoi(matches[1])
		if err != nil {
			return nil, errors.Wrapf(err, "unable to parse port as integer: %s",
				matches[1])
		}

		rules = append(rules, IPTablesRule{
			Source:   ipNet,
			DestPort: port,
			Line:     numInt,
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, errors.Wrap(err, "scan error")
	}

	return rules, nil
}

// removeUnlistedRules compares active iptables rules with those that should
// be there as defined by the CIDR file CIDRs.
//
// We only look at rules matching one of the specified ports.
//
// If there is an iptables rule that is not one of our listed CIDRs, then
// remove the rule.
func removeUnlistedRules(
	cidrs []*net.IPNet,
	ports []int,
	currentRules []IPTablesRule,
	verbose bool,
) error {
	// Track how many rules we remove. This lets us know the real line number
	// as we progress through the rules.
	// Note we assume the rules are in order by line number.
	rulesRemoved := 0

	for _, rule := range currentRules {
		// If it is not a port we are managing, then ignore it.
		if !isPortInList(ports, rule.DestPort) {
			continue
		}

		// If it is an IP we want listed, ignore it since it should be there.
		if isCIDRInList(cidrs, rule.Source) {
			continue
		}

		// This rule is no longer valid. Remove it.

		lineNumber := rule.Line - rulesRemoved
		if err := removeRule(lineNumber); err != nil {
			return fmt.Errorf("unable to remove rule: %v: %s", rule, err)
		}

		log.Printf("Removed unwanted rule: %v", rule)
		rulesRemoved++
	}

	return nil
}

// isPortInList looks through a slice of integers. If there is one that matches
// the port number then we say it is in the list.
func isPortInList(ports []int, port int) bool {
	for _, p := range ports {
		if p == port {
			return true
		}
	}
	return false
}

// isCIDRInList looks through a slice of CIDRs. If the given CIDR matches one,
// then we say it is in the list.
func isCIDRInList(cidrs []*net.IPNet, cidr *net.IPNet) bool {
	// TODO(horgh): We could further optimize this by making a map once.
	for _, c := range cidrs {
		if c.IP.Equal(cidr.IP) && bytes.Equal(c.Mask, cidr.Mask) {
			return true
		}
	}
	return false
}

// removeRule calls iptables -D to remove a rule on the given line number.
func removeRule(lineNumber int) error {
	cmd := exec.Command("iptables", "-D", "INPUT", strconv.Itoa(lineNumber))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("unable to run iptables -D: %s", err)
	}
	return nil
}

// addMissingRules looks at the CIDRs that should have rules.
//
// If there should be a rule for the CIDR and port combination, then we add it.
func addMissingRules(
	cidrs []*net.IPNet,
	ports []int,
	currentRules []IPTablesRule,
	verbose bool,
) error {
	activeRules := map[string]struct{}{}
	for _, r := range currentRules {
		activeRules[r.String()] = struct{}{}
	}

	for _, cidr := range cidrs {
		// If it's IPv6, skip it. Why? Because apparently iptables keeps separate
		// lists for IPv6 IPs and errors if you don't use ip6tables or -6. Since I
		// don't use IPv6 on any hosts I use this program on, I'm not bothering to
		// add support for IPv6. (However, I can get ::1/128 with localhost
		// connections, hence ignoring this being explicit).
		if ip := cidr.IP.To4(); ip == nil {
			continue
		}

		for _, port := range ports {
			// If it's already listed, then do nothing.
			{
				k := fmt.Sprintf("%s:%d", cidr.String(), port)
				if _, exists := activeRules[k]; exists {
					if verbose {
						log.Printf("Rule already exists: %s %d", cidr, port)
					}
					continue
				}
			}

			if err := addRule(verbose, cidr, port); err != nil {
				return errors.WithMessage(err, "unable to add rule")
			}

			log.Printf("Added rule: %s %d", cidr, port)
		}
	}

	return nil
}

// addRule runs iptables -I to add the given CIDR and port tuple.
func addRule(verbose bool, cidr *net.IPNet, port int) error {
	if verbose {
		log.Printf("Trying to add network: %s", cidr)
	}

	cmd := exec.Command(
		"iptables", "-I", "INPUT", "1",
		"-s", cidr.String(),
		"-p", "tcp",
		"-m", "tcp",
		"--dport", strconv.Itoa(port),
		"-j", "ACCEPT",
	)
	if buf, err := cmd.CombinedOutput(); err != nil {
		return errors.Wrapf(err, "unable to run iptables -I: %s", buf)
	}
	return nil
}

// CSVToPorts takes a comma separated string such as "80,443" and returns the
// ports.
func CSVToPorts(s string) ([]int, error) {
	portsRaw := strings.Split(s, ",")
	var ports []int
	for _, port := range portsRaw {
		port = strings.TrimSpace(port)
		if len(port) == 0 {
			continue
		}

		portInt, err := strconv.Atoi(port)
		if err != nil {
			return nil, fmt.Errorf("invalid port: %s: %s", port, err)
		}

		ports = append(ports, portInt)
	}

	return ports, nil
}
