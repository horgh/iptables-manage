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
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// Record holds information about a single CIDR list entry.
type Record struct {
	Net     *net.IPNet
	Comment string
}

// RecordIP records the IP to the CIDR file.
//
// The format we write, every time:
// # Comment @ current time\n
// cidr\n
//
// For example:
// # A great IP @ Thu, 21 Jul 2016 22:45:17 PDT
// 192.168.1.32/32
//
// If the IP is already in the file, then we rewrite the file without the IP,
// then add it back (leaving the CIDR as it was in the file) with the given
// comment at the end of the file. This lets us see most recently used IPs at
// the bottom of the file.
//
// Writing a record even if the IP is present also means that if
// iptables-manage is monitoring the file, then it will re-sync the rules even
// if the IP is already allowed. This is useful in case the rules somehow got
// into an inconsistent state (such as through reloading rules from a
// snapshot).
func RecordIP(file, ipStr, comment string, t time.Time) error {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return fmt.Errorf("invalid IP: %s", ipStr)
	}

	lfh, err := lockFile(file)
	if err != nil {
		return fmt.Errorf("unable to lock file: %s: %s", file, err)
	}

	defer func() {
		if err := lfh.Close(); err != nil {
			log.Printf("Error closing lock on file: %s: %s", file, err)
		}
	}()

	// Read in current records.
	records, err := LoadCIDRsFromFile(file)
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("unable to load records: %s", err)
		}
	}

	// Write records out to temporary file. Skip the IP if it is already present.

	// Find directory the file is in so we create the temporary file in the same
	// one. This is because we will rename it after we finish writing to replace
	// the old, and we want it on the same filesystem. Otherwise moving is not
	// atomic. As we have a lock it is not a huge concern if it is not atomic, but
	// we may as well do this.
	dir := filepath.Dir(file)

	fh, err := ioutil.TempFile(dir, "iptables-manage")
	if err != nil {
		return fmt.Errorf("unable to create temporary file: %s", err)
	}

	tempName := fh.Name()

	// Track network that already contains the IP in the file (if any).
	var ipNet *net.IPNet

	for _, rec := range records {
		if rec.Net.Contains(ip) {
			// Raise error if IP is listed in two CIDRs. We need to resolve this. We
			// probably want the broader CIDR, but lets manually fix it for now.
			if ipNet != nil {
				_ = fh.Close()
				_ = os.Remove(tempName)
				return fmt.Errorf("ip is listed twice: %s: %s and %s", ip, ipNet,
					rec.Net)
			}

			ipNet = rec.Net
			continue
		}

		output := fmt.Sprintf("# %s\n%s\n", rec.Comment, rec.Net)

		if err := writeFull(fh, output); err != nil {
			_ = fh.Close()
			_ = os.Remove(tempName)
			return fmt.Errorf("unable to write: %s: %s", tempName, err)
		}
	}

	// Write our IP. Retain the CIDR we found if the IP was already present. If
	// it wasn't, default to the specific IP. (/32 for IPv4, /128 for IPv6).

	output := ""

	if ipNet != nil {
		output = fmt.Sprintf("# %s @ %s\n%s\n", comment, t.Format(time.RFC1123),
			ipNet)
	} else {
		if ipv4IP := ip.To4(); ipv4IP != nil {
			output = fmt.Sprintf("# %s @ %s\n%s/32\n", comment,
				t.Format(time.RFC1123), ip)
		} else {
			output = fmt.Sprintf("# %s @ %s\n%s/128\n", comment,
				t.Format(time.RFC1123), ip)
		}
	}

	if err := writeFull(fh, output); err != nil {
		_ = fh.Close()
		_ = os.Remove(tempName)
		return fmt.Errorf("unable to write: %s: %s", tempName, err)
	}

	if err := fh.Close(); err != nil {
		_ = os.Remove(tempName)
		return fmt.Errorf("close failed: %s: %s", file, err)
	}

	if err := copyFileIDs(file, tempName); err != nil {
		_ = os.Remove(tempName)
		return fmt.Errorf("copying file IDs: %s", err)
	}

	// Move it into place.

	if err := os.Rename(tempName, file); err != nil {
		_ = os.Remove(tempName)
		return fmt.Errorf("unable to replace file: %s to %s: %s", tempName, file,
			err)
	}

	return nil
}

// Acquire a lock on the file. We don't lock the file itself, but instead the
// file with a .lock suffix.
//
// Why not lock the file itself? Consider the case where we want to rewrite the
// file. If we did that, other processes could have the old file open after we
// release the lock:
//
// - P0 opens the file F0
// - P0 acquires lock on F0
// - P1 opens the file F0
// - P1 tries to acquire lock on F0 and waits
// - P0 replaces file F0 with F1 (moving a F1 over to replace F0)
// - P0 relinquishes lock on F0
// - P1 acquires lock on F0. Examines file F0 and does work on it. But it should
//   be looking at F1 now.
//
// If we instead use a lock file then P1 would open F1 after it acquires the
// lock on the lock file, and avoid the above issue.
//
// Note this method currently assumes leaving the .lock file in place, as
// removing it will lead to a similar race on the .lock file itself.
func lockFile(file string) (*os.File, error) {
	lockFilename := fmt.Sprintf("%s.lock", file)

	fh, err := os.OpenFile(lockFilename, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return nil, fmt.Errorf("unable to open: %s: %s", lockFilename, err)
	}

	flockt := syscall.Flock_t{
		Type: syscall.F_WRLCK,
	}
	err = syscall.FcntlFlock(fh.Fd(), syscall.F_SETLKW, &flockt)
	if err != nil {
		_ = fh.Close()
		return nil, fmt.Errorf("unable to lock file: %s: %s", lockFilename, err)
	}

	if err := copyFileIDs(file, lockFilename); err != nil {
		_ = fh.Close()
		return nil, fmt.Errorf("copying file IDs: %s", err)
	}

	return fh, nil
}

func writeFull(fh *os.File, s string) error {
	sz, err := fh.WriteString(s)
	if err != nil {
		return fmt.Errorf("unable to write: %s", err)
	}

	if sz != len(s) {
		return fmt.Errorf("short write")
	}

	return nil
}

// Set the same user ID and group ID on file 2 as is on file 1.
//
// If we rewrite files then the IDs may change. This can prevent access.
func copyFileIDs(src, dest string) error {
	var stat syscall.Stat_t

	if err := syscall.Stat(src, &stat); err != nil {
		return fmt.Errorf("stat: %s", err)
	}

	if err := os.Chown(dest, int(stat.Uid), int(stat.Gid)); err != nil {
		return fmt.Errorf("chown: %s", err)
	}

	return nil
}

// LoadCIDRsFromFile opens and parse the CIDR file.
//
// We ignore # comments and blank lines.
//
// All other lines must be full CIDRs. We parse them.
func LoadCIDRsFromFile(file string) ([]Record, error) {
	fh, err := os.Open(file)
	if err != nil {
		return nil, err
	}

	defer func() {
		if err := fh.Close(); err != nil {
			log.Printf("Failure closing file: %s: %s", file, err)
		}
	}()

	scanner := bufio.NewScanner(fh)

	records := []Record{}
	comment := ""

	for scanner.Scan() {
		line := scanner.Text()

		line = strings.TrimSpace(line)
		if len(line) == 0 {
			continue
		}

		if line[0] == '#' {
			if len(line) > 2 {
				// From "# test" take "test"
				comment = line[2:]
			} else {
				comment = ""
			}
			continue
		}

		_, ipNet, err := net.ParseCIDR(line)
		if err != nil {
			return nil, err
		}

		records = append(records, Record{
			Net:     ipNet,
			Comment: comment,
		})

		comment = ""
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("file scan error: %s", err)
	}

	return records, nil
}
