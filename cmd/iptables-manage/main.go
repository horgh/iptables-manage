package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/user"
	"strconv"
	"strings"

	"github.com/fsnotify/fsnotify"
	iptablesmanage "github.com/horgh/iptables-manage"
)

// Args holds command line arguments.
type Args struct {
	// Path to file holding list of allowed CIDRs.
	CIDRFile string

	// Ports to grant access to.
	Ports []int

	// Verbose controls verbose output.
	Verbose bool

	// Daemonise. If true, then the program sits persistently and watches the
	// given CIDR file for modifications. When the file is modified, we apply
	// the changes immediately.
	Daemonise bool
}

func main() {
	log.SetFlags(0)

	user, err := user.Current()
	if err != nil {
		log.Fatalf("Unable to determine the current user: %s", err)
	}
	if user.Username != "root" {
		log.Fatalf("You must run this program as root. You are %s.", user.Username)
	}

	args, err := getArgs()
	if err != nil {
		log.Printf("Invalid argument: %s", err)
		flag.PrintDefaults()
		os.Exit(1)
	}

	if args.Verbose {
		log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	}

	if err := iptablesmanage.ApplyUpdatesFromCIDRFile(args.CIDRFile, args.Verbose,
		args.Ports); err != nil {
		log.Fatal(err)
	}

	if !args.Daemonise {
		return
	}

	if err := watchCIDRFile(args.CIDRFile, args.Verbose, args.Ports); err != nil {
		log.Fatal(err)
	}
}

// getArgs retrieves and validates command line arguments.
func getArgs() (Args, error) {
	cidrFile := flag.String("cidr-file", "", "File with CIDRs to allow.")
	portsString := flag.String("ports", "80,443",
		"Port(s) to grant access to. Comma separated.")
	verbose := flag.Bool("verbose", false, "Toggle verbose output.")
	daemonise := flag.Bool("daemonise", false,
		"Daemonise and watch the CIDR file for changes. Apply changes when the file changes.")

	flag.Parse()

	if len(*cidrFile) == 0 {
		return Args{}, fmt.Errorf("please provide a CIDR file")
	}

	if len(*portsString) == 0 {
		return Args{}, fmt.Errorf("please provide ports")
	}

	portsRaw := strings.Split(*portsString, ",")
	ports := []int{}
	for _, port := range portsRaw {
		port = strings.TrimSpace(port)
		if len(port) == 0 {
			continue
		}

		portInt, err := strconv.Atoi(port)
		if err != nil {
			return Args{}, fmt.Errorf("invalid port: %s: %s", port, err)
		}

		ports = append(ports, portInt)
	}

	return Args{
		CIDRFile:  *cidrFile,
		Ports:     ports,
		Verbose:   *verbose,
		Daemonise: *daemonise,
	}, nil
}

// watchCIDRFile waits for modification events to the CIDR file. When seen,
// we apply the CIDR file to the iptables rules. This loops forever (or
// until we see an error).
func watchCIDRFile(cidrFile string, verbose bool, ports []int) error {
	watcher, err := watchFile(cidrFile)
	if err != nil {
		return fmt.Errorf("unable to watch file: %s", err)
	}

	for {
		if verbose {
			log.Printf("Waiting for changes...")
		}

		select {
		case ev := <-watcher.Events:
			if verbose {
				log.Printf("Event: %s", ev)
			}

			// File removed. Watch again. We expect the file was replaced.
			if ev.Op == fsnotify.Remove {
				if err := watcher.Close(); err != nil {
					return fmt.Errorf("watcher close error: %s", err)
				}

				watcher, err = watchFile(cidrFile)
				if err != nil {
					return fmt.Errorf("unable to re-watch file: %s", err)
				}

				// Fall through. The file was replaced, so run updates.
			}

			if ev.Op == fsnotify.Write || ev.Op == fsnotify.Remove {
				if err := iptablesmanage.ApplyUpdatesFromCIDRFile(cidrFile, verbose,
					ports); err != nil {
					_ = watcher.Close()
					return fmt.Errorf("unable to apply updates: %s", err)
				}

				log.Printf("Applied updates.")
				continue
			}

		case err := <-watcher.Errors:
			_ = watcher.Close()
			return fmt.Errorf("error watching file: %s: %s", cidrFile, err)
		}
	}
}

// watchFile creates a new Watcher watching the given file.
func watchFile(file string) (*fsnotify.Watcher, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("unable to create file watcher: %s", err)
	}

	if err := watcher.Add(file); err != nil {
		_ = watcher.Close()
		return nil, fmt.Errorf("unable to re-watch file: %s: %s", file, err)
	}

	return watcher, nil
}
