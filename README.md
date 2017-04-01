iptables-manage is a wrapper to simplify managing iptables rules.

Specifically it simplifies whitelisting a list of IPs to grant access to a
list of ports.

It reads the IPs (as CIDRs) from a file and updates iptables rules to
permit them access to the specified ports. It adds IPs that are not
present, and removes any that are in the rules but no longer in the file.

It can run in two modes:

  1. One-off in which it updates the rules once and exits
  2. Or as a daemon. As a daemon it watches for changes to the IP file and
     updates the rules each time the file changes. I use the daemon to
     dynamically whitelist IPs, such as with
     [sshrecordips](https://github.com/horgh/sshrecordips).


# Rationale
Why? I keep my httpd firewalled from all hosts except those I whitelist.

I want to work on a list of IPs (adding and removing to that list as
necessary) and then sync the rules. Doing this with iptables alone is
tedious, so I built this wrapper.

I expect there are existing tools to do this kind of thing, but given it is
really only one command (`iptables -A`), I prefer to write something simple
myself so I understand what is happening best.
