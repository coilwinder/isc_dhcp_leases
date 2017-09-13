# isc_dhcp_leases
Small python2 script for reading /var/lib/dhcp/dhcpd.leases from isc-dhcp-server.

## Usage
```
Usage: ./isc_dhcp_leases.py [-a | --abandoned] [-s | --static] [filename]

Options:
  -h, --help       show this help message and exit
  -a, --abandoned  Show abandoned leases, instead active
  -s, --static     Show only static active leases
```
