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

## Output
Show current active leases in dhcpd.leases file
```
# ./isc_dhcp_leases.py 
+------------------------------------------------------------------------------
| DHCPD ACTIVE LEASES REPORT
+-----------------+-------------------+----------------------+-----------------
| IP Address      | MAC Address       | Expires (days,H:M:S) | Client Hostname 
+-----------------+-------------------+----------------------+-----------------
| 10.0.5.152      | 8c:dc:d4:7b:92:24 |              0:24:28 | arm-1
| 10.0.5.155      | 52:54:00:cc:24:ba |              0:24:54 | arm-2
+-----------------+-------------------+----------------------+-----------------
| Total Active Leases: 2
| Report generated (UTC): 2017-09-13 10:05:39
+------------------------------------------------------------------------------

```
