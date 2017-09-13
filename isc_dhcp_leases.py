#!/usr/bin/python
"""
Parser for dhcpd.lease file
Tested with isc-dhcpd-4.2.2
"""

import sys
from optparse import OptionParser
import re
from datetime import datetime, timedelta


class LeaseError(Exception):
    """
    The exception when encountering an incorrect(unknown) lease entry
    in dhcpd.leases file
    """


def ip_as_int(ip_str):
    """
    The function of converting an ip address to an int

    Args:
        ip_str (str): str object with an ip address
    """

    tokens = ip_str.split('.')

    return (long(tokens[0]) << 24) + (long(tokens[1]) << 16) + \
           (long(tokens[2]) << 8) + long(tokens[3])


def round_timedelta(tdelta):
    """
    The microsecond rounding function for the timedelta object

    Args:
        tdelta (timedelta): timedelta object to be rounded to microseconds
    """

    discard = timedelta(microseconds=tdelta.microseconds)
    result = tdelta - discard

    if discard > timedelta(microseconds=500000):
        result += timedelta(seconds=1)

    return result


def round_datetime(dtime):
    """
    The microsecond rounding function for the datetime object

    Args:
        dtime (datetime): datetime object to be rounded to microseconds
    """

    discard = timedelta(microseconds=dtime.microsecond)
    result = dtime - discard

    if discard > timedelta(microseconds=500000):
        result += timedelta(seconds=1)

    return result


class Lease(object):
    """
    The class describing a single lease record in dhcpd.leases file
    """

    # Regular expresson for an ip address
    REGEX_IP = r"[1-9]\d{0,2}\.\d{1,3}\.\d{1,3}\.\d{1,3}"

    # Regular expression for date and time record in dhcpd.leases file
    REGEX_TIMESTAMP = r"\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}"

    def __init__(self, lease_record):
        """
        Args:
            lease_record (str): single lease record from dhcpd.leases file
        """

        self.lease_record = lease_record

        # For each lease record field, a method is defined for its processing
        lease_structure = {
            'ip':       self.__find_ip,
            'starts':   self.__find_starts,
            'ends':     self.__find_ends,
            'tstp':     self.__find_tstp,
            'tsfp':     self.__find_tsfp,
            'atsfp':    self.__find_atsfp,
            'cltt':     self.__find_cltt,
            'hardware': self.__find_hardware,
            'binding':  self.__find_binding,
            'next':     self.__find_next,
            'rewind':   self.__find_rewind,
            'hostname': self.__find_hostname,
            'uid':      self.__find_uid,
            'set':      self.__find_set,
            'option':   self.__find_option
        }

        # The dictionary containing a lease record structure
        self.lease = {}

        # Search for available fields in a lease record
        for field in lease_structure:
            self.lease[field] = lease_structure[field]()

    def __getitem__(self, key):
        """
        Getting the value of the lease record field

        Args:
            key (str): key for lease record field
        """

        return self.lease[key] if key in self.lease.keys() else None

    def __eq__(self, other):
        """
        Comparison of two records by ip address

        Args:
            other (Lease): another Lease record object
        """

        return True if self['ip'] == other['ip'] else False

    @property
    def static(self):
        """
        The property that determines whether a lease record is static
        """

        # Static recording can be without a ends field
        if self['ends'] is None:
            return True

        # If ends field has a string value it has to be 'never'
        if isinstance(self['ends'], str):
            if self['ends'] == 'never':
                return True
            else:
                raise LeaseError('Wrong value in ends: ' + self['ends'])

        # If the field is present and the value is not equal to 'never'
        # this is not a static record
        return False

    @property
    def active(self):
        """
        The property that determines whether the lease record is active NOW
        """

        now = datetime.utcnow()

        # Static lease always active
        if self.static:
            return True

        # If lease record isn't static, ends field have to be datetime object
        return self['starts'] <= now and self['ends'] > now

    @property
    def abandoned(self):
        """
        The property that determines whether the lease record is abndoned
        """

        return self['binding'] == 'abandoned'

    def __find_ip(self):
        """
        The method of retrieving an ip address from a lease record

        Returns:
            str: ip address string
        """

        # Regular expression for client ip address in lease record
        # lease 172.16.0.1 {
        regex_ip = r"lease\s+(?P<ip>{})\s+{{".format(self.REGEX_IP)

        match = re.search(regex_ip, self.lease_record)

        return match.group('ip') if match else None

    def __find_starts(self):
        """
        The method of retrieving a starts field from a lease record

        Returns:
            datetime: date and time when lease starts
        """

        # Regular expression for starts date and time in lease record
        # starts 2 2013/12/10 12:57:04;
        regex_starts = r"starts\s+[0-6]\s+(?P<starts>{})".format(self.REGEX_TIMESTAMP)

        match = re.search(regex_starts, self.lease_record)

        return datetime.strptime(match.group('starts'), '%Y/%m/%d %H:%M:%S') if match else None

    def __find_ends(self):
        """
        The method of retrieving a ends field from a lease record

        Returns:
            datetime or str: date and time when lease ends, or str 'never'
        """

        # Regular expression for ends date and time in lease record
        # ends 2 2013/12/10 13:07:04;
        regex_ends = r"ends\s+[0-6]\s+(?P<ends>{}|never);".format(self.REGEX_TIMESTAMP)

        match = re.search(regex_ends, self.lease_record)

        if match:
            if match.group('ends') == 'never':
                ends = 'never'
            else:
                ends = datetime.strptime(match.group('ends'), '%Y/%m/%d %H:%M:%S')

            return ends

        # If didn't get ends field
        return None

    def __find_tstp(self):
        """
        The method of retrieving a tstp field from a lease record

        The tstp statement is specified if the failover protocol is being used,
        and indicates what time the peer has been told the lease expires.

        Returns:
            datetime: date and time in tstp field
        """

        # Regular expression for tstp date and time in lease record
        # tstp 2 2013/12/10 13:07:04;
        regex_tstp = r"tstp\s+[0-6]\s+(?P<tstp>{});".format(self.REGEX_TIMESTAMP)

        match = re.search(regex_tstp, self.lease_record)

        return datetime.strptime(match.group('tstp'), '%Y/%m/%d %H:%M:%S') if match else None

    def __find_tsfp(self):
        """
        The method of retrieving a tsfp field in lease record

        The tsfp statement is also specified if the failover protocol is being used,
        and indicates the lease expiry time that the peer has acknowledged.

        Returns:
            datetime: date and time in tsfp field
        """

        # Regular expression for tsfp date and time in lease record
        # tsfp 2 2013/12/10 13:07:04;
        regex_tsfp = r"tsfp\s+[0-6]\s+(?P<tsfp>{});".format(self.REGEX_TIMESTAMP)

        match = re.search(regex_tsfp, self.lease_record)

        return datetime.strptime(match.group('tsfp'), '%Y/%m/%d %H:%M:%S') if match else None

    def __find_atsfp(self):
        """
        The method for retrieving atsfp field in lease record

        The atsfp statement is the actual time sent from the failover partner.

        Returns:
            datetime: date and time in atsfp field
        """

        # Regular expression for atsfp date and time in lease record
        # atsfp 2 2013/12/10 13:07:04;
        regex_atsfp = r"atsfp\s+[0-6]\s+(?P<atsfp>{});".format(self.REGEX_TIMESTAMP)

        match = re.search(regex_atsfp, self.lease_record)

        return datetime.strptime(match.group('atsfp'), '%Y/%m/%d %H:%M:%S') if match else None

    def __find_cltt(self):
        """
        The method for retrieving cltt field in lease record

        The cltt statement is the client's last transaction time.

        Returns:
            datetime: date and time in cltt field
        """

        # Regular expression for cltt date and time in lease record
        # cltt 2 2013/12/10 12:57:04;
        regex_cltt = r"cltt\s+[0-6]\s+(?P<cltt>{});".format(self.REGEX_TIMESTAMP)

        match = re.search(regex_cltt, self.lease_record)

        return datetime.strptime(match.group('cltt'), '%Y/%m/%d %H:%M:%S') if match else None

    def __find_hardware(self):
        """
        The method for retrieving hardware ethernet field in lease record

        Returns:
            str: ethernet hardware address
        """

        # Regulr expression for hardware ethernet address in lease record
        # hardware ethernet 60:a4:4c:b5:6a:dd;
        regex_hardware = (r"hardware\s+ethernet\s+"
                          r"(?P<hardware>([\da-f]{2}:){5}[\da-f]{2});"
                         )

        match = re.search(regex_hardware, self.lease_record, re.IGNORECASE)

        return match.group('hardware') if match else None

    def __find_binding(self):
        """
        The method for retrieving binding state in lease record

        The binding state statement declares the lease's binding state. When the
        DHCP server is not configured to use the failover protocol, a lease's
        binding state will be either active or free. The failover protocol adds
        some additional transitional states, as well as the backup state, which
        indicates that the lease is available for allocation by the failover secondary.

        Returns:
            str: binding state
        """

        # Regular expression for binding state in lease record
        # binding state free;
        regex_binding = r"binding\s+state\s+(?P<binding>\w+);"

        match = re.search(regex_binding, self.lease_record)

        return match.group('binding') if match else None

    def __find_next(self):
        """
        The method for retrieving next binding state in lease record

        The next binding state statement indicates what state the lease will move to when
        the current state expires. The time when the current state expires is specified
        in the ends statement.

        Returns:
            str: next binding state
        """

        # Regular expression for next binding state in
        # next binding state free;
        regex_next = r"next\s+binding\s+state\s+(?P<next>\w+);"

        match = re.search(regex_next, self.lease_record)

        return match.group('next') if match else None

    def __find_rewind(self):
        """
        The method for retrieving rewind binding state in lease record

        This  statement is part of an optimization for use with failover. This
        helps a server rewind a lease to the state most recently transmitted to
        its peer.

        Returns:
            str: rewind binding state
        """

        # Regular expression for rewind binding state in lease record
        # rewind binding state free;
        regex_rewind = r"rewind\s+binding\s+state\s+(?P<rewind>\w+);"

        match = re.search(regex_rewind, self.lease_record)

        return match.group('rewind') if match else None

    def __find_hostname(self):
        """
        The method for retrieving client hostname in lease record

        Returns:
            str: client hostname
        """

        # Regular expression for hostname in lease record
        # client-hostname "arm-1";
        regex_hostname = r'client-hostname\s+"(?P<hostname>[\w\-]+)";'

        match = re.search(regex_hostname, self.lease_record)

        return match.group('hostname') if match else None

    def __find_uid(self):
        """
        The method for retrieving uid in lease record

        Returns:
            str: client uid
        """

        # Regular expression for uid in lease record
        # uid "\001RT\000\314$\272";
        regex_uid = r'uid\s+"(?P<uid>.*)";'

        match = re.search(regex_uid, self.lease_record)

        return match.group('uid') if match else None

    def __find_set(self):
        """
        The method for retrieving sets statements in lease record

        Returns:
            dict: dictionary with set records
        """

        # Regular expression for variable = value in lease record
        # set ddns-rev-name = "151.5.0.10.in-addr.arpa.";
        regex_set = r'set\s+(?P<variable>[\w-]+)\s+=\s+"(?P<value>.+)";'

        sets = {}

        for match in re.finditer(regex_set, self.lease_record):
            variable = match.group('variable')
            value = match.group('value')
            sets[variable] = value

        return sets

    def __find_option(self):
        """
        The method for retrieving option statements in lease record

        Returns:
            dict: dictionary with option records
        """

        # Regular expression for key value in lease record
        # option agent.circuit-id string;
        regex_option = r'option\s+(?P<key>.+)\s+"(?P<value>.+)";'

        options = {}

        for match in re.finditer(regex_option, self.lease_record):
            key = match.group('key')
            value = match.group('value')
            options[key] = value

        return options

class LeaseDatabaseManager(object):
    """
    The class describing dhcpd.leases file for isc dhcpd server. It parses
    dhcpd.leases file and place in memory database with Lease objects
    """

    # Regular expression for one lease record
    REGEX_LEASE_RECORD = re.compile(r"lease .*{[^}]+?\n}")

    def __init__(self, lease_file_path):
        """
        Args:
            lease_file_path (str): path to dhcpd.leases file
        """

        self.leases = []
        self.active_leases = []
        self.abandoned_leases = []

        try:
            lease_file = open(lease_file_path, "r")
        except IOError:
            print("Can't open " + lease_file_path)
            sys.exit(1)
        else:
            with lease_file:
                lease_file_content = lease_file.read()

        for match in self.REGEX_LEASE_RECORD.finditer(lease_file_content):
            lease = Lease(match.group())
            self.leases.append(lease)

    def find_active_leases(self):
        """
        The method for finding active Lease objects in self.leases and put them to
        self.active_leases
        """

        for lease in self.leases:
            if lease.active:

                # If lease already is in self.active_leases - replace it
                # dhcpd.leases(5) - The lease file is a log-structured file -whenever
                # a lease changes, the contents of that lease are written to the end
                # of the file. This means that it is entirely possible and quite
                # reasonable for there to be two or more declarations  of the same
                # lease in the lease file at the same time. In that case, the instance
                # of that particular lease that appears last in the file  is the one
                # that is in effect.
                if lease in self.active_leases:
                    self.active_leases.remove(lease)

                self.active_leases.append(lease)

        # sort self.active_leases by ip address
        self.active_leases.sort(key=lambda l: ip_as_int(l['ip']))

    def find_abandoned_leases(self):
        """
        The method for finding abandoned Lease objects in self.leases[] and put them to
        self.abandoned_leases
        """

        for lease in self.leases:
            if lease.abandoned:
                self.abandoned_leases.append(lease)

        # sort self.abandoned_leases by ip address
        self.abandoned_leases.sort(key=lambda l: ip_as_int(l['ip']))

    def print_active_leases(self, only_static=False):
        """
        The method for printing active leases to stdout
        """

        # Find all active leases in lease database
        self.find_active_leases()

        # Get current time in UTC
        now = datetime.utcnow()

        print('+------------------------------------------------------------------------------')

        # If we want to print only static leases
        if only_static:
            print('| DHCPD STATIC LEASES REPORT')
        else:
            print('| DHCPD ACTIVE LEASES REPORT')

        print('+-----------------+-------------------+----------------------+-----------------')
        print('| IP Address      | MAC Address       | Expires (days,H:M:S) | Client Hostname ')
        print('+-----------------+-------------------+----------------------+-----------------')

        for lease in self.active_leases:

            # If we want to print only static leases and lease isn't static - continue
            if only_static and not lease.static:
                continue

            # Static leases never ends
            ends = 'never' if lease.static else round_timedelta(lease['ends'] - now)

            # Some static leases can be without hardware address in record
            hardware = lease['hardware'] if lease['hardware'] else 'See dhcpd.conf'

            # Some leases can be without hostname
            hostname = lease['hostname'] if lease['hostname'] else ''

            print('| ' + format(lease['ip'], '<15') + ' | ' + \
                   format(hardware, '<17') + ' | ' + \
                   format(str(ends), '>20') + ' | ' + \
                   hostname
                 )

        print('+-----------------+-------------------+----------------------+-----------------')

        # If we want to print only static leases
        if only_static:
            static_leases_num = len([l for l in self.active_leases if l.static])
            print('| Total Static Leases: ' + str(static_leases_num))
        else:
            active_leases_num = len(self.active_leases)
            print('| Total Active Leases: ' + str(active_leases_num))


        print('| Report generated (UTC): ' + str(round_datetime(now)))
        print('+------------------------------------------------------------------------------')

    def print_abandoned_leases(self):
        """
        The method for printing abandoned leases to stdout
        """

        # Find all abandoned leases in lease database
        self.find_abandoned_leases()

        # Get current time in UTC
        now = datetime.utcnow()

        print('+----------------------------------------------------------')
        print('| DHCPD ABANDONED LEASES REPORT')
        print('+-----------------+----------------------+-----------------')
        print('| IP Address      | Starts               | Client Hostname ')
        print('+-----------------+----------------------+-----------------')

        for lease in self.abandoned_leases:
            # Some leases can be without hostname
            hostname = lease['hostname'] if lease['hostname'] else ''

            print('| ' + format(lease['ip'], '<15') + ' | ' + \
                   format(str(lease['starts']), '<20') + ' | ' + \
                   hostname
                 )

        print('+-----------------+----------------------+-----------------')
        print('| Total Abandoned Leases: ' + str(len(self.abandoned_leases)))
        print('| Report generated (UTC): ' + str(round_datetime(now)))
        print('+----------------------------------------------------------')


def main():
    """
    main function
    """
    parser = OptionParser(description="Python script to parse ISC DHCP lease file",
                          prog="leases",
                          usage="%prog [-a | --abandoned] [-s | --static] [filename]"
                         )

    parser.add_option('-a', '--abandoned',
                      help="Show abandoned leases, instead active",
                      action="store_true",
                      default=False
                     )

    parser.add_option('-s', '--static',
                      help="Show only static active leases",
                      action="store_true",
                      default=False
                     )

    options, arguments = parser.parse_args()

    # Same lease can't be static and abandoned
    if options.abandoned and options.static:
        print "Error!!! Found both -a and -s options. Same lease can't be static and abandoned!"
        sys.exit(1)

    if len(arguments) == 1:
        leases_file = arguments[0]
    else:
        leases_file = "/var/lib/dhcp/dhcpd.leases"

    # Parse dhcpd.lease file
    leaseman = LeaseDatabaseManager(leases_file)

    if options.abandoned:
        # Print abandoned leases
        leaseman.print_abandoned_leases()
    else:
        # Print active leases or only static leases
        leaseman.print_active_leases(only_static=options.static)

if __name__ == '__main__':
    main()
