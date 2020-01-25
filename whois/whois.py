# -*- coding: utf-8 -*-

"""
Whois client for python

transliteration of:
http://www.opensource.apple.com/source/adv_cmds/adv_cmds-138.1/whois/whois.c

Copyright (c) 2010 Chris Wolf

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""

from __future__ import print_function
from __future__ import unicode_literals
from __future__ import division
from __future__ import absolute_import
from future import standard_library

import os
import optparse
import socket
import sys
import re
from builtins import object
from builtins import *
standard_library.install_aliases()


class NICClient(object):

    ABUSEHOST = "whois.abuse.net"
    NICHOST = "whois.crsnic.net"
    INICHOST = "whois.networksolutions.com"
    DNICHOST = "whois.nic.mil"
    GNICHOST = "whois.nic.gov"
    ANICHOST = "whois.arin.net"
    LNICHOST = "whois.lacnic.net"
    RNICHOST = "whois.ripe.net"
    PNICHOST = "whois.apnic.net"
    MNICHOST = "whois.ra.net"
    QNICHOST_TAIL = ".whois-servers.net"
    SNICHOST = "whois.6bone.net"
    BNICHOST = "whois.registro.br"
    NORIDHOST = "whois.norid.no"
    IANAHOST = "whois.iana.org"
    PANDIHOST = "whois.pandi.or.id"
    DENICHOST = "de.whois-servers.net"
    AI_HOST = "whois.nic.ai"
    AR_HOST = "whois.nic.ar"
    BY_HOST = "whois.cctld.by"
    HR_HOST = "whois.dns.hr"
    APP_HOST = "whois.nic.google"
    DEV_HOST = "whois.nic.google"
    GAMES_HOST = "whois.nic.games"
    PAGE_HOST = "whois.nic.page"
    CL_HOST = "whois.nic.cl"
    CR_HOST = "whois.nic.cr"
    DE_HOST = "whois.denic.de"
    DK_HOST = "whois.dk-hostmaster.dk"
    DO_HOST = "whois.nic.do"
    CA_HOST = "whois.ca.fury.ca"
    HK_HOST = "whois.hkirc.hk"
    HN_HOST = "whois.nic.hn"
    KZ_HOST = "whois.nic.kz"
    DEFAULT_PORT = "nicname"
    MONEY_HOST = "whois.nic.money"
    JOBS_HOST = "whois.nic.jobs"
    LAT_HOST = "whois.nic.lat"
    LI_HOST = "whois.nic.li"
    MX_HOST = "whois.mx"
    PE_HOST = "kero.yachay.pe"
    ONLINE_HOST = "whois.nic.online"
    IST_HOST = "whois.afilias-srs.net"

    WHOIS_RECURSE = 0x01
    WHOIS_QUICK = 0x02

    ip_whois = [LNICHOST, RNICHOST, PNICHOST, BNICHOST, PANDIHOST]

    def __init__(self):
        self.use_qnichost = False

    def findwhois_server(self, buf, hostname, query):
        """Search the initial TLD lookup results for the regional-specifc
        whois server for getting contact details.
        """
        nhost = None
        match = re.compile('Domain Name: {}\s*.*?Whois Server: (.*?)\s'.format(query), flags=re.IGNORECASE | re.DOTALL).search(buf)
        if match:
            nhost = match.groups()[0]
            # if the whois address is domain.tld/something then
            # s.connect((hostname, 43)) does not work
            if nhost.count('/') > 0:
                nhost = None
        elif hostname == NICClient.ANICHOST:
            for nichost in NICClient.ip_whois:
                if buf.find(nichost) != -1:
                    nhost = nichost
                    break
        return nhost

    def whois(self, query, hostname, flags, many_results=False):
        """Perform initial lookup with TLD whois server
        then, if the quick flag is false, search that result
        for the region-specifc whois server and do a lookup
        there for contact details
        """
        response = b''
        if "SOCKS" in os.environ:
            try:
                import socks
            except ImportError as e:
                print("You need to install the Python socks module. Install PIP (https://bootstrap.pypa.io/get-pip.py) and then 'pip install PySocks'")
                raise e
            socks_user, socks_password = None, None
            if "@" in os.environ["SOCKS"]:
                creds, proxy = os.environ["SOCKS"].split("@")
                socks_user, socks_password = creds.split(":")
            else:
                proxy = os.environ["SOCKS"]
            socksproxy, port = proxy.split(":")
            socks_proto = socket.AF_INET
            if socket.AF_INET6 in [sock[0] for sock in socket.getaddrinfo(socksproxy, port)]:
                socks_proto=socket.AF_INET6
            s = socks.socksocket(socks_proto)
            s.set_proxy(socks.SOCKS5, socksproxy, int(port), True, socks_user, socks_password)
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        try: # socket.connect in a try, in order to allow things like looping whois on different domains without stopping on timeouts: https://stackoverflow.com/questions/25447803/python-socket-connection-exception
            s.connect((hostname, 43))
            try:
                query = query.decode('utf-8')
            except UnicodeEncodeError:
                pass  # Already Unicode (python2's error)
            except AttributeError:
                pass  # Already Unicode (python3's error)

            if hostname == NICClient.DENICHOST:
                query_bytes = "-T dn,ace -C UTF-8 " + query
            elif hostname == NICClient.DK_HOST:
                query_bytes = " --show-handles " + query
            elif hostname.endswith(NICClient.QNICHOST_TAIL) and many_results:
                query_bytes = '=' + query
            else:
                query_bytes = query
            s.send(bytes(query_bytes, 'utf-8') + b"\r\n")
            # recv returns bytes
            while True:
                d = s.recv(4096)
                response += d
                if not d:
                    break
            s.close()

            nhost = None
            response = response.decode('utf-8', 'replace')
            if 'with "=xxx"' in response:
                return self.whois(query, hostname, flags, True)
            if flags & NICClient.WHOIS_RECURSE and nhost is None:
                nhost = self.findwhois_server(response, hostname, query)
            if nhost is not None:
                response += self.whois(query, nhost, 0)
        except socket.error as exc: # 'response' is assigned a value (also a str) even on socket timeout
            print("Error trying to connect to socket: closing socket") 
            s.close()
            response = "Socket not responding"   
        return response

    def choose_server(self, domain):
        """Choose initial lookup NIC host"""
        try:
            domain = domain.encode('idna').decode('utf-8')
        except TypeError:
            domain = domain.decode('utf-8').encode('idna').decode('utf-8')
        except AttributeError:
            domain = domain.decode('utf-8').encode('idna').decode('utf-8')
        if domain.endswith("-NORID"):
            return NICClient.NORIDHOST
        if domain.endswith("id"):
            return NICClient.PANDIHOST
        if domain.endswith("hr"):
            return NICClient.HR_HOST

        domain = domain.split('.')
        if len(domain) < 2:
            return None
        tld = domain[-1]
        if tld[0].isdigit():
            return NICClient.ANICHOST
        elif tld == 'ai':
            return NICClient.AI_HOST
        elif tld == 'app':
            return NICClient.APP_HOST
        elif tld == 'dev':
            return NICClient.DEV_HOST
        elif tld == 'games':
            return NICClient.GAMES_HOST
        elif tld == 'page':
            return NICClient.PAGE_HOST
        elif tld == 'money':
            return NICClient.MONEY_HOST
        elif tld == 'online':
            return NICClient.ONLINE_HOST
        elif tld == 'cl':
            return NICClient.CL_HOST
        elif tld == 'ar':
            return NICClient.AR_HOST
        elif tld == 'by':
            return NICClient.BY_HOST
        elif tld == 'cr':
            return NICClient.CR_HOST
        elif tld == 'ca':
            return NICClient.CA_HOST
        elif tld == 'do':
            return NICClient.DO_HOST
        elif tld == 'de':
            return NICClient.DE_HOST
        elif tld == 'hk':
            return NICClient.HK_HOST
        elif tld == 'hn':
            return NICClient.HN_HOST
        elif tld == 'jobs':
            return NICClient.JOBS_HOST
        elif tld == 'lat':
            return NICClient.LAT_HOST
        elif tld == 'li':
            return NICClient.LI_HOST
        elif tld == 'mx':
            return NICClient.MX_HOST
        elif tld == 'pe':
            return NICClient.PE_HOST
        elif tld == 'ist':
            return NICClient.IST_HOST
        elif tld == 'kz':
            return NICClient.KZ_HOST
        else:
            return tld + NICClient.QNICHOST_TAIL

    def whois_lookup(self, options, query_arg, flags):
        """Main entry point: Perform initial lookup on TLD whois server,
        or other server to get region-specific whois server, then if quick
        flag is false, perform a second lookup on the region-specific
        server for contact records"""
        nichost = None
        # whoud happen when this function is called by other than main
        if options is None:
            options = {}

        if ('whoishost' not in options or options['whoishost'] is None) \
                and ('country' not in options or options['country'] is None):
            self.use_qnichost = True
            options['whoishost'] = NICClient.NICHOST
            if not (flags & NICClient.WHOIS_QUICK):
                flags |= NICClient.WHOIS_RECURSE

        if 'country' in options and options['country'] is not None:
            result = self.whois(
                query_arg,
                options['country'] + NICClient.QNICHOST_TAIL,
                flags
            )
        elif self.use_qnichost:
            nichost = self.choose_server(query_arg)
            if nichost is not None:
                result = self.whois(query_arg, nichost, flags)
            else:
                result = ''
        else:
            result = self.whois(query_arg, options['whoishost'], flags)
        return result


def parse_command_line(argv):
    """Options handling mostly follows the UNIX whois(1) man page, except
    long-form options can also be used.
    """
    flags = 0

    usage = "usage: %prog [options] name"

    parser = optparse.OptionParser(add_help_option=False, usage=usage)
    parser.add_option("-a", "--arin", action="store_const",
                      const=NICClient.ANICHOST, dest="whoishost",
                      help="Lookup using host " + NICClient.ANICHOST)
    parser.add_option("-A", "--apnic", action="store_const",
                      const=NICClient.PNICHOST, dest="whoishost",
                      help="Lookup using host " + NICClient.PNICHOST)
    parser.add_option("-b", "--abuse", action="store_const",
                      const=NICClient.ABUSEHOST, dest="whoishost",
                      help="Lookup using host " + NICClient.ABUSEHOST)
    parser.add_option("-c", "--country", action="store",
                      type="string", dest="country",
                      help="Lookup using country-specific NIC")
    parser.add_option("-d", "--mil", action="store_const",
                      const=NICClient.DNICHOST, dest="whoishost",
                      help="Lookup using host " + NICClient.DNICHOST)
    parser.add_option("-g", "--gov", action="store_const",
                      const=NICClient.GNICHOST, dest="whoishost",
                      help="Lookup using host " + NICClient.GNICHOST)
    parser.add_option("-h", "--host", action="store",
                      type="string", dest="whoishost",
                      help="Lookup using specified whois host")
    parser.add_option("-i", "--nws", action="store_const",
                      const=NICClient.INICHOST, dest="whoishost",
                      help="Lookup using host " + NICClient.INICHOST)
    parser.add_option("-I", "--iana", action="store_const",
                      const=NICClient.IANAHOST, dest="whoishost",
                      help="Lookup using host " + NICClient.IANAHOST)
    parser.add_option("-l", "--lcanic", action="store_const",
                      const=NICClient.LNICHOST, dest="whoishost",
                      help="Lookup using host " + NICClient.LNICHOST)
    parser.add_option("-m", "--ra", action="store_const",
                      const=NICClient.MNICHOST, dest="whoishost",
                      help="Lookup using host " + NICClient.MNICHOST)
    parser.add_option("-p", "--port", action="store",
                      type="int", dest="port",
                      help="Lookup using specified tcp port")
    parser.add_option("-Q", "--quick", action="store_true",
                      dest="b_quicklookup",
                      help="Perform quick lookup")
    parser.add_option("-r", "--ripe", action="store_const",
                      const=NICClient.RNICHOST, dest="whoishost",
                      help="Lookup using host " + NICClient.RNICHOST)
    parser.add_option("-R", "--ru", action="store_const",
                      const="ru", dest="country",
                      help="Lookup Russian NIC")
    parser.add_option("-6", "--6bone", action="store_const",
                      const=NICClient.SNICHOST, dest="whoishost",
                      help="Lookup using host " + NICClient.SNICHOST)
    parser.add_option("-n", "--ina", action="store_const",
                      const=NICClient.PANDIHOST, dest="whoishost",
                      help="Lookup using host " + NICClient.PANDIHOST)
    parser.add_option("-?", "--help", action="help")

    return parser.parse_args(argv)


if __name__ == "__main__":
    flags = 0
    nic_client = NICClient()
    options, args = parse_command_line(sys.argv)
    if options.b_quicklookup:
        flags = flags | NICClient.WHOIS_QUICK
    print(nic_client.whois_lookup(options.__dict__, args[1], flags))
