# -*- coding: utf-8 -*-

# parser.py - Module for parsing whois response data
# Copyright (c) 2008 Andrey Petrov
#
# This module is part of pywhois and is released under
# the MIT license: http://www.opensource.org/licenses/mit-license.php

from __future__ import absolute_import
from __future__ import unicode_literals
from __future__ import print_function
from __future__ import division
from future import standard_library

import re
from datetime import datetime
import json
from past.builtins import basestring
from builtins import str
from builtins import *

standard_library.install_aliases()

try:
    import dateutil.parser as dp
    from .time_zones import tz_data
    DATEUTIL = True
except ImportError:
    DATEUTIL = False

EMAIL_REGEX = "[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?"

KNOWN_FORMATS = [
    '%d-%b-%Y',                 # 02-jan-2000
    '%d-%B-%Y',                 # 11-February-2000
    '%d-%m-%Y',                 # 20-10-2000
    '%Y-%m-%d',                 # 2000-01-02
    '%d.%m.%Y',                 # 2.1.2000
    '%Y.%m.%d',                 # 2000.01.02
    '%Y/%m/%d',                 # 2000/01/02
    '%Y%m%d',                   # 20170209
    '%d/%m/%Y',                 # 02/01/2013
    '%Y. %m. %d.',              # 2000. 01. 02.
    '%Y.%m.%d %H:%M:%S',        # 2014.03.08 10:28:24
    '%d-%b-%Y %H:%M:%S %Z',     # 24-Jul-2009 13:20:03 UTC
    '%a %b %d %H:%M:%S %Z %Y',  # Tue Jun 21 23:59:59 GMT 2011
    '%Y-%m-%dT%H:%M:%SZ',       # 2007-01-26T19:10:31Z
    '%Y-%m-%dT%H:%M:%S.%fZ',    # 2018-12-01T16:17:30.568Z
    '%Y-%m-%dT%H:%M:%S%z',      # 2013-12-06T08:17:22-0800
    '%Y-%m-%d %H:%M:%SZ',       # 2000-08-22 18:55:20Z
    '%Y-%m-%d %H:%M:%S',        # 2000-08-22 18:55:20
    '%d %b %Y %H:%M:%S',        # 08 Apr 2013 05:44:00
    '%d/%m/%Y %H:%M:%S',     # 23/04/2015 12:00:07 EEST
    '%d/%m/%Y %H:%M:%S %Z',     # 23/04/2015 12:00:07 EEST
    '%d/%m/%Y %H:%M:%S.%f %Z',  # 23/04/2015 12:00:07.619546 EEST
    '%B %d %Y',                 # August 14 2017
    '%d.%m.%Y %H:%M:%S',        # 08.03.2014 10:28:24
]


class PywhoisError(Exception):
    pass


def datetime_parse(s):
    for known_format in KNOWN_FORMATS:
        try:
            s = datetime.strptime(s, known_format)
            break
        except ValueError as e:
            pass  # Wrong format, keep trying
    return s


def cast_date(s, dayfirst=False, yearfirst=False):
    """Convert any date string found in WHOIS to a datetime object.
    """
    if DATEUTIL:
        try:
            return dp.parse(
                s,
                tzinfos=tz_data,
                dayfirst=dayfirst,
                yearfirst=yearfirst
            ).replace(tzinfo=None)
        except Exception:
            return datetime_parse(s)
    else:
        return datetime_parse(s)


class WhoisEntry(dict):
    """Base class for parsing a Whois entries.
    """
    # regular expressions to extract domain data from whois profile
    # child classes will override this
    _regex = {
        'domain_name':          'Domain Name: *(.+)',
        'registrar':            'Registrar: *(.+)',
        'whois_server':         'Whois Server: *(.+)',
        'referral_url':         'Referral URL: *(.+)',  # http url of whois_server
        'updated_date':         'Updated Date: *(.+)',
        'creation_date':        'Creation Date: *(.+)',
        'expiration_date':      'Expir\w+ Date: *(.+)',
        'name_servers':         'Name Server: *(.+)',  # list of name servers
        'status':               'Status: *(.+)',  # list of statuses
        'emails':               EMAIL_REGEX,  # list of email s
        'dnssec':               'dnssec: *([\S]+)',
        'name':                 'Registrant Name: *(.+)',
        'org':                  'Registrant\s*Organization: *(.+)',
        'address':              'Registrant Street: *(.+)',
        'city':                 'Registrant City: *(.+)',
        'state':                'Registrant State/Province: *(.+)',
        'zipcode':              'Registrant Postal Code: *(.+)',
        'country':              'Registrant Country: *(.+)',
    }
    dayfirst = False
    yearfirst = False

    def __init__(self, domain, text, regex=None):
        if 'This TLD has no whois server, but you can access the whois database at' in text:
            raise PywhoisError(text)
        else:
            self.domain = domain
            self.text = text
            if regex is not None:
                self._regex = regex
            self.parse()

    def parse(self):
        """The first time an attribute is called it will be calculated here.
        The attribute is then set to be accessed directly by subsequent calls.
        """
        for attr, regex in list(self._regex.items()):
            if regex:
                values = []
                for data in re.findall(regex, self.text, re.IGNORECASE | re.M):
                    matches = data if isinstance(data, tuple) else [data]
                    for value in matches:
                        value = self._preprocess(attr, value)
                        if value and value not in values:
                            # avoid duplicates
                            values.append(value)
                if values and attr in ('registrar', 'whois_server', 'referral_url'):
                    values = values[-1]  # ignore junk
                if len(values) == 1:
                    values = values[0]
                elif not values:
                    values = None

                self[attr] = values

    def _preprocess(self, attr, value):
        value = value.strip()
        if value and isinstance(value, basestring) and not value.isdigit() and '_date' in attr:
            # try casting to date format
            value = cast_date(
                value,
                dayfirst=self.dayfirst,
                yearfirst=self.yearfirst)
        return value

    def __setitem__(self, name, value):
        super(WhoisEntry, self).__setitem__(name, value)

    def __getattr__(self, name):
        return self.get(name)

    def __str__(self):
        def handler(e): return str(e)
        return json.dumps(self, indent=2, default=handler)

    def __getstate__(self):
        return self.__dict__

    def __setstate__(self, state):
        self.__dict__ = state

    @staticmethod
    def load(domain, text):
        """Given whois output in ``text``, return an instance of ``WhoisEntry``
        that represents its parsed contents.
        """
        if text.strip() == 'No whois server is known for this kind of object.':
            raise PywhoisError(text)

        if domain.endswith('.com'):
            return WhoisCom(domain, text)
        elif domain.endswith('.net'):
            return WhoisNet(domain, text)
        elif domain.endswith('.org'):
            return WhoisOrg(domain, text)
        elif domain.endswith('.name'):
            return WhoisName(domain, text)
        elif domain.endswith('.me'):
            return WhoisMe(domain, text)
        elif domain.endswith('ae'):
            return WhoisAe(domain, text)
        elif domain.endswith('.au'):
            return WhoisAU(domain, text)
        elif domain.endswith('.ru'):
            return WhoisRu(domain, text)
        elif domain.endswith('.us'):
            return WhoisUs(domain, text)
        elif domain.endswith('.uk'):
            return WhoisUk(domain, text)
        elif domain.endswith('.fr'):
            return WhoisFr(domain, text)
        elif domain.endswith('.nl'):
            return WhoisNl(domain, text)
        elif domain.endswith('.fi'):
            return WhoisFi(domain, text)
        elif domain.endswith('.hr'):
            return WhoisHr(domain, text)
        elif domain.endswith('.hn'):
            return WhoisHn(domain, text)
        elif domain.endswith('.hk'):
            return WhoisHk(domain, text)
        elif domain.endswith('.jp'):
            return WhoisJp(domain, text)
        elif domain.endswith('.pl'):
            return WhoisPl(domain, text)
        elif domain.endswith('.br'):
            return WhoisBr(domain, text)
        elif domain.endswith('.eu'):
            return WhoisEu(domain, text)
        elif domain.endswith('.ee'):
            return WhoisEe(domain, text)
        elif domain.endswith('.kr'):
            return WhoisKr(domain, text)
        elif domain.endswith('.pt'):
            return WhoisPt(domain, text)
        elif domain.endswith('.bg'):
            return WhoisBg(domain, text)
        elif domain.endswith('.de'):
            return WhoisDe(domain, text)
        elif domain.endswith('.at'):
            return WhoisAt(domain, text)
        elif domain.endswith('.ca'):
            return WhoisCa(domain, text)
        elif domain.endswith('.be'):
            return WhoisBe(domain, text)
        elif domain.endswith('.рф'):
            return WhoisRf(domain, text)
        elif domain.endswith('.info'):
            return WhoisInfo(domain, text)
        elif domain.endswith('.su'):
            return WhoisSu(domain, text)
        elif domain.endswith('si'):
            return WhoisSi(domain, text)
        elif domain.endswith('.kg'):
            return WhoisKg(domain, text)
        elif domain.endswith('.io'):
            return WhoisIo(domain, text)
        elif domain.endswith('.biz'):
            return WhoisBiz(domain, text)
        elif domain.endswith('.mobi'):
            return WhoisMobi(domain, text)
        elif domain.endswith('.ch'):
            return WhoisChLi(domain, text)
        elif domain.endswith('.li'):
            return WhoisChLi(domain, text)
        elif domain.endswith('.id'):
            return WhoisID(domain, text)
        elif domain.endswith('.sk'):
            return WhoisSK(domain, text)
        elif domain.endswith('.se'):
            return WhoisSe(domain, text)
        elif domain.endswith('no'):
            return WhoisNo(domain, text)
        elif domain.endswith('.nu'):
            return WhoisSe(domain, text)
        elif domain.endswith('.is'):
            return WhoisIs(domain, text)
        elif domain.endswith('.dk'):
            return WhoisDk(domain, text)
        elif domain.endswith('.it'):
            return WhoisIt(domain, text)
        elif domain.endswith('.mx'):
            return WhoisMx(domain, text)
        elif domain.endswith('.ai'):
            return WhoisAi(domain, text)
        elif domain.endswith('.il'):
            return WhoisIl(domain, text)
        elif domain.endswith('.in'):
            return WhoisIn(domain, text)
        elif domain.endswith('.cat'):
            return WhoisCat(domain, text)
        elif domain.endswith('.ie'):
            return WhoisIe(domain, text)
        elif domain.endswith('.nz'):
            return WhoisNz(domain, text)
        elif domain.endswith('.space'):
            return WhoisSpace(domain, text)
        elif domain.endswith('.lu'):
            return WhoisLu(domain, text)
        elif domain.endswith('.cz'):
            return WhoisCz(domain, text)
        elif domain.endswith('.online'):
            return WhoisOnline(domain, text)
        elif domain.endswith('.cn'):
            return WhoisCn(domain, text)
        elif domain.endswith('.app'):
            return WhoisApp(domain, text)
        elif domain.endswith('.money'):
            return WhoisMoney(domain, text)
        elif domain.endswith('.cl'):
            return WhoisCl(domain, text)
        elif domain.endswith('.ar'):
            return WhoisAr(domain, text)
        elif domain.endswith('.by'):
            return WhoisBy(domain, text)
        elif domain.endswith('.cr'):
            return WhoisCr(domain, text)
        elif domain.endswith('.do'):
            return WhoisDo(domain, text)
        elif domain.endswith('.jobs'):
            return WhoisJobs(domain, text)
        elif domain.endswith('.lat'):
            return WhoisLat(domain, text)
        elif domain.endswith('.pe'):
            return WhoisPe(domain, text)
        elif domain.endswith('.ro'):
            return WhoisRo(domain, text)
        elif domain.endswith('.sa'):
            return WhoisSa(domain, text)
        elif domain.endswith('.tw'):
            return WhoisTw(domain, text)
        elif domain.endswith('.tr'):
            return WhoisTr(domain, text)
        elif domain.endswith('.ve'):
            return WhoisVe(domain, text)
        elif domain.endswith('.ua'):
            return WhoisUA(domain, text)
        elif domain.endswith('.kz'):
            return WhoisKZ(domain, text)
        else:
            return WhoisEntry(domain, text)


class WhoisCl(WhoisEntry):
    """Whois parser for .cl domains."""

    regex = {
        'domain_name': 'Domain name: *(.+)',
        'registrant_name': 'Registrant name: *(.+)',
        'registrant_organization': 'Registrant organisation: *(.+)',
        'registrar': 'registrar name: *(.+)',
        'registrar_url': 'Registrar URL: *(.+)',
        'creation_date': 'Creation date: *(.+)',
        'expiration_date': 'Expiration date: *(.+)',
        'name_servers': 'Name server: *(.+)',  # list of name servers
    }

    def __init__(self, domain, text):
        if 'No match for "' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisPe(WhoisEntry):
    """Whois parser for .pe domains."""

    regex = {
        'domain_name':              'Domain name: *(.+)',
        'status':                   'Domain Status: *(.+)',
        'whois_server':             'WHOIS Server: *(.+)',
        'registrant_name':          'Registrant name: *(.+)',
        'registrar':                'Sponsoring Registrar: *(.+)',
        'admin':                    'Admin Name: *(.+)',
        'admin_email':              'Admin Email: *(.+)',
        'dnssec':                   'DNSSEC: *(.+)',
        'name_servers':             'Name server: *(.+)',  # list of name servers
    }

    def __init__(self, domain, text):
        if 'No match for "' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisSpace(WhoisEntry):
    """Whois parser for .space domains
    """

    def __init__(self, domain, text):
        if 'No match for "' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text)


class WhoisCom(WhoisEntry):
    """Whois parser for .com domains
    """

    def __init__(self, domain, text):
        if 'No match for "' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text)


class WhoisNet(WhoisEntry):
    """Whois parser for .net domains
    """

    def __init__(self, domain, text):
        if 'No match for "' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text)


class WhoisOrg(WhoisEntry):
    """Whois parser for .org domains
    """
    regex = {
        'domain_name':      'Domain Name: *(.+)',
        'registrar':        'Registrar: *(.+)',
        'whois_server':     'Whois Server: *(.+)',  # empty usually
        'referral_url':     'Referral URL: *(.+)',  # http url of whois_server: empty usually
        'updated_date':     'Updated Date: *(.+)',
        'creation_date':    'Creation Date: *(.+)',
        'expiration_date':  'Registry Expiry Date: *(.+)',
        'name_servers':     'Name Server: *(.+)',  # list of name servers
        'status':           'Status: *(.+)',  # list of statuses
        'emails':           EMAIL_REGEX,  # list of email addresses
    }

    def __init__(self, domain, text):
        if text.strip() == 'NOT FOUND':
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text)


class WhoisRo(WhoisEntry):
    """Whois parser for .ro domains
    """
    regex = {
        'domain_name':      'Domain Name: *(.+)',
        'domain_status':    'Domain Status: *(.+)',
        'registrar':        'Registrar: *(.+)',

        'referral_url':     'Referral URL: *(.+)',  # http url of whois_server: empty usually

        'creation_date':    'Registered On: *(.+)',
        'expiration_date':  'Expires On: *(.+)',
        'name_servers':     'Nameserver: *(.+)',  # list of name servers
        'status':           'Status: *(.+)',  # list of statuses
        'dnssec':           'DNSSEC: *(.+)',
    }

    def __init__(self, domain, text):
        if text.strip() == 'NOT FOUND':
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisRu(WhoisEntry):
    """Whois parser for .ru domains
    """
    regex = {
        'domain_name': 'domain: *(.+)',
        'registrar': 'registrar: *(.+)',
        'creation_date': 'created: *(.+)',
        'expiration_date': 'paid-till: *(.+)',
        'updated_date': None,
        'name_servers': 'nserver: *(.+)',  # list of name servers
        'status': 'state: *(.+)',  # list of statuses
        'emails': EMAIL_REGEX,  # list of email addresses
        'org': 'org: *(.+)'
    }

    def __init__(self, domain, text):
        if 'No entries found' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisNl(WhoisEntry):
    """Whois parser for .nl domains
        """
    regex = {
        'domain_name':         'Domain Name: *(.+)',
        'expiration_date':     None,
        'updated_date':        None,
        'creation_date':       None,
        'status':              'Status: *(.+)',  # list of statuses
        'name':                None,
        'registrar':           'Registrar:\s*(.*\n)',
        'registrar_address':   'Registrar:\s*(?:.*\n){1}\s*(.*)',
        'registrar_zip_code':  'Registrar:\s*(?:.*\n){2}\s*(\S*)\s(?:.*)',
        'registrar_city':      'Registrar:\s*(?:.*\n){2}\s*(?:\S*)\s(.*)',
        'registrar_country':   'Registrar:\s*(?:.*\n){3}\s*(.*)',
        'dnssec':              'DNSSEC: *(.+)',
    }

    def __init__(self, domain, text):
        if text.endswith('is free'):
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)

        match = re.compile('Domain nameservers:(.*?)Record maintained by', re.DOTALL).search(text)
        if match:
            duplicate_nameservers_with_ip = [line.strip()
                                             for line in match.groups()[0].strip().splitlines()]
            duplicate_nameservers_without_ip = [nameserver.split(' ')[0]
                                                for nameserver in duplicate_nameservers_with_ip]
            self['name_servers'] = sorted(list(set(duplicate_nameservers_without_ip)))



class WhoisName(WhoisEntry):
    """Whois parser for .name domains
    """
    regex = {
        'domain_name_id':  'Domain Name ID: *(.+)',
        'domain_name':     'Domain Name: *(.+)',
        'registrar_id':    'Sponsoring Registrar ID: *(.+)',
        'registrar':       'Sponsoring Registrar: *(.+)',
        'registrant_id':   'Registrant ID: *(.+)',
        'admin_id':        'Admin ID: *(.+)',
        'technical_id':    'Tech ID: *(.+)',
        'billing_id':      'Billing ID: *(.+)',
        'creation_date':   'Created On: *(.+)',
        'expiration_date': 'Expires On: *(.+)',
        'updated_date':    'Updated On: *(.+)',
        'name_server_ids': 'Name Server ID: *(.+)',  # list of name server ids
        'name_servers':    'Name Server: *(.+)',  # list of name servers
        'status':          'Domain Status: *(.+)',  # list of statuses
    }

    def __init__(self, domain, text):
        if 'No match for ' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisUs(WhoisEntry):
    """Whois parser for .us domains
    """
    regex = {
        'domain_name':                    'Domain Name: *(.+)',
        'domain__id':                     'Domain ID: *(.+)',
        'whois_server':                   'Registrar WHOIS Server: *(.+)',

        'registrar':                      'Registrar: *(.+)',
        'registrar_id':                   'Registrar IANA ID: *(.+)',
        'registrar_url':                  'Registrar URL: *(.+)',
        'registrar_email':                'Registrar Abuse Contact Email: *(.+)',
        'registrar_phone':                'Registrar Abuse Contact Phone: *(.+)',

        'status':                         'Domain Status: *(.+)',  # list of statuses

        'registrant_id':                  'Registry Registrant ID: *(.+)',
        'registrant_name':                'Registrant Name: *(.+)',
        'registrant_organization':        'Registrant Organization: *(.+)',
        'registrant_street':              'Registrant Street: *(.+)',
        'registrant_city':                'Registrant City: *(.+)',
        'registrant_state_province':      'Registrant State/Province: *(.+)',
        'registrant_postal_code':         'Registrant Postal Code: *(.+)',
        'registrant_country':             'Registrant Country: *(.+)',
        'registrant_phone':               'Registrant Phone: *(.+)',
        'registrant_email':               'Registrant Email: *(.+)',
        'registrant_fax':                 'Registrant Fax: *(.+)',
        'registrant_application_purpose': 'Registrant Application Purpose: *(.+)',
        'registrant_nexus_category':      'Registrant Nexus Category: *(.+)',

        'admin_id':                       'Registry Admin ID: *(.+)',
        'admin':                          'Admin Name: *(.+)',
        'admin_organization':             'Admin Organization: *(.+)',
        'admin_street':                   'Admin Street: *(.+)',
        'admin_city':                     'Admin City: *(.+)',
        'admin_state_province':           'Admin State/Province: *(.+)',
        'admin_postal_code':              'Admin Postal Code: *(.+)',
        'admin_country':                  'Admin Country: *(.+)',
        'admin_phone':                    'Admin Phone: *(.+)',
        'admin_email':                    'Admin Email: *(.+)',
        'admin_fax':                      'Admin Fax: *(.+)',
        'admin_application_purpose':      'Admin Application Purpose: *(.+)',
        'admin_nexus_category':           'Admin Nexus Category: *(.+)',

        'tech_id':                        'Registry Tech ID: *(.+)',
        'tech_name':                      'Tech Name: *(.+)',
        'tech_organization':              'Tech Organization: *(.+)',
        'tech_street':                    'Tech Street: *(.+)',
        'tech_city':                      'Tech City: *(.+)',
        'tech_state_province':            'Tech State/Province: *(.+)',
        'tech_postal_code':               'Tech Postal Code: *(.+)',
        'tech_country':                   'Tech Country: *(.+)',
        'tech_phone':                     'Tech Phone: *(.+)',
        'tech_email':                     'Tech Email: *(.+)',
        'tech_fax':                       'Tech Fax: *(.+)',
        'tech_application_purpose':       'Tech Application Purpose: *(.+)',
        'tech_nexus_category':            'Tech Nexus Category: *(.+)',

        'name_servers':                   'Name Server: *(.+)',  # list of name servers

        'creation_date':                  'Creation Date: *(.+)',
        'expiration_date':                'Registry Expiry Date: *(.+)',
        'updated_date':                   'Updated Date: *(.+)',
    }

    def __init__(self, domain, text):
        if 'Not found:' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisPl(WhoisEntry):
    """Whois parser for .pl domains
    """
    regex = {
        'domain_name':                    'DOMAIN NAME: *(.+)\n',
        'name_servers':                   'nameservers:((?:\s+.+\n+)*)',
        'registrar':                      'REGISTRAR:\s*(.+)',
        'registrar_url':                  'URL: *(.+)',        # not available
        'status':                         'Registration status:\n\s*(.+)',  # not available
        'registrant_name':                'Registrant:\n\s*(.+)',   # not available
        'creation_date':                  '(?<! )created: *(.+)\n',
        'expiration_date':                'renewal date: *(.+)',
        'updated_date':                   'last modified: *(.+)\n',
    }

    def __init__(self, domain, text):
        if 'No information available about domain name' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisCa(WhoisEntry):
    """Whois parser for .ca domains
    """
    regex = {
        'domain_name':                    'Domain name: *(.+)',
        'whois_server':                   'Registrar WHOIS Server: *(.+)',
        'registrar':                      'Registrar: *(.+)',
        'registrar_url':                  'Registrar URL: *(.+)',
        'registrant_name':                'Registrant Name: *(.+)',
        'registrant_number':              'Registry Registrant ID: *(.+)',
        'admin_name':                     'Admin Name: *(.+)',
        'domain_status':                  'Domain status: *(.+)',
        'emails':                         'Email: *(.+)',
        'updated_date':                   'Updated Date: *(.+)',
        'creation_date':                  'Creation Date: *(.+)',
        'expiration_date':                'Expiry Date: *(.+)',
        'phone':                          'Phone: *(.+)',
        'fax':                            'Fax: *(.+)',
        'dnssec':                         'dnssec: *([\S]+)'
    }

    def __init__(self, domain, text):
        if 'Domain status:         available' in text or 'Not found:' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisMe(WhoisEntry):
    """Whois parser for .me domains
    """
    regex = {
        'domain_id':                   'Registry Domain ID:(.+)',
        'domain_name':                 'Domain Name:(.+)',
        'creation_date':               'Creation Date:(.+)',
        'updated_date':                'Updated Date:(.+)',
        'expiration_date':             'Registry Expiry Date: (.+)',
        'registrar':                   'Registrar:(.+)',
        'status':                      'Domain Status:(.+)',  # list of statuses
        'registrant_id':               'Registrant ID:(.+)',
        'registrant_name':             'Registrant Name:(.+)',
        'registrant_org':              'Registrant Organization:(.+)',
        'registrant_address':          'Registrant Address:(.+)',
        'registrant_address2':         'Registrant Address2:(.+)',
        'registrant_address3':         'Registrant Address3:(.+)',
        'registrant_city':             'Registrant City:(.+)',
        'registrant_state_province':   'Registrant State/Province:(.+)',
        'registrant_country':          'Registrant Country/Economy:(.+)',
        'registrant_postal_code':      'Registrant Postal Code:(.+)',
        'registrant_phone':            'Registrant Phone:(.+)',
        'registrant_phone_ext':        'Registrant Phone Ext\.:(.+)',
        'registrant_fax':              'Registrant FAX:(.+)',
        'registrant_fax_ext':          'Registrant FAX Ext\.:(.+)',
        'registrant_email':            'Registrant E-mail:(.+)',
        'admin_id':                    'Admin ID:(.+)',
        'admin_name':                  'Admin Name:(.+)',
        'admin_org':                   'Admin Organization:(.+)',
        'admin_address':               'Admin Address:(.+)',
        'admin_address2':              'Admin Address2:(.+)',
        'admin_address3':              'Admin Address3:(.+)',
        'admin_city':                  'Admin City:(.+)',
        'admin_state_province':        'Admin State/Province:(.+)',
        'admin_country':               'Admin Country/Economy:(.+)',
        'admin_postal_code':           'Admin Postal Code:(.+)',
        'admin_phone':                 'Admin Phone:(.+)',
        'admin_phone_ext':             'Admin Phone Ext\.:(.+)',
        'admin_fax':                   'Admin FAX:(.+)',
        'admin_fax_ext':               'Admin FAX Ext\.:(.+)',
        'admin_email':                 'Admin E-mail:(.+)',
        'tech_id':                     'Tech ID:(.+)',
        'tech_name':                   'Tech Name:(.+)',
        'tech_org':                    'Tech Organization:(.+)',
        'tech_address':                'Tech Address:(.+)',
        'tech_address2':               'Tech Address2:(.+)',
        'tech_address3':               'Tech Address3:(.+)',
        'tech_city':                   'Tech City:(.+)',
        'tech_state_province':         'Tech State/Province:(.+)',
        'tech_country':                'Tech Country/Economy:(.+)',
        'tech_postal_code':            'Tech Postal Code:(.+)',
        'tech_phone':                  'Tech Phone:(.+)',
        'tech_phone_ext':              'Tech Phone Ext\.:(.+)',
        'tech_fax':                    'Tech FAX:(.+)',
        'tech_fax_ext':                'Tech FAX Ext\.:(.+)',
        'tech_email':                  'Tech E-mail:(.+)',
        'name_servers':                'Nameservers:(.+)',  # list of name servers
    }

    def __init__(self, domain, text):
        if 'NOT FOUND' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisUk(WhoisEntry):
    """Whois parser for .uk domains
    """
    regex = {
        'domain_name':                    'Domain name:\s*(.+)',

        'registrar':                      'Registrar:\s*(.+)',
        'registrar_url':                  'URL:\s*(.+)',

        'status':                         'Registration status:\s*(.+)',  # list of statuses

        'registrant_name':                'Registrant:\s*(.+)',
        'registrant_type':                'Registrant type:\s*(.+)',
        'registrant_street':              'Registrant\'s address:\s*(?:.*\n){2}\s+(.*)',
        'registrant_city':                'Registrant\'s address:\s*(?:.*\n){3}\s+(.*)',
        'registrant_country':             'Registrant\'s address:\s*(?:.*\n){5}\s+(.*)',

        'creation_date':                  'Registered on:\s*(.+)',
        'expiration_date':                'Expiry date:\s*(.+)',
        'updated_date':                   'Last updated:\s*(.+)',

        'name_servers':                   'Name servers:\s*(.+)',
    }

    def __init__(self, domain, text):
        if 'No match for ' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisFr(WhoisEntry):
    """Whois parser for .fr domains
    """
    regex = {
        'domain_name': 'domain: *(.+)',
        'registrar': 'registrar: *(.+)',
        'creation_date': 'created: *(.+)',
        'expiration_date': 'Expir\w+ Date:\s?(.+)',
        'name_servers': 'nserver: *(.+)',  # list of name servers
        'status': 'status: *(.+)',  # list of statuses
        'emails': EMAIL_REGEX,  # list of email addresses
        'updated_date': 'last-update: *(.+)',
    }

    def __init__(self, domain, text):
        if 'No entries found' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisFi(WhoisEntry):
    """Whois parser for .fi domains
    """
    regex = {
        'domain_name':                    'domain\.*: *([\S]+)',
        'name':                           'Holder\s*name\.*:([\S\ ]+)',
        'address':                        '[Holder\w\W]address\.*: ([\S\ ]+)',
        'phone':                          'Holder[\s\w\W]+phone\.*: ([\S]+)',
        'email':                          'holder email\.*: *([\S\ ]+)',
        'status':                         'status\.*: *([\S]+)',  # list of statuses
        'creation_date':                  'created\.*: *([\S]+)',
        'updated_date':                   'modified\.*: *([\S]+)',
        'expiration_date':                'expires\.*: *([\S]+)',
        'name_servers':                   'nserver\.*: *([\S]+) \[\S+\]',  # list of name servers
        'name_server_statuses':           'nserver\.*: *([\S]+ \[\S+\])',  # list of name servers and statuses
        'dnssec':                         'dnssec\.*: *([\S]+)',
        'registrar':                      'Registrar\s*registrar\.*: *([\S]+)',
        'registrar_site':                 'Registrar[\s\w\W]+www\.*: *([\S]+)'

    }

    def __init__(self, domain, text):
        if 'Domain not ' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisJp(WhoisEntry):
    """Whois parser for .jp domains
    """
    regex = {
        'domain_name': 'a\. \[Domain Name\]\s*(.+)',
        'registrant_org': 'g\. \[Organization\](.+)',
        'creation_date': r'\[Registered Date\]\s*(.+)',
        'name_servers': 'p\. \[Name Server\]\s*(.+)',  # list of name servers
        'updated_date':  '\[Last Update\]\s?(.+)',
        'status': '\[State\]\s*(.+)',  # list of statuses
    }

    def __init__(self, domain, text):
        if 'No match!!' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisAU(WhoisEntry):
    """Whois parser for .au domains
    """
    regex = {
        'domain_name':                    'Domain Name: *(.+)\n',
        'updated_date':                  'Last Modified: *(.+)\n',
        'registrar':                      'Registrar Name: *(.+)\n',
        'status':                         'Status: *(.+)',
        'registrant_name':                'Registrant: *(.+)',
        'registrant_contact_name':        'Registrant Contact Name: (.+)',
        'name_servers':                   'Name Server: *(.+)',
    }

    def __init__(self, domain, text):
        if text.strip() == 'No Data Found':
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisEu(WhoisEntry):
    """Whois parser for .eu domains
    """
    regex = {
        'domain_name': r'Domain: *([^\n\r]+)',
        'tech_name': r'Technical: *Name: *([^\n\r]+)',
        'tech_org': r'Technical: *Name: *[^\n\r]+\s*Organisation: *([^\n\r]+)',
        'tech_phone': r'Technical: *Name: *[^\n\r]+\s*Organisation: *[^\n\r]+\s*Language: *[^\n\r]+\s*Phone: *([^\n\r]+)',
        'tech_fax': r'Technical: *Name: *[^\n\r]+\s*Organisation: *[^\n\r]+\s*Language: *[^\n\r]+\s*Phone: *[^\n\r]+\s*Fax: *([^\n\r]+)',
        'tech_email': r'Technical: *Name: *[^\n\r]+\s*Organisation: *[^\n\r]+\s*Language: *[^\n\r]+\s*Phone: *[^\n\r]+\s*Fax: *[^\n\r]+\s*Email: *([^\n\r]+)',
        'registrar': r'Registrar: *Name: *([^\n\r]+)',
        'name_servers': r'Name servers:\s*(.+)',  # list of name servers
    }

    def __init__(self, domain, text):
        if text.strip() == 'Status: AVAILABLE':
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisEe(WhoisEntry):
    """Whois parser for .ee domains
    """
    regex = {
        'domain_name': r'Domain: *[\n\r]+\s*name: *([^\n\r]+)',
        'status': r'Domain: *[\n\r]+\s*name: *[^\n\r]+\sstatus: *([^\n\r]+)',
        'creation_date': r'Domain: *[\n\r]+\s*name: *[^\n\r]+\sstatus: *[^\n\r]+\sregistered: *([^\n\r]+)',
        'updated_date': r'Domain: *[\n\r]+\s*name: *[^\n\r]+\sstatus: *[^\n\r]+\sregistered: *[^\n\r]+\schanged: *([^\n\r]+)',
        'expiration_date': r'Domain: *[\n\r]+\s*name: *[^\n\r]+\sstatus: *[^\n\r]+\sregistered: *[^\n\r]+\schanged: *[^\n\r]+\sexpire: *([^\n\r]+)',

        # 'tech_name': r'Technical: *Name: *([^\n\r]+)',
        # 'tech_org': r'Technical: *Name: *[^\n\r]+\s*Organisation: *([^\n\r]+)',
        # 'tech_phone': r'Technical: *Name: *[^\n\r]+\s*Organisation: *[^\n\r]+\s*Language: *[^\n\r]+\s*Phone: *([^\n\r]+)',
        # 'tech_fax': r'Technical: *Name: *[^\n\r]+\s*Organisation: *[^\n\r]+\s*Language: *[^\n\r]+\s*Phone: *[^\n\r]+\s*Fax: *([^\n\r]+)',
        # 'tech_email': r'Technical: *Name: *[^\n\r]+\s*Organisation: *[^\n\r]+\s*Language: *[^\n\r]+\s*Phone: *[^\n\r]+\s*Fax: *[^\n\r]+\s*Email: *([^\n\r]+)',
        'registrar': r'Registrar: *[\n\r]+\s*name: *([^\n\r]+)',
        'name_servers': r'nserver: *(.*)',  # list of name servers
    }

    def __init__(self, domain, text):
        if text.strip() == 'Domain not found':
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisBr(WhoisEntry):
    """Whois parser for .br domains
    """
    regex = {
        'domain_name':                    'domain: *(.+)\n',
        'registrant_name':               'owner: *([\S ]+)',
        'registrant_id':                 'ownerid: *(.+)',
        'country':                       'country: *(.+)',
        'owner_c':                       'owner-c: *(.+)',
        'admin_c':                       'admin-c: *(.+)',
        'tech_c':                        'tech-c: *(.+)',
        'billing_c':                     'billing-c: *(.+)',
        'name_server':                   'nserver: *(.+)',
        'nsstat':                        'nsstat: *(.+)',
        'nslastaa':                      'nslastaa: *(.+)',
        'saci':                          'saci: *(.+)',
        'creation_date':                 'created: *(.+)',
        'updated_date':                  'changed: *(.+)',
        'expiration_date':               'expires: *(.+)',
        'status':                        'status: *(.+)',
        'nic_hdl_br':                    'nic-hdl-br: *(.+)',
        'person':                        'person: *([\S ]+)',
        'email':                         'e-mail: *(.+)',
    }

    def __init__(self, domain, text):

        if 'Not found:' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)

    def _preprocess(self, attr, value):
        value = value.strip()
        if value and isinstance(value, basestring) and '_date' in attr:
            # try casting to date format
            value = re.findall(r"[\w\s:.-\\/]+", value)[0].strip()
            value = cast_date(
                value,
                dayfirst=self.dayfirst,
                yearfirst=self.yearfirst)
        return value
        

class WhoisKr(WhoisEntry):
    """Whois parser for .kr domains
    """
    regex = {
        'domain_name': 'Domain Name\s*: *(.+)',
        'registrant_name': 'Registrant\s*: *(.+)',
        'registrant_address': 'Registrant Address\s*: *(.+)',
        'registrant_zip': 'Registrant Zip Code\s*: *(.+)',
        'admin_name': 'Administrative Contact\(AC\)\s*: *(.+)',
        'admin_email': 'AC E-Mail\s*: *(.+)',
        'admin_phone': 'AC Phone Number\s*: *(.+)',
        'creation_date': 'Registered Date\s*: *(.+)',
        'updated_date':  'Last updated Date\s*: *(.+)',
        'expiration_date':  'Expiration Date\s*: *(.+)',
        'registrar':  'Authorized Agency\s*: *(.+)',
        'name_servers': 'Host Name\s*: *(.+)',  # list of name servers
    }

    def __init__(self, domain, text):
        if text.endswith(' no match'):
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisPt(WhoisEntry):
    """Whois parser for .pt domains
    """
    regex = {
        'domain_name': 'Domain: *(.+)',
        'creation_date': 'Creation Date: *(.+)',
        'expiration_date': 'Expiration Date: *(.+)',
        'registrant_name': 'Owner Name: *(.+)',
        'registrant_street': 'Owner Address: *(.+)',
        'registrant_city': 'Owner Locality: *(.+)',
        'registrant_postal_code': 'Owner ZipCode: *(.+)',
        'registrant_email': 'Owner Email: *(.+)',
        'admin': 'Admin Name: *(.+)',
        'admin_street': 'Admin Address: *(.+)',
        'admin_city': 'Admin Locality: *(.+)',
        'admin_postal_code':'Admin ZipCode: *(.+)',
        'admin_email': 'Admin Email: *(.+)',
        'name_servers': 'Name Server: *(.+) \|',  # list of name servers
        'status': 'Domain Status: *(.+)',  # list of statuses
        'emails': EMAIL_REGEX,  # list of email addresses
    }
    dayfirst = True

    def __init__(self, domain, text):
        if text.strip() == 'No entries found':
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisBg(WhoisEntry):
    """Whois parser for .bg domains
    """
    regex = {
        'domain_name': 'DOMAIN NAME: *(.+)\n',
        'status': 'registration status: s*(.+)',
        'expiration_date': 'expires at: *(.+)',
    }
    dayfirst = True

    def __init__(self, domain, text):
        if 'does not exist in database!' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisDe(WhoisEntry):
    """Whois parser for .de domains
    """
    regex = {
        'domain_name':      'Domain: *(.+)',
        'status':           'Status: *(.+)',
        'updated_date':     'Changed: *(.+)',
        'name':             'name: *(.+)',
        'org':              'Organisation: *(.+)',
        'address':          'Address: *(.+)',
        'zipcode':          'PostalCode: *(.+)',
        'city':             'City: *(.+)',
        'country_code':     'CountryCode: *(.+)',
        'phone':            'Phone: *(.+)',
        'fax':              'Fax: *(.+)',
        'name_servers':     'Nserver: *(.+)',  # list of name servers
        'emails': EMAIL_REGEX  # list of email addresses

    }

    def __init__(self, domain, text):
        if 'Status: free' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisAt(WhoisEntry):
    """Whois parser for .at domains
    """
    regex = {
        'domain_name': 'domain: *(.+)',
        'registrar': 'registrar: *(.+)',
        'name': 'personname: *(.+)',
        'org': 'organization: *(.+)',
        'address': 'street address: *(.+)',
        'zipcode': 'postal code: *(.+)',
        'city': 'city: *(.+)',
        'country': 'country: *(.+)',
        'phone': 'phone: *(.+)',
        'fax': 'fax-no: *(.+)',
        'updated_date': 'changed: *(.+)',
        'email': 'e-mail: *(.+)',
    }

    def __init__(self, domain, text):
        if 'Status: free' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisBe(WhoisEntry):
    """Whois parser for .be domains
    """
    regex = {
        'name': 'Name: *(.+)',
        'org': 'Organisation: *(.+)',
        'phone': 'Phone: *(.+)',
        'fax': 'Fax: *(.+)',
        'email': 'Email: *(.+)',
    }

    def __init__(self, domain, text):
        if 'Status: AVAILABLE' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisInfo(WhoisEntry):
    """Whois parser for .info domains
    """
    regex = {
        'domain_name':      'Domain Name: *(.+)',
        'registrar':        'Registrar: *(.+)',
        'whois_server':     'Whois Server: *(.+)',  # empty usually
        'referral_url':     'Referral URL: *(.+)',  # http url of whois_server: empty usually
        'updated_date':     'Updated Date: *(.+)',
        'creation_date':    'Creation Date: *(.+)',
        'expiration_date':  'Registry Expiry Date: *(.+)',
        'name_servers':     'Name Server: *(.+)',  # list of name servers
        'status':           'Status: *(.+)',  # list of statuses
        'emails':           EMAIL_REGEX,  # list of email addresses
        'name':             'Registrant Name: *(.+)',
        'org':              'Registrant Organization: *(.+)',
        'address':          'Registrant Street: *(.+)',
        'city':             'Registrant City: *(.+)',
        'state':            'Registrant State/Province: *(.+)',
        'zipcode':          'Registrant Postal Code: *(.+)',
        'country':          'Registrant Country: *(.+)',
    }

    def __init__(self, domain, text):
        if text.strip() == 'NOT FOUND':
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisRf(WhoisRu):
    """Whois parser for .su domains
    """

    def __init__(self, domain, text):
        WhoisRu.__init__(self, domain, text)


class WhoisSu(WhoisRu):
    """Whois parser for .su domains
    """

    def __init__(self, domain, text):
        WhoisRu.__init__(self, domain, text)


class WhoisClub(WhoisEntry):
    """Whois parser for .us domains
    """
    regex = {
        'domain_name':                    'Domain Name: *(.+)',
        'domain__id':                     'Domain ID: *(.+)',
        'registrar':                      'Sponsoring Registrar: *(.+)',
        'registrar_id':                   'Sponsoring Registrar IANA ID: *(.+)',
        'registrar_url':                  'Registrar URL \(registration services\): *(.+)',
        # list of statuses
        'status':                         'Domain Status: *(.+)',
        'registrant_id':                  'Registrant ID: *(.+)',
        'registrant_name':                'Registrant Name: *(.+)',
        'registrant_address1':            'Registrant Address1: *(.+)',
        'registrant_address2':            'Registrant Address2: *(.+)',
        'registrant_city':                'Registrant City: *(.+)',
        'registrant_state_province':      'Registrant State/Province: *(.+)',
        'registrant_postal_code':         'Registrant Postal Code: *(.+)',
        'registrant_country':             'Registrant Country: *(.+)',
        'registrant_country_code':        'Registrant Country Code: *(.+)',
        'registrant_phone_number':        'Registrant Phone Number: *(.+)',
        'registrant_email':               'Registrant Email: *(.+)',
        'registrant_application_purpose': 'Registrant Application Purpose: *(.+)',
        'registrant_nexus_category':      'Registrant Nexus Category: *(.+)',
        'admin_id':                       'Administrative Contact ID: *(.+)',
        'admin_name':                     'Administrative Contact Name: *(.+)',
        'admin_address1':                 'Administrative Contact Address1: *(.+)',
        'admin_address2':                 'Administrative Contact Address2: *(.+)',
        'admin_city':                     'Administrative Contact City: *(.+)',
        'admin_state_province':           'Administrative Contact State/Province: *(.+)',
        'admin_postal_code':              'Administrative Contact Postal Code: *(.+)',
        'admin_country':                  'Administrative Contact Country: *(.+)',
        'admin_country_code':             'Administrative Contact Country Code: *(.+)',
        'admin_phone_number':             'Administrative Contact Phone Number: *(.+)',
        'admin_email':                    'Administrative Contact Email: *(.+)',
        'admin_application_purpose':      'Administrative Application Purpose: *(.+)',
        'admin_nexus_category':           'Administrative Nexus Category: *(.+)',
        'billing_id':                     'Billing Contact ID: *(.+)',
        'billing_name':                   'Billing Contact Name: *(.+)',
        'billing_address1':               'Billing Contact Address1: *(.+)',
        'billing_address2':               'Billing Contact Address2: *(.+)',
        'billing_city':                   'Billing Contact City: *(.+)',
        'billing_state_province':         'Billing Contact State/Province: *(.+)',
        'billing_postal_code':            'Billing Contact Postal Code: *(.+)',
        'billing_country':                'Billing Contact Country: *(.+)',
        'billing_country_code':           'Billing Contact Country Code: *(.+)',
        'billing_phone_number':           'Billing Contact Phone Number: *(.+)',
        'billing_email':                  'Billing Contact Email: *(.+)',
        'billing_application_purpose':    'Billing Application Purpose: *(.+)',
        'billing_nexus_category':         'Billing Nexus Category: *(.+)',
        'tech_id':                        'Technical Contact ID: *(.+)',
        'tech_name':                      'Technical Contact Name: *(.+)',
        'tech_address1':                  'Technical Contact Address1: *(.+)',
        'tech_address2':                  'Technical Contact Address2: *(.+)',
        'tech_city':                      'Technical Contact City: *(.+)',
        'tech_state_province':            'Technical Contact State/Province: *(.+)',
        'tech_postal_code':               'Technical Contact Postal Code: *(.+)',
        'tech_country':                   'Technical Contact Country: *(.+)',
        'tech_country_code':              'Technical Contact Country Code: *(.+)',
        'tech_phone_number':              'Technical Contact Phone Number: *(.+)',
        'tech_email':                     'Technical Contact Email: *(.+)',
        'tech_application_purpose':       'Technical Application Purpose: *(.+)',
        'tech_nexus_category':            'Technical Nexus Category: *(.+)',
        # list of name servers
        'name_servers':                   'Name Server: *(.+)',
        'created_by_registrar':           'Created by Registrar: *(.+)',
        'last_updated_by_registrar':      'Last Updated by Registrar: *(.+)',
        'creation_date':                  'Domain Registration Date: *(.+)',
        'expiration_date':                'Domain Expiration Date: *(.+)',
        'updated_date':                   'Domain Last Updated Date: *(.+)',
    }

    def __init__(self, domain, text):
        if 'Not found:' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisIo(WhoisEntry):
    """Whois parser for .io domains
    """
    regex = {
        'domain_name':                    'Domain Name: *(.+)',
        'domain__id':                     'Registry Domain ID: *(.+)',
        'registrar':                      'Registrar: *(.+)',
        'registrar_id':                   'Registrar IANA ID: *(.+)',
        'registrar_url':                  'Registrar URL: *(.+)',
        'status':                         'Domain Status: *(.+)',
        'registrant_name':                'Registrant Organization: *(.+)',
        'registrant_state_province':      'Registrant State/Province: *(.+)',
        'registrant_country':             'Registrant Country: *(.+)',
        'name_servers':                   'Name Server: *(.+)',
        'creation_date':                  'Creation Date: *(.+)',
        'expiration_date':                'Registry Expiry Date: *(.+)',
        'updated_date':                   'Updated Date: *(.+)',
    }

    def __init__(self, domain, text):
        if 'is available for purchase' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisBiz(WhoisEntry):
    """Whois parser for .biz domains
    """
    regex = {
        'domain_name':                    'Domain Name: *(.+)',
        'domain__id':                     'Domain ID: *(.+)',
        'registrar':                      'Registrar: *(.+)',
        'registrar_url':                  'Registrar URL: *(.+)',
        'registrar_id':                   'Registrar IANA ID: *(.+)',
        'registrar_email':                'Registrar Abuse Contact Email: *(.+)',
        'registrar_phone':                'Registrar Abuse Contact Phone: *(.+)',
        'status':                         'Domain Status: *(.+)',  # list of statuses
        'registrant_id':                  'Registrant ID: *(.+)',
        'registrant_name':                'Registrant Name: *(.+)',
        'registrant_address':             'Registrant Street: *(.+)',
        'registrant_city':                'Registrant City: *(.+)',
        'registrant_state_province':      'Registrant State/Province: *(.+)',
        'registrant_postal_code':         'Registrant Postal Code: *(.+)',
        'registrant_country':             'Registrant Country: *(.+)',
        'registrant_country_code':        'Registrant Country Code: *(.+)',
        'registrant_phone_number':        'Registrant Phone: *(.+)',
        'registrant_email':               'Registrant Email: *(.+)',
        'admin_id':                       'Registry Admin ID: *(.+)',
        'admin_name':                     'Admin Name: *(.+)',
        'admin_organization':             'Admin Organization: *(.+)',
        'admin_address':                  'Admin Street: *(.+)',
        'admin_city':                     'Admin City: *(.+)',
        'admin_state_province':           'Admin State/Province: *(.+)',
        'admin_postal_code':              'Admin Postal Code: *(.+)',
        'admin_country':                  'Admin Country: *(.+)',
        'admin_phone_number':             'Admin Phone: *(.+)',
        'admin_email':                    'Admin Email: *(.+)',
        'tech_id':                        'Registry Tech ID: *(.+)',
        'tech_name':                      'Tech Name: *(.+)',
        'tech_organization':              'Tech Organization: *(.+)',
        'tech_address':                   'Tech Street: *(.+)',
        'tech_city':                      'Tech City: *(.+)',
        'tech_state_province':            'Tech State/Province: *(.+)',
        'tech_postal_code':               'Tech Postal Code: *(.+)',
        'tech_country':                   'Tech Country: *(.+)',
        'tech_phone_number':              'Tech Phone: *(.+)',
        'tech_email':                     'Tech Email: *(.+)',
        'name_servers':                   'Name Server: *(.+)',  # list of name servers
        'creation_date':                  'Creation Date: *(.+)',
        'expiration_date':                'Registrar Registration Expiration Date: *(.+)',
        'updated_date':                   'Updated Date: *(.+)',
    }

    def __init__(self, domain, text):
        if 'No Data Found' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisMobi(WhoisMe):
    """Whois parser for .mobi domains
    """

    def __init__(self, domain, text):
        WhoisMe.__init__(self, domain, text)


class WhoisKg(WhoisEntry):
    """Whois parser for .kg domains
    """
    regex = {
        'domain_name':                    'Domain\s*([\w]+\.[\w]{2,5})',
        'registrar':                      'Domain support: \s*(.+)',
        'registrant_name':                'Name: *(.+)',
        'registrant_address':             'Address: *(.+)',
        'registrant_phone_number':        'phone: *(.+)',
        'registrant_email':               'Email: *(.+)',
        # # list of name servers
        'name_servers':                   'Name servers in the listed order: *([\d\w\.\s]+)',
        # 'name_servers':      r'([\w]+\.[\w]+\.[\w]{2,5}\s*\d{1,3}\.\d]{1,3}\.[\d]{1-3}\.[\d]{1-3})',
        'creation_date':                  'Record created: *(.+)',
        'expiration_date':                'Record expires on \s*(.+)',
        'updated_date':                   'Record last updated on\s*(.+)',

    }

    def __init__(self, domain, text):
        if 'Data not found. This domain is available for registration' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisChLi(WhoisEntry):
    """Whois Parser for .ch and .li domains
    """
    regex = {
        'domain_name':                      '\nDomain name:\n*(.+)',
        'registrant_name':                  'Holder of domain name:\s*(?:.*\n){1}\s*(.+)',
        'registrant_address':               'Holder of domain name:\s*(?:.*\n){2}\s*(.+)',
        'registrar':                        'Registrar:\n*(.+)',
        'creation_date':                    'First registration date:\n*(.+)',
        'dnssec':                           'DNSSEC:*([\S]+)',
        'tech-c':                           'Technical contact:\n*([\n\s\S]+)\nRegistrar:',
        'name_servers':                     'Name servers:\n *([\n\S\s]+)'
    }

    def __init__(self, domain, text):
        if 'We do not have an entry in our database matching your query.' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisID(WhoisEntry):
    """Whois parser for .id domains
    """
    regex = {
        'domain_id':                   'Domain ID:(.+)',
        'domain_name':                 'Domain Name:(.+)',
        'creation_date':               'Created On:(.+)',
        'expiration_date':             'Expiration Date:(.+)',
        'updated_date':                'Last Updated On:(.+)',
        'dnssec':                      'DNSSEC:(.+)',

        'registrar':                   'Sponsoring Registrar Organization:(.+)',
        'registrar_city':              'Sponsoring Registrar City:(.+)',
        'registrar_postal_code':       'Sponsoring Registrar Postal Code:(.+)',
        'registrar_country':           'Sponsoring Registrar Country:(.+)',
        'registrar_phone':             'Sponsoring Registrar Phone:(.+)',
        'registrar_email':             'Sponsoring Registrar Contact Email:(.+)',

        'status':                      'Status:(.+)',  # list of statuses

        'registrant_id':               'Registrant ID:(.+)',
        'registrant_name':             'Registrant Name:(.+)',
        'registrant_org':              'Registrant Organization:(.+)',
        'registrant_address':          'Registrant Street1:(.+)',
        'registrant_address2':         'Registrant Street2:(.+)',
        'registrant_address3':         'Registrant Street3:(.+)',
        'registrant_city':             'Registrant City:(.+)',
        'registrant_country':          'Registrant Country:(.+)',
        'registrant_postal_code':      'Registrant Postal Code:(.+)',
        'registrant_phone':            'Registrant Phone:(.+)',
        'registrant_fax':              'Registrant FAX:(.+)',
        'registrant_email':            'Registrant Email:(.+)',

        'name_servers':                'Name Server:(.+)',  # list of name servers
    }

    def __init__(self, domain, text):
        if 'NOT FOUND' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisSe(WhoisEntry):
    """Whois parser for .se domains
    """
    regex = {
        'domain_name':                    'domain\.*: *(.+)',
        'registrant_name':                'holder\.*: *(.+)',
        'creation_date':                  'created\.*: *(.+)',
        'updated_date':                   'modified\.*: *(.+)',
        'expiration_date':                'expires\.*: *(.+)',
        'transfer_date':                  'transferred\.*: *(.+)',
        'name_servers':                   'nserver\.*: *(.+)',  # list of name servers
        'dnssec':                         'dnssec\.*: *(.+)',
        'status':                         'status\.*: *(.+)',  # list of statuses
        'registrar':                      'registrar: *(.+)',
    }

    def __init__(self, domain, text):
        if 'not found.' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisJobs(WhoisEntry):
    """Whois parser for .jobs domains
    """
    regex = {
        'domain_name':                    'Domain Name: *(.+)',
        'domain_id':                      'Registry Domain ID: *(.+)',
        'status':                         'Domain Status: *(.+)',
        'whois_server':                   'Registrar WHOIS Server: *(.+)',

        'registrar_url':                  'Registrar URL: *(.+)',
        'registrar_name':                 'Registrar: *(.+)',
        'registrar_email':                'Registrar Abuse Contact Email: *(.+)',
        'registrar_phone':                'Registrar Abuse Contact Phone: *(.+)',

        'registrant_name':                'Registrant Name: (.+)',
        'registrant_id':                  'Registry Registrant ID: (.+)',
        'registrant_organization':        'Registrant Organization: (.+)',
        'registrant_city':                'Registrant City: (.*)',
        'registrant_street':              'Registrant Street: (.*)',
        'registrant_state_province':      'Registrant State/Province: (.*)',
        'registrant_postal_code':         'Registrant Postal Code: (.*)',
        'registrant_country':             'Registrant Country: (.+)',
        'registrant_phone':               'Registrant Phone: (.+)',
        'registrant_fax':                 'Registrant Fax: (.+)',
        'registrant_email':               'Registrant Email: (.+)',


        'admin_name':                     'Admin Name: (.+)',
        'admin_id':                       'Registry Admin ID: (.+)',
        'admin_organization':             'Admin Organization: (.+)',
        'admin_city':                     'Admin City: (.*)',
        'admin_street':                   'Admin Street: (.*)',
        'admin_state_province':           'Admin State/Province: (.*)',
        'admin_postal_code':              'Admin Postal Code: (.*)',
        'admin_country':                  'Admin Country: (.+)',
        'admin_phone':                    'Admin Phone: (.+)',
        'admin_fax':                      'Admin Fax: (.+)',
        'admin_email':                    'Admin Email: (.+)',

        'billing_name':                   'Billing Name: (.+)',
        'billing_id':                     'Registry Billing ID: (.+)',
        'billing_organization':           'Billing Organization: (.+)',
        'billing_city':                   'Billing City: (.*)',
        'billing_street':                 'Billing Street: (.*)',
        'billing_state_province':         'Billing State/Province: (.*)',
        'billing_postal_code':            'Billing Postal Code: (.*)',
        'billing_country':                'Billing Country: (.+)',
        'billing_phone':                  'Billing Phone: (.+)',
        'billing_fax':                    'Billing Fax: (.+)',
        'billing_email':                  'Billing Email: (.+)',

        'tech_name':                      'Tech Name: (.+)',
        'tech_id':                        'Registry Tech ID: (.+)',
        'tech_organization':              'Tech Organization: (.+)',
        'tech_city':                      'Tech City: (.*)',
        'tech_street':                    'Tech Street: (.*)',
        'tech_state_province':            'Tech State/Province: (.*)',
        'tech_postal_code':               'Tech Postal Code: (.*)',
        'tech_country':                   'Tech Country: (.+)',
        'tech_phone':                     'Tech Phone: (.+)',
        'tech_fax':                       'Tech Fax: (.+)',
        'tech_email':                     'Tech Email: (.+)',

        'updated_date':                   'Updated Date: *(.+)',
        'creation_date':                  'Creation Date: *(.+)',
        'expiration_date':                'Registry Expiry Date: *(.+)',
        'name_servers':                   'Name Server: *(.+)'

    }

    def __init__(self, domain, text):
        if 'not found.' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisIt(WhoisEntry):
    """Whois parser for .it domains
    """
    regex = {
        'domain_name':                    'Domain: *(.+)',
        'creation_date':                  '(?<! )Created: *(.+)',
        'updated_date':                   '(?<! )Last Update: *(.+)',
        'expiration_date':                '(?<! )Expire Date: *(.+)',
        'status':                         'Status: *(.+)',  # list of statuses
        'name_servers':                   'Nameservers[\s]((?:.+\n)*)',  # servers in one string sep by \n

        'registrant_organization':        '(?<=Registrant)[\s\S]*?Organization:(.*)',
        'registrant_address':             '(?<=Registrant)[\s\S]*?Address:(.*)',

        'admin_address':                  '(?<=Admin Contact)[\s\S]*?Address:(.*)',
        'admin_organization':             '(?<=Admin Contact)[\s\S]*?Organization:(.*)',
        'admin_name':                     '(?<=Admin Contact)[\s\S]*?Name:(.*)',

        'tech_address':                   '(?<=Technical Contacts)[\s\S]*?Address:(.*)',
        'tech_organization':              '(?<=Technical Contacts)[\s\S]*?Organization:(.*)',
        'tech_name':                      '(?<=Technical Contacts)[\s\S]*?Name:(.*)',

        'registrar_address':              '(?<=Registrar)[\s\S]*?Address:(.*)',
        'registrar':                      '(?<=Registrar)[\s\S]*?Organization:(.*)',
        'registrar_name':                 '(?<=Registrar)[\s\S]*?Name:(.*)',
    }

    def __init__(self, domain, text):
        if 'not found.' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisSa(WhoisEntry):
    """Whois parser for .sa domains
    """
    regex = {
        'domain_name':                    'Domain Name: *(.+)',
        'creation_date':                  'Created on: *(.+)',
        'updated_date':                   'Last Updated on: *(.+)',
        'name_servers':                   'Name Servers:[\s]((?:.+\n)*)',  # servers in one string sep by \n

        'registrant_name':                'Registrant:\s*(.+)',
        'registrant_address':             '(?<=Registrant)[\s\S]*?Address:((?:.+\n)*)',

        'admin_address':                  '(?<=Administrative Contact)[\s\S]*?Address:((?:.+\n)*)',
        'admin':                          'Administrative Contact:\s*(.*)',

        'tech_address':                   '(?<=Technical Contact)[\s\S]*?Address:((?:.+\n)*)',
        'tech':                           'Technical Contact:\s*(.*)',
    }

    def __init__(self, domain, text):
        if 'not found.' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisSK(WhoisEntry):
    """Whois parser for .sk domains
    """
    regex = {
        'domain_name':                    'Domain: *(.+)',
        'creation_date':                  '(?<=Domain:)[\s\w\W]*?Created: *(.+)',
        'updated_date':                   '(?<=Domain:)[\s\w\W]*?Updated: *(.+)',
        'expiration_date':                'Valid Until: *(.+)',
        'name_servers':                   'Nameserver: *(.+)',

        'registrant_name':                'Name:\s*(.+)',
        'registrant_email':               'Email:\s*(.+)',
        'registrant_phone':               'Phone:\s*(.+)',
        'registrant_address':             'Street:\s*(.+)',

        'registrar':                      '(?<=Registrar)[\s\S]*?Organization:(.*)',
        'registrar_organization_id':      '(?<=Registrar)[\s\S]*?Organization ID:(.*)',
        'registrar_name':                 '(?<=Registrant)[\s\S]*?Name:(.*)',
        'registrar_phone':                '(?<=Registrant)[\s\S]*?Phone:(.*)',
        'registrar_email':                '(?<=Registrant)[\s\S]*?Email:(.*)',
        'registrar_street':               '(?<=Registrant)[\s\S]*?Street:(.*)',
        'registrar_city':                 '(?<=Registrant)[\s\S]*?City:(.*)',
        'registrar_postal_code':          '(?<=Registrant)[\s\S]*?Postal Code:(.*)',
        'registrar_country_code':         '(?<=Registrant)[\s\S]*?Country Code:(.*)',

        'admin':                          'Admin Contact:\s*(.*)',
        'admin_organization':             '(?<=^Contact)[\s\S]*?Organization:(.*)',
        'admin_phone':                    '(?<=^Contact)[\s\S]*?Phone:(.*)',
        'admin_email':                    '(?<=^Contact)[\s\S]*?Email:(.*)',
        'admin_street':                   '(?<=^Contact)[\s\S]*?Street:(.*)',
        'admin_city':                     '(?<=^Contact)[\s\S]*?City:(.*)',
        'admin_postal_code':              '(?<=^Contact)[\s\S]*?Postal Code:(.*)',
        'admin_country_code':             '(?<=^Contact)[\s\S]*?Country Code:(.*)',

        'tech':                           'Tech Contact:\s*(.*)',
    }

    def __init__(self, domain, text):
        if 'not found.' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisMx(WhoisEntry):
    """Whois parser for .mx domains
    """
    regex = {
        'domain_name':                    'Domain Name: *(.+)',
        'creation_date':                  'Created On: *(.+)',
        'updated_date':                   'Last Updated On: *(.+)',
        'expiration_date':                'Expiration Date: *(.+)',
        'url':                            'URL: *(.+)',

        'name_servers':                   'DNS: (.*)',  # servers in one string sep by \n

        'registrar':                      'Registrar:\s*(.+)',

        'registrant_name':                '(?<=Registrant)[\s\S]*?Name:(.*)',
        'registrant_city':                '(?<=Registrant)[\s\S]*?City:(.*)',
        'registrant_state':               '(?<=Registrant)[\s\S]*?State:(.*)',
        'registrant_country':             '(?<=Registrant)[\s\S]*?Country:(.*)',

        'admin':                          '(?<=Administrative Contact)[\s\S]*?Name:(.*)',
        'admin_city':                     '(?<=Administrative Contact)[\s\S]*?City:(.*)',
        'admin_country':                  '(?<=Administrative Contact)[\s\S]*?Country:(.*)',
        'admin_state':                    '(?<=Administrative Contact)[\s\S]*?State:(.*)',

        'tech_name':                      '(?<=Technical Contact)[\s\S]*?Name:(.*)',
        'tech_city':                      '(?<=Technical Contact)[\s\S]*?City:(.*)',
        'tech_state':                     '(?<=Technical Contact)[\s\S]*?State:(.*)',
        'tech_country':                   '(?<=Technical Contact)[\s\S]*?Country:(.*)',


        'billing_name':                   '(?<=Billing Contact)[\s\S]*?Name:(.*)',
        'billing_city':                   '(?<=Billing Contact)[\s\S]*?City:(.*)',
        'billing_state':                  '(?<=Billing Contact)[\s\S]*?State:(.*)',
        'billing_country':                '(?<=Billing Contact)[\s\S]*?Country:(.*)',
    }

    def __init__(self, domain, text):
        if 'not found.' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisTw(WhoisEntry):
    """Whois parser for .tw domains
    """
    regex = {
        'domain_name':                    'Domain Name: *(.+)',
        'creation_date':                  'Record created on (.+) ',
        'expiration_date':                'Record expires on (.+) ',

        'name_servers':                   'Domain servers in listed order:((?:\s.+)*)',  # servers in one string sep by \n

        'registrar':                      'Registration Service Provider: *(.+)',
        'registrar_url':                  'Registration Service URL: *(.+)',

        'registrant_name':                '(?<=Registrant:)\s+(.*)',
        'registrant_organization':        '(?<=Registrant:)\s*(.*)',
        'registrant_city':                '(?<=Registrant:)\s*(?:.*\n){5}\s+(.*),',
        'registrant_street':              '(?<=Registrant:)\s*(?:.*\n){4}\s+(.*)',
        'registrant_state_province':      '(?<=Registrant:)\s*(?:.*\n){5}.*, (.*)',
        'registrant_country':             '(?<=Registrant:)\s*(?:.*\n){6}\s+(.*)',
        'registrant_phone':               '(?<=Registrant:)\s*(?:.*\n){2}\s+(\+*\d.*)',
        'registrant_fax':                 '(?<=Registrant:)\s*(?:.*\n){3}\s+(\+*\d.*)',
        'registrant_email':               '(?<=Registrant:)\s*(?:.*\n){1}.*  (.*)',

        'admin':                          '(?<=Administrative Contact:\n)\s+(.*)  ',
        'admin_email':                    '(?<=Administrative Contact:)\s*.*  (.*)',
        'admin_phone':                    '(?<=Administrative Contact:\n)\s*(?:.*\n){1}\s+(\+*\d.*)',
        'admin_fax':                      '(?<=Administrative Contact:\n)\s*(?:.*\n){2}\s+(\+*\d.*)',

        'tech':                           '(?<=Technical Contact:\n)\s+(.*)  ',
        'tech_email':                     '(?<=Technical Contact:)\s*.*  (.*)',
        'tech_phone':                     '(?<=Technical Contact:\n)\s*(?:.*\n){1}\s+(\+*\d.*)',
        'tech_fax':                       '(?<=Technical Contact:\n)\s*(?:.*\n){2}\s+(\+*\d.*)',
    }

    def __init__(self, domain, text):
        if 'not found.' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisTr(WhoisEntry):
    """Whois parser for .tr domains
    """
    regex = {
        'domain_name':                    '[**] Domain Name: *(.+)',

        'creation_date':                  'Created on.*: *(.+)',
        'expiration_date':                'Expires on.*: *(.+)',

        'name_servers':                   '[**] Domain servers:((?:\s.+)*)',  # servers in one string sep by \n

        'registrant_name':                '(?<=[**] Registrant:)[\s\S]((?:\s.+)*)',

        'admin':                          '(?<=[**] Administrative Contact:)[\s\S]*?NIC Handle\s+: (.*)',
        'admin_organization':             '(?<=[**] Administrative Contact:)[\s\S]*?Organization Name\s+: (.*)',
        'admin_address':                  '(?<=[**] Administrative Contact)[\s\S]*?Address\s+: (.*)',
        'admin_phone':                    '(?<=[**] Administrative Contact)[\s\S]*?Phone\s+: (.*)',
        'admin_fax':                      '(?<=[**] Administrative Contact)[\s\S]*?Fax\s+: (.*)',

        'tech':                           '(?<=[**] Technical Contact:)[\s\S]*?NIC Handle\s+: (.*)',
        'tech_organization':              '(?<=[**] Technical Contact:)[\s\S]*?Organization Name\s+: (.*)',
        'tech_address':                   '(?<=[**] Technical Contact)[\s\S]*?Address\s+: (.*)',
        'tech_phone':                     '(?<=[**] Technical Contact)[\s\S]*?Phone\s+: (.*)',
        'tech_fax':                       '(?<=[**] Technical Contact)[\s\S]*?Fax\s+: (.*)',

        'billing':                        '(?<=[**] Billing Contact:)[\s\S]*?NIC Handle\s+: (.*)',
        'billing_organization':           '(?<=[**] Billing Contact:)[\s\S]*?Organization Name\s+: (.*)',
        'billing_address':                '(?<=[**] Billing Contact)[\s\S]*?Address\s+: (.*)',
        'billing_phone':                  '(?<=[**] Billing Contact)[\s\S]*?Phone\s+: (.*)',
        'billing_fax':                    '(?<=[**] Billing Contact)[\s\S]*?Fax\s+: (.*)',
    }

    def __init__(self, domain, text):
        if 'not found.' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisIs(WhoisEntry):
    """Whois parser for .se domains
    """
    regex = {
        'domain_name':      'domain\.*: *(.+)',
        'registrant_name':  'registrant: *(.+)',
        'name':             'person\.*: *(.+)',
        'address':          'address\.*: *(.+)',
        'creation_date':    'created\.*: *(.+)',
        'expiration_date':  'expires\.*: *(.+)',
        'email':            'e-mail: *(.+)',
        'name_servers':     'nserver\.*: *(.+)',  # list of name servers
        'dnssec':           'dnssec\.*: *(.+)',
    }

    def __init__(self, domain, text):
        if 'No entries found' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisDk(WhoisEntry):
    """Whois parser for .dk domains
    """
    regex = {
        'domain_name':         'Domain: *(.+)',
        'creation_date':       'Registered: *(.+)',
        'expiration_date':     'Expires: *(.+)',
        'dnssec':              'Dnssec: *(.+)',
        'status':              'Status: *(.+)',
        'registrant_handle':   'Registrant\s*(?:.*\n){1}\s*Handle: *(.+)',
        'registrant_name':     'Registrant\s*(?:.*\n){2}\s*Name: *(.+)',
        'registrant_address':  'Registrant\s*(?:.*\n){3}\s*Address: *(.+)',
        'registrant_zip_code': 'Registrant\s*(?:.*\n){4}\s*Postalcode: *(.+)',
        'registrant_city':     'Registrant\s*(?:.*\n){5}\s*City: *(.+)',
        'registrant_country':  'Registrant\s*(?:.*\n){6}\s*Country: *(.+)',
        'name_servers':        'Nameservers\n *([\n\S\s]+)'
    }

    def __init__(self, domain, text):
        if 'No match for ' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)

    def _preprocess(self, attr, value):
        if attr == 'name_servers':
            return [
                line.split(":")[-1].strip()
                for line in value.split("\n")
                if line.startswith("Hostname")
            ]
        return super(WhoisDk, self)._preprocess(attr, value)


class WhoisAi(WhoisEntry):
    """Whois parser for .ai domains
    """
    regex = {
        'domain_name':      'Complete Domain Name\.*: *(.+)',
        'name':             'Name \(Last, First\)\.*: *(.+)',
        'org':              'Organization Name\.*: *(.+)',
        'address':          'Street Address\.*: *(.+)',
        'city':             'City\.*: *(.+)',
        'state':            'State\.*: *(.+)',
        'zipcode':          'Postal Code\.*: *(\d+)',
        'country':          'Country\.*: *(.+)',
        'name_servers':     'Server Hostname\.*: *(.+)',
    }

    def __init__(self, domain, text):
        if 'not registered' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisIl(WhoisEntry):
    """Whois parser for .il domains
    """
    regex = {
        'domain_name':        'domain: *(.+)',
        'expiration_date':    'validity: *(.+)',
        'registrant_name':    'person: *(.+)',
        'registrant_address': 'address *(.+)',
        'dnssec':             'DNSSEC: *(.+)',
        'status':             'status: *(.+)',
        'name_servers':       'nserver: *(.+)',
        'emails':             'e-mail: *(.+)',
        'phone':              'phone: *(.+)',
        'registrar':          'registrar name: *(.+)',
        'referral_url':       'registrar info: *(.+)',
    }
    dayfirst = True

    def __init__(self, domain, text):
        if 'No data was found' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)

    def _preprocess(self, attr, value):
        if attr == 'emails':
            value = value.replace(' AT ', '@')
        return super(WhoisIl, self)._preprocess(attr, value)


class WhoisIn(WhoisEntry):
    """Whois parser for .in domains
    """
    regex = {
        'domain_name':      'Domain Name: *(.+)',
        'registrar':        'Registrar: *(.+)',
        'registrar_url':    'Registrar URL: *(.+)',
        'registrar_iana':   'Registrar IANA ID: *(\d+)',
        'updated_date':     'Updated Date: *(.+)|Last Updated On: *(.+)',
        'creation_date':    'Creation Date: *(.+)|Created On: *(.+)',
        'expiration_date':  'Expiration Date: *(.+)|Registry Expiry Date: *(.+)',
        'name_servers':     'Name Server: *(.+)',
        'organization':     'Registrant Organization: *(.+)',
        'state':            'Registrant State/Province: *(.+)',
        'status':           'Status: *(.+)',
        'emails':           EMAIL_REGEX,
        'country':          'Registrant Country: *(.+)',
        'dnssec':           'DNSSEC: *([\S]+)',
    }

    def __init__(self, domain, text):
        if 'NOT FOUND' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisCat(WhoisEntry):
    """Whois parser for .cat domains
    """
    regex = {
        'domain_name':      'Domain Name: *(.+)',
        'registrar':        'Registrar: *(.+)',
        'updated_date':     'Updated Date: *(.+)',
        'creation_date':    'Creation Date: *(.+)',
        'expiration_date':  'Registry Expiry Date: *(.+)',
        'name_servers':     'Name Server: *(.+)',
        'status':           'Domain status: *(.+)',
        'emails':           EMAIL_REGEX,
    }

    def __init__(self, domain, text):
        if 'no matching objects' in text:
            raise PywhoisError(text)
        else:
            # Merge base class regex with specifics
            self._regex.copy().update(self.regex)
            self.regex = self._regex
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisIe(WhoisEntry):
    """Whois parser for .ie domains
    """
    regex = {
        'domain_name':      'Domain: *(.+)',
        'registrant_name':  'Domain Holder: *(.+)',
        'description':      'descr: *(.+)',
        'source':           'Source: *(.+)',
        'creation_date':    'Registration Date: *(.+)',
        'expiration_date':  'Renewal Date: *(.+)',
        'name_servers':     'Nserver: *(.+)',
        'status':           'Renewal status: *(.+)',
        'admin_id':         'Admin-c: *(.+)',
        'tech_id':          'Tech-c: *(.+)',
        'registrar':        'Account Name: *(.+)',
        'registrar_contact':'Registrar Abuse Contact: *(.+)'
    }

    def __init__(self, domain, text):
        if 'no matching objects' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisNz(WhoisEntry):
    """Whois parser for .nz domains
    """
    regex = {
        'domain_name':          'domain_name:\s*([^\n\r]+)',
        'registrar':            'registrar_name:\s*([^\n\r]+)',
        'updated_date':         'domain_datelastmodified:\s*([^\n\r]+)',
        'creation_date':        'domain_dateregistered:\s*([^\n\r]+)',
        'expiration_date':      'domain_datebilleduntil:\s*([^\n\r]+)',
        'name_servers':         'ns_name_\d*:\s*([^\n\r]+)',  # list of name servers
        'status':               'status:\s*([^\n\r]+)',  # list of statuses
        'emails':               EMAIL_REGEX,  # list of email s
        'name':                 'registrant_contact_name:\s*([^\n\r]+)',
        'address':              'registrant_contact_address\d*:\s*([^\n\r]+)',
        'city':                 'registrant_contact_city:\s*([^\n\r]+)',
        'zipcode':              'registrant_contact_postalcode:\s*([^\n\r]+)',
        'country':              'registrant_contact_country:\s*([^\n\r]+)',
    }

    def __init__(self, domain, text):
        if 'no matching objects' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisLu(WhoisEntry):
    """Whois parser for .lu domains
    """
    regex = {
        'domain_name':              'domainname: *(.+)',
        'creation_date':            'registered: *(.+)',
        'name_servers':             'nserver: *(.+)',
        'status':                   'domaintype: *(.+)',
        'registrar':                'registrar-name: *(.+)',
        'registrant_name':          'org-name: *(.+)',
        'registrant_address':       'org-address: *(.+)',
        'registrant_postal_code':   'org-zipcode:*(.+)',
        'registrant_city':          'org-city: *(.+)',
        'registrant_country':       'org-country: *(.+)',
        'admin_name':               'adm-name: *(.+)',
        'admin_address':            'adm-address: *(.+)',
        'admin_postal_code':        'adm-zipcode: *(.+)',
        'admin_city':               'adm-city: *(.+)',
        'admin_country':            'adm-country: *(.+)',
        'admin_email':              'adm-email: *(.+)',
        'tech_name':                'tec-name: *(.+)',
        'tech_address':             'tec-address: *(.+)',
        'tech_postal_code':         'tec-zipcode: *(.+)',
        'tech_city':                'tec-city: *(.+)',
        'tech_country':             'tec-country: *(.+)',
        'tech_email':               'tec-email: *(.+)',
    }

    def __init__(self, domain, text):
        if 'No such domain' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisCz(WhoisEntry):
    """Whois parser for .cz domains
    """
    regex = {
        'domain_name':              'domain: *(.+)',
        'registrant_name':          'registrant: *(.+)',
        'registrar':                'registrar: *(.+)',
        'creation_date':            'registered: *(.+)',
        'updated_date':             'changed: *(.+)',
        'expiration_date':          'expire: *(.+)',
        'name_servers':             'nserver: *(.+)',
    }

    def __init__(self, domain, text):
        if '% No entries found.' in text or 'Your connection limit exceeded' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisOnline(WhoisEntry):
    """Whois parser for .online domains
    """
    regex = {
        'domain_name':                    'Domain Name: *(.+)',
        'domain__id':                     'Domain ID: *(.+)',
        'whois_server':                   'Registrar WHOIS Server: *(.+)',
        'registrar':                      'Registrar: *(.+)',
        'registrar_id':                   'Registrar IANA ID: *(.+)',
        'registrar_url':                  'Registrar URL: *(.+)',
        'status':                         'Domain Status: *(.+)',
        'registrant_email':               'Registrant Email: *(.+)',
        'admin_email':                    'Admin Email: *(.+)',
        'billing_email':                  'Billing Email: *(.+)',
        'tech_email':                     'Tech Email: *(.+)',
        'name_servers':                   'Name Server: *(.+)',
        'creation_date':                  'Creation Date: *(.+)',
        'expiration_date':                'Registry Expiry Date: *(.+)',
        'updated_date':                   'Updated Date: *(.+)',
        'dnssec':                         'DNSSEC: *([\S]+)',
    }

    def __init__(self, domain, text):
        if 'Not found:' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisHr(WhoisEntry):
    """Whois parser for .hr domains
    """
    regex = {
        'domain_name':                    'Domain Name: *(.+)',
        'whois_server':                   'Registrar WHOIS Server: *(.+)',
        'registrar_url':                  'Registrar URL: *(.+)',
        'updated_date':                   'Updated Date: *(.+)',
        'creation_date':                  'Creation Date: *(.+)',
        'expiration_date':                'Registrar Registration Expiration Date: *(.+)',
        'name_servers':                   'Name Server: *(.+)',
        'registrant_name':                'Registrant Name:\s(.+)',
        'registrant_address':             'Reigstrant Street:\s*(.+)',
    }

    def __init__(self, domain, text):
        if 'ERROR: No entries found' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisHk(WhoisEntry):
    """Whois parser for .hk domains
    """
    regex = {
        'domain_name':                    'Domain Name: *(.+)',
        'status':                         'Domain Status: *(.+)',
        'dnssec':                         'DNSSEC: *(.+)',
        'whois_server':                   'Registrar WHOIS Server: *(.+)',

        'registrar_url':                  'Registrar URL: *(.+)',
        'registrar':                      'Registrar Name: *(.+)',
        'registrar_email':                'Registrar Contact Information: Email: *(.+)',

        'registrant_company_name':        'Registrant Contact Information:\s*Company English Name.*:(.+)',
        'registrant_address':             '(?<=Registrant Contact Information:)[\s\S]*?Address: (.*)',
        'registrant_country':             '[Registrant Contact Information\w\W]+Country: ([\S\ ]+)',
        'registrant_email':               '[Registrant Contact Information\w\W]+Email: ([\S\ ]+)',

        'admin_name':                     '[Administrative Contact Information\w\W]+Given name: ([\S\ ]+)',
        'admin_family_name':              '[Administrative Contact Information\w\W]+Family name: ([\S\ ]+)',
        'admin_company_name':             '[Administrative Contact Information\w\W]+Company name: ([\S\ ]+)',
        'admin_address':                  '(?<=Administrative Contact Information:)[\s\S]*?Address: (.*)',
        'admin_country':                  '[Administrative Contact Information\w\W]+Country: ([\S\ ]+)',
        'admin_phone':                    '[Administrative Contact Information\w\W]+Phone: ([\S\ ]+)',
        'admin_fax':                      '[Administrative Contact Information\w\W]+Fax: ([\S\ ]+)',
        'admin_email':                    '[Administrative Contact Information\w\W]+Email: ([\S\ ]+)',
        'admin_account_name':             '[Administrative Contact Information\w\W]+Account Name: ([\S\ ]+)',

        'tech_name':                      '[Technical Contact Information\w\W]+Given name: (.+)',
        'tech_family_name':               '[Technical Contact Information\w\W]+Family name: (.+)',
        'tech_company_name':              '[Technical Contact Information\w\W]+Company name: (.+)',
        'tech_address':                   '(?<=Technical Contact Information:)[\s\S]*?Address: (.*)',
        'tech_country':                   '[Technical Contact Information\w\W]+Country: (.+)',
        'tech_phone':                     '[Technical Contact Information\w\W]+Phone: (.+)',
        'tech_fax':                       '[Technical Contact Information\w\W]+Fax: (.+)',
        'tech_email':                     '[Technical Contact Information\w\W]+Email: (.+)',
        'tech_account_name':              '[Technical Contact Information\w\W]+Account Name: (.+)',

        'updated_date':                   'Updated Date: *(.+)',
        'creation_date':                  '[Registrant Contact Information\w\W]+Domain Name Commencement Date: (.+)',
        'expiration_date':                '[Registrant Contact Information\w\W]+Expiry Date: (.+)',
        'name_servers':                   'Name Servers Information:\s+((?:.+\n)*)'
    }

    def __init__(self, domain, text):
        if 'ERROR: No entries found' in text or 'The domain has not been registered' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisUA(WhoisEntry):
    """Whois parser for .ua domains
    """
    regex = {
        'domain_name':                    'domain: *(.+)',
        'status':                         'status: *(.+)',

        'registrar':                     '(?<=Registrar:)[\s\W\w]*?organization-loc:(.*)',
        'registrar_name':                '(?<=Registrar:)[\s\W\w]*?registrar:(.*)',
        'registrar_url':                 '(?<=Registrar:)[\s\W\w]*?url:(.*)',
        'registrar_country':             '(?<=Registrar:)[\s\W\w]*?country:(.*)',
        'registrar_city':                '(?<=Registrar:)[\s\W\w]*?city:\s+(.*)\n',
        'registrar_address':             '(?<=Registrar:)[\s\W\w]*?abuse-postal:\s+(.*)\n',
        'registrar_email':               '(?<=Registrar:)[\s\W\w]*?abuse-email:(.*)',

        'registrant_name':               '(?<=Registrant:)[\s\W\w]*?organization-loc:(.*)',
        'registrant_country':            '(?<=Registrant:)[\s\W\w]*?country-loc:(.*)',
        'registrant_city':               '(?<=Registrant:)[\s\W\w]*?(?:address\-loc:\s+.*\n){2}address-loc:\s+(.*)\n',
        'registrant_state':              '(?<=Registrant:)[\s\W\w]*?(?:address\-loc:\s+.*\n){1}address-loc:\s+(.*)\n',
        'registrant_address':            '(?<=Registrant:)[\s\W\w]*?address-loc:\s+(.*)\n',
        'registrant_email':              '(?<=Registrant:)[\s\W\w]*?e-mail:(.*)',
        'registrant_postal_code':        '(?<=Registrant:)[\s\W\w]*?postal-code-loc:(.*)',
        'registrant_phone':              '(?<=Registrant:)[\s\W\w]*?phone:(.*)',
        'registrant_fax':                '(?<=Registrant:)[\s\W\w]*?fax:(.*)',

        'admin':                         '(?<=Administrative Contacts:)[\s\W\w]*?organization-loc:(.*)',
        'admin_country':                 '(?<=Administrative Contacts:)[\s\W\w]*?country-loc:(.*)',
        'admin_city':                    '(?<=Administrative Contacts:)[\s\W\w]*?(?:address\-loc:\s+.*\n){2}address-loc:\s+(.*)\n',
        'admin_state':                   '(?<=Administrative Contacts:)[\s\W\w]*?(?:address\-loc:\s+.*\n){1}address-loc:\s+(.*)\n',
        'admin_address':                 '(?<=Administrative Contacts:)[\s\W\w]*?address-loc:\s+(.*)\n',
        'admin_email':                   '(?<=Administrative Contacts:)[\s\W\w]*?e-mail:(.*)',
        'admin_postal_code':             '(?<=Administrative Contacts:)[\s\W\w]*?postal-code-loc:(.*)',
        'admin_phone':                   '(?<=Administrative Contacts:)[\s\W\w]*?phone:(.*)',
        'admin_fax':                     '(?<=Administrative Contacts:)[\s\W\w]*?fax:(.*)',

        'updated_date':                   'modified: *(.+)',
        'creation_date':                  'created: (.+)',
        'expiration_date':                'expires: (.+)',
        'name_servers':                   'nserver: *(.+)'
    }

    def __init__(self, domain, text):
        if 'ERROR: No entries found' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisHn(WhoisEntry):
    """Whois parser for .hn domains
        """
    regex = {
        'domain_name':                    'Domain Name: *(.+)',
        'domain_id':                      'Domain ID: *(.+)',
        'status':                         'Domain Status: *(.+)',
        'whois_server':                   'WHOIS Server: *(.+)',

        'registrar_url':                  'Registrar URL: *(.+)',
        'registrar':                      'Registrar: *(.+)',

        'registrant_name':                'Registrant Name: (.+)',
        'registrant_id':                  'Registrant ID: (.+)',
        'registrant_organization':        'Registrant Organization: (.+)',
        'registrant_city':                'Registrant City: (.*)',
        'registrant_street':              'Registrant Street: (.*)',
        'registrant_state_province':      'Registrant State/Province: (.*)',
        'registrant_postal_code':         'Registrant Postal Code: (.*)',
        'registrant_country':             'Registrant Country: (.+)',
        'registrant_phone':               'Registrant Phone: (.+)',
        'registrant_fax':                 'Registrant Fax: (.+)',
        'registrant_email':               'Registrant Email: (.+)',


        'admin_name':                     'Admin Name: (.+)',
        'admin_id':                       'Admin ID: (.+)',
        'admin_organization':             'Admin Organization: (.+)',
        'admin_city':                     'Admin City: (.*)',
        'admin_street':                   'Admin Street: (.*)',
        'admin_state_province':           'Admin State/Province: (.*)',
        'admin_postal_code':              'Admin Postal Code: (.*)',
        'admin_country':                  'Admin Country: (.+)',
        'admin_phone':                    'Admin Phone: (.+)',
        'admin_fax':                      'Admin Fax: (.+)',
        'admin_email':                    'Admin Email: (.+)',

        'billing_name':                   'Billing Name: (.+)',
        'billing_id':                     'Billing ID: (.+)',
        'billing_organization':           'Billing Organization: (.+)',
        'billing_city':                   'Billing City: (.*)',
        'billing_street':                 'Billing Street: (.*)',
        'billing_state_province':         'Billing State/Province: (.*)',
        'billing_postal_code':            'Billing Postal Code: (.*)',
        'billing_country':                'Billing Country: (.+)',
        'billing_phone':                  'Billing Phone: (.+)',
        'billing_fax':                    'Billing Fax: (.+)',
        'billing_email':                  'Billing Email: (.+)',

        'tech_name':                      'Tech Name: (.+)',
        'tech_id':                        'Tech ID: (.+)',
        'tech_organization':              'Tech Organization: (.+)',
        'tech_city':                      'Tech City: (.*)',
        'tech_street':                    'Tech Street: (.*)',
        'tech_state_province':            'Tech State/Province: (.*)',
        'tech_postal_code':               'Tech Postal Code: (.*)',
        'tech_country':                   'Tech Country: (.+)',
        'tech_phone':                     'Tech Phone: (.+)',
        'tech_fax':                       'Tech Fax: (.+)',
        'tech_email':                     'Tech Email: (.+)',

        'updated_date':                   'Updated Date: *(.+)',
        'creation_date':                  'Creation Date: *(.+)',
        'expiration_date':                'Registry Expiry Date: *(.+)',
        'name_servers':                   'Name Server: *(.+)'
    }

    def __init__(self, domain, text):
        if text.strip() == 'No matching record.':
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisLat(WhoisEntry):
    """Whois parser for .lat domains
        """
    regex = {
        'domain_name':                    'Domain Name: *(.+)',
        'domain_id':                      'Registry Domain ID: *(.+)',
        'status':                         'Domain Status: *(.+)',
        'whois_server':                   'Registrar WHOIS Server: *(.+)',

        'registrar_url':                  'Registrar URL: *(.+)',
        'registrar':                      'Registrar: *(.+)',
        'registrar_email':                'Registrar Abuse Contact Email: *(.+)',
        'registrar_phone':                'Registrar Abuse Contact Phone: *(.+)',

        'registrant_name':                'Registrant Name: (.+)',
        'registrant_id':                  'Registry Registrant ID: (.+)',
        'registrant_organization':        'Registrant Organization: (.+)',
        'registrant_city':                'Registrant City: (.*)',
        'registrant_street':              'Registrant Street: (.*)',
        'registrant_state_province':      'Registrant State/Province: (.*)',
        'registrant_postal_code':         'Registrant Postal Code: (.*)',
        'registrant_country':             'Registrant Country: (.+)',
        'registrant_phone':               'Registrant Phone: (.+)',
        'registrant_fax':                 'Registrant Fax: (.+)',
        'registrant_email':               'Registrant Email: (.+)',


        'admin_name':                     'Admin Name: (.+)',
        'admin_id':                       'Registry Admin ID: (.+)',
        'admin_organization':             'Admin Organization: (.+)',
        'admin_city':                     'Admin City: (.*)',
        'admin_street':                   'Admin Street: (.*)',
        'admin_state_province':           'Admin State/Province: (.*)',
        'admin_postal_code':              'Admin Postal Code: (.*)',
        'admin_country':                  'Admin Country: (.+)',
        'admin_phone':                    'Admin Phone: (.+)',
        'admin_fax':                      'Admin Fax: (.+)',
        'admin_email':                    'Admin Email: (.+)',

        'tech_name':                      'Tech Name: (.+)',
        'tech_id':                        'Registry Tech ID: (.+)',
        'tech_organization':              'Tech Organization: (.+)',
        'tech_city':                      'Tech City: (.*)',
        'tech_street':                    'Tech Street: (.*)',
        'tech_state_province':            'Tech State/Province: (.*)',
        'tech_postal_code':               'Tech Postal Code: (.*)',
        'tech_country':                   'Tech Country: (.+)',
        'tech_phone':                     'Tech Phone: (.+)',
        'tech_fax':                       'Tech Fax: (.+)',
        'tech_email':                     'Tech Email: (.+)',

        'updated_date':                   'Updated Date: *(.+)',
        'creation_date':                  'Creation Date: *(.+)',
        'expiration_date':                'Registry Expiry Date: *(.+)',
        'name_servers':                   'Name Server: *(.+)'
    }

    def __init__(self, domain, text):
        if text.strip() == 'No matching record.':
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisCn(WhoisEntry):
    """Whois parser for .cn domains
    """
    regex = {
        'domain_name':          'Domain Name: *(.+)',
        'registrar':            'Registrar: *(.+)',
        'creation_date':        'Registration Time: *(.+)',
        'expiration_date':      'Expiration Time: *(.+)',
        'name_servers':         'Name Server: *(.+)',  # list of name servers
        'status':               'Status: *(.+)',  # list of statuses
        'emails':               EMAIL_REGEX,  # list of email s
        'dnssec':               'dnssec: *([\S]+)',
        'name':                 'Registrant: *(.+)',
    }

    def __init__(self, domain, text):
        if text.strip() == 'No matching record.':
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisApp(WhoisEntry):
    """Whois parser for .app domains
    """
    regex = {
        'domain_name':          'Domain Name: *(.+)',
        'registrar':            'Registrar: *(.+)',
        'whois_server':         'Whois Server: *(.+)',
        'updated_date':         'Updated Date: *(.+)',
        'creation_date':        'Creation Date: *(.+)',
        'expiration_date':      'Expir\w+ Date: *(.+)',
        'name_servers':         'Name Server: *(.+)',  # list of name servers
        'status':               'Status: *(.+)',  # list of statuses
        'emails':               EMAIL_REGEX,  # list of email s
        'registrant_email':     'Registrant Email: *(.+)',  # registrant email
        'registrant_phone':     'Registrant Phone: *(.+)',  # registrant phone
        'dnssec':               'dnssec: *([\S]+)',
        'name':                 'Registrant Name: *(.+)',
        'org':                  'Registrant\s*Organization: *(.+)',
        'address':              'Registrant Street: *(.+)',
        'city':                 'Registrant City: *(.+)',
        'state':                'Registrant State/Province: *(.+)',
        'zipcode':              'Registrant Postal Code: *(.+)',
        'country':              'Registrant Country: *(.+)',
    }

    def __init__(self, domain, text):
        if text.strip() == 'Domain not found.':
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisMoney(WhoisEntry):
    """Whois parser for .money domains
    """
    regex = {
        'domain_name':          'Domain Name: *(.+)',
        'registrar':            'Registrar: *(.+)',
        'whois_server':         'Registrar WHOIS Server: *(.+)',
        'updated_date':         'Updated Date: *(.+)',
        'creation_date':        'Creation Date: *(.+)',
        'expiration_date':      'Registry Expiry Date: *(.+)',
        'name_servers':         'Name Server: *(.+)',  # list of name servers
        'status':               'Domain Status: *(.+)',
        'emails':               EMAIL_REGEX,  # list of emails
        'registrant_email':     'Registrant Email: *(.+)',
        'registrant_phone':     'Registrant Phone: *(.+)',
        'dnssec':               'DNSSEC: *(.+)',
        'name':                 'Registrant Name: *(.+)',
        'org':                  'Registrant Organization: *(.+)',
        'address':              'Registrant Street: *(.+)',
        'city':                 'Registrant City: *(.+)',
        'state':                'Registrant State/Province: *(.+)',
        'zipcode':              'Registrant Postal Code: *(.+)',
        'country':              'Registrant Country: *(.+)',
    }

    def __init__(self, domain, text):
        if text.strip() == 'Domain not found.':
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisAr(WhoisEntry):
    """Whois parser for .ar domains
    """
    regex = {
        'domain_name':          'domain: *(.+)',
        'registrar':            'registrar: *(.+)',
        'whois_server':         'whois: *(.+)',
        'updated_date':         'changed: *(.+)',
        'creation_date':        'created: *(.+)',
        'expiration_date':      'expire: *(.+)',
        'name_servers':         'nserver: *(.+) \(.*\)',  # list of name servers
        'status':               'Domain Status: *(.+)',
        'emails':               EMAIL_REGEX,  # list of emails
        'name':                 'name: *(.+)',
    }

    def __init__(self, domain, text):
        if text.strip() == 'El dominio no se encuentra registrado en NIC Argentina':
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisBy(WhoisEntry):
    """Whois parser for .by domains
    """
    regex = {
        'domain_name':          'Domain Name: *(.+)',
        'registrar':            'Registrar: *(.+)',
        'updated_date':         'Updated Date: *(.+)',
        'creation_date':        'Creation Date: *(.+)',
        'expiration_date':      'Expiration Date: *(.+)',
        'name_servers':         'Name Server: *(.+)',  # list of name servers
        'status':               'Domain Status: *(.+)',
        'name':                 'Person: *(.+)',
        'org':                  'Org: *(.+)',
        'registrant_country':   'Country: *(.+)',
        'registrant_address':   'Address: *(.+)',
        'registrant_phone':     'Phone: *(.+)',
    }

    def __init__(self, domain, text):
        if text.strip() == 'El dominio no se encuentra registrado en NIC Argentina':
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisCr(WhoisEntry):
    """Whois parser for .cr domains
    """
    regex = {
        'domain_name':          'domain: *(.+)',
        'registrant_name':      'registrant: *(.+)',
        'registrar':            'registrar: *(.+)',
        'updated_date':         'changed: *(.+)',
        'creation_date':        'registered: *(.+)',
        'expiration_date':      'expire: *(.+)',
        'name_servers':         'nserver: *(.+)',  # list of name servers
        'status':               'status: *(.+)',
        'contact':              'contact: *(.+)',
        'name':                 'name: *(.+)',
        'org':                  'org: *(.+)',
        'address':              'address: *(.+)',
        'phone':                'phone: *(.+)',
    }

    def __init__(self, domain, text):
        if text.strip() == 'El dominio no existe.':
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisVe(WhoisEntry):
    """Whois parser for .ve domains
    """
    regex = {
        'domain_name':           'Nombre de Dominio: *(.+)',
        'status':                'Estatus del dominio: *(.+)',

        'registrar':             'registrar: *(.+)',

        'updated_date':          'Ultima Actualización: *(.+)',
        'creation_date':         'Fecha de Creación: *(.+)',
        'expiration_date':       'Fecha de Vencimiento: *(.+)',

        'name_servers':          'Nombres de Dominio:((?:\s+- .*)*)',

        'registrant_name':       'Titular:\s*(?:.*\n){1}\s+(.*)',
        'registrant_city':       'Titular:\s*(?:.*\n){3}\s+([\s\w]*)',
        'registrant_street':     'Titular:\s*(?:.*\n){2}\s+(.*)',
        'registrant_state_province': 'Titular:\s*(?:.*\n){3}\s+.*?,(.*),',
        'registrant_country':    'Titular:\s*(?:.*\n){3}\s+.*, .+  (.*)',
        'registrant_phone':      'Titular:\s*(?:.*\n){4}\s+(\+*\d.+)',
        'registrant_email':      'Titular:\s*.*\t(.*)',

        'tech':                  'Contacto Técnico:\s*(?:.*\n){1}\s+(.*)',
        'tech_city':             'Contacto Técnico:\s*(?:.*\n){3}\s+([\s\w]*)',
        'tech_street':           'Contacto Técnico:\s*(?:.*\n){2}\s+(.*)',
        'tech_state_province':   'Contacto Técnico:\s*(?:.*\n){3}\s+.*?,(.*),',
        'tech_country':          'Contacto Técnico:\s*(?:.*\n){3}\s+.*, .+  (.*)',
        'tech_phone':            'Contacto Técnico:\s*(?:.*\n){4}\s+(\+*\d.*)\(',
        'tech_fax':              'Contacto Técnico:\s*(?:.*\n){4}\s+.*\(FAX\) (.*)',
        'tech_email':            'Contacto Técnico:\s*.*\t(.*)',

        'admin':                  'Contacto Administrativo:\s*(?:.*\n){1}\s+(.*)',
        'admin_city':             'Contacto Administrativo:\s*(?:.*\n){3}\s+([\s\w]*)',
        'admin_street':           'Contacto Administrativo:\s*(?:.*\n){2}\s+(.*)',
        'admin_state_province':   'Contacto Administrativo:\s*(?:.*\n){3}\s+.*?,(.*),',
        'admin_country':          'Contacto Administrativo:\s*(?:.*\n){3}\s+.*, .+  (.*)',
        'admin_phone':            'Contacto Administrativo:\s*(?:.*\n){4}\s+(\+*\d.*)\(',
        'admin_fax':              'Contacto Administrativo:\s*(?:.*\n){4}\s+.*\(FAX\) (.*)',
        'admin_email':            'Contacto Administrativo:\s*.*\t(.*)',


        'billing':                'Contacto de Cobranza:\s*(?:.*\n){1}\s+(.*)',
        'billing_city':           'Contacto de Cobranza:\s*(?:.*\n){3}\s+([\s\w]*)',
        'billing_street':         'Contacto de Cobranza:\s*(?:.*\n){2}\s+(.*)',
        'billing_state_province': 'Contacto de Cobranza:\s*(?:.*\n){3}\s+.*?,(.*),',
        'billing_country':        'Contacto de Cobranza:\s*(?:.*\n){3}\s+.*, .+  (.*)',
        'billing_phone':          'Contacto de Cobranza:\s*(?:.*\n){4}\s+(\+*\d.*)\(',
        'billing_fax':            'Contacto de Cobranza:\s*(?:.*\n){4}\s+.*\(FAX\) (.*)',
        'billing_email':          'Contacto de Cobranza:\s*.*\t(.*)',


    }

    def __init__(self, domain, text):
        if text.strip() == 'El dominio no existe.':
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisDo(WhoisEntry):
    """Whois parser for .do domains
    """
    regex = {
        'domain_name':          'Domain Name: *(.+)',
        'whois_server':         'WHOIS Server: *(.+)',
        'registrar':            'Registrar: *(.+)',
        'registrar_email':      'Registrar Customer Service Email: *(.+)',
        'registrar_phone':      'Registrar Phone: *(.+)',
        'registrar_address':    'Registrar Address: *(.+)',
        'registrar_country':    'Registrar Country: *(.+)',
        'status':               'Domain Status: *(.+)',  # list of statuses
        'registrant_id':        'Registrant ID: *(.+)',
        'registrant_name':      'Registrant Name: *(.+)',
        'registrant_organization': 'Registrant Organization: *(.+)',
        'registrant_address':   'Registrant Street: *(.+)',
        'registrant_city':      'Registrant City: *(.+)',
        'registrant_state_province': 'Registrant State/Province: *(.+)',
        'registrant_postal_code': 'Registrant Postal Code: *(.+)',
        'registrant_country': 'Registrant Country: *(.+)',
        'registrant_phone_number': 'Registrant Phone: *(.+)',
        'registrant_email':     'Registrant Email: *(.+)',
        'admin_id':             'Admin ID: *(.+)',
        'admin_name':           'Admin Name: *(.+)',
        'admin_organization':   'Admin Organization: *(.+)',
        'admin_address':        'Admin Street: *(.+)',
        'admin_city':           'Admin City: *(.+)',
        'admin_state_province': 'Admin State/Province: *(.+)',
        'admin_postal_code':    'Admin Postal Code: *(.+)',
        'admin_country':        'Admin Country: *(.+)',
        'admin_phone_number':   'Admin Phone: *(.+)',
        'admin_email':          'Admin Email: *(.+)',
        'billing_id':           'Billing ID: *(.+)',
        'billing_name':         'Billing Name: *(.+)',
        'billing_address':      'Billing Street: *(.+)',
        'billing_city':         'Billing City: *(.+)',
        'billing_state_province': 'Billing State/Province: *(.+)',
        'billing_postal_code':  'Billing Postal Code: *(.+)',
        'billing_country':      'Billing Country: *(.+)',
        'billing_phone_number': 'Billing Phone: *(.+)',
        'billing_email':        'Billing Email: *(.+)',
        'tech_id':              'Tech ID: *(.+)',
        'tech_name':            'Tech Name: *(.+)',
        'tech_organization':    'Tech Organization: *(.+)',
        'tech_address':         'Tech Street: *(.+)',
        'tech_city':            'Tech City: *(.+)',
        'tech_state_province':  'Tech State/Province: *(.+)',
        'tech_postal_code':     'Tech Postal Code: *(.+)',
        'tech_country':         'Tech Country: *(.+)',
        'tech_phone_number':    'Tech Phone: *(.+)',
        'tech_email':           'Tech Email: *(.+)',
        'name_servers':         'Name Server: *(.+)',  # list of name servers
        'creation_date':        'Creation Date: *(.+)',
        'expiration_date':      'Registry Expiry Date: *(.+)',
        'updated_date':         'Updated Date: *(.+)',
        'dnssec':               'DNSSEC: *(.+)'
    }

    def __init__(self, domain, text):
        if text.strip() == 'Extensión de dominio no válido.':
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisAe(WhoisEntry):
    """Whois parser for .ae domains
    """
    regex = {
        'domain_name':     'Domain Name: *(.+)',
        'status':          'Status: *(.+)',
        'registrant_name': 'Registrant Contact Name: *(.+)',
        'tech_name':       'Tech Contact Name: *(.+)',
    }

    def __init__(self, domain, text):
        if text.strip() == 'No Data Found':
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisSi(WhoisEntry):
    """Whois parser for .si domains
    """
    regex = {
        'domain_name':     'domain: *(.+)',
        'registrar':       'registrar: *(.+)',
        'name_servers':    'nameserver: *(.+)',
        'registrant_name': 'registrant: *(.+)',
        'creation_date':   'created: *(.+)',
        'expiration_date': 'expire: *(.+)',
    }

    def __init__(self, domain, text):
        if 'No entries found for the selected source(s).' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisNo(WhoisEntry):
    """Whois parser for .no domains
    """
    regex = {
        'domain_name':     'Domain Name.*:\s*(.+)',
        'creation_date':   'Additional information:\nCreated:\s*(.+)',
        'updated_date':    'Additional information:\n(?:.*\n)Last updated:\s*(.+)',
    }

    def __init__(self, domain, text):
        if 'No match' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisKZ(WhoisEntry):
    """Whois parser for .kz domains
    """
    regex = {
        'domain_name':      'Domain Name............: *(.+)',
        'registar_created': 'Registar Created: *(.+)',
        'curent_registrar': 'Current Registar: *(.+)',
        'creation_date':    'Domain created: *(.+)',
        'lats_modified':    'Last modified : *(.+)',
        'name_servers':     'server.*: *(.+)',  # list of name servers
        'status':           ' (.+?) -',  # list of statuses
        'emails':           EMAIL_REGEX,  # list of email addresses
        'org':              'Organization Name.*: *(.+)'
    }

    def __init__(self, domain, text):
        if text.strip() == 'No entries found':
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)
