# coding=utf-8

from __future__ import unicode_literals
from __future__ import print_function
from __future__ import division
from __future__ import absolute_import
from future import standard_library
standard_library.install_aliases()
from builtins import *
import unittest
from whois import whois


class TestQuery(unittest.TestCase):
    def test_simple_ascii_domain(self):
        domain = 'google.com'
        whois(domain)

    def test_simple_unicode_domain(self):
        domain = 'нарояци.com'
        whois(domain)

    def test_unicode_domain_and_tld(self):
        domain = 'россия.рф'
        whois(domain)

    def test_ipv4(self):
        """ Verify ipv4 addresses. """
        domain = '172.217.3.110'
        whois_results = whois(domain)
        if isinstance(whois_results['domain_name'], list):
            domain_names = [_.lower() for _ in whois_results['domain_name']]
        else:
            domain_names = [whois_results['domain_name'].lower()]

        self.assertIn('1e100.net', domain_names)
        self.assertIn('ns1.google.com', [_.lower() for _ in whois_results['name_servers']])

    def test_ipv6(self):
        """ Verify ipv6 addresses. """
        domain = '2607:f8b0:4006:802::200e'
        whois_results = whois(domain)
        if isinstance(whois_results['domain_name'], list):
            domain_names = [_.lower() for _ in whois_results['domain_name']]
        else:
            domain_names = [whois_results['domain_name'].lower()]

        self.assertIn('1e100.net', domain_names)
        self.assertIn('ns1.google.com', [_.lower() for _ in whois_results['name_servers']])
