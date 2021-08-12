# coding=utf-8
"""Integration tests for queries on live whois servers."""

from __future__ import unicode_literals
from __future__ import print_function
from __future__ import division
from __future__ import absolute_import
from future import standard_library
standard_library.install_aliases()
from builtins import *  # noqa
import unittest  # noqa: E402
from whois import whois  # noqa: E402


class TestQuery(unittest.TestCase):
    """Test case for integration tests on the library."""

    def test_simple_ascii_domain(self):
        """Grab domain name in ascii.

        It should not raise an exception.
        """
        domain = 'google.com'
        whois(domain)

    def test_simple_unicode_domain(self):
        """Grab domain name in unicode with ascii TLD.

        It should not raise an exception.
        """
        domain = 'нарояци.com'
        whois(domain)

    def test_unicode_domain_and_tld(self):
        """Grab domain name in unicode with TLD in unicode.

        It should not raise an exception.
        """
        domain = 'россия.рф'
        whois(domain)

    def test_ipv4(self):
        """Grab information about an ipv4 address and verify results."""
        domain = '172.217.3.110'
        whois_results = whois(domain)
        if isinstance(whois_results['domain_name'], list):
            domain_names = [_.lower() for _ in whois_results['domain_name']]
        else:
            domain_names = [whois_results['domain_name'].lower()]

        self.assertIn('1e100.net', domain_names)
        self.assertIn('ns1.google.com', [_.lower() for _ in whois_results['name_servers']])

    def test_ipv6(self):
        """Grab information about an ipv6 address and verify results."""
        domain = '2607:f8b0:4006:802::200e'
        whois_results = whois(domain)
        if isinstance(whois_results['domain_name'], list):
            domain_names = [_.lower() for _ in whois_results['domain_name']]
        else:
            domain_names = [whois_results['domain_name'].lower()]

        self.assertIn('1e100.net', domain_names)
        self.assertIn('ns1.google.com', [_.lower() for _ in whois_results['name_servers']])
