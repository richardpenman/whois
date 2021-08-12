# coding=utf-8
"""Unit tests for extract_domain."""

from __future__ import unicode_literals
from __future__ import print_function
from __future__ import division
from __future__ import absolute_import
from future import standard_library
standard_library.install_aliases()
from builtins import *  # noqa
import unittest  # noqa: E402
from whois import extract_domain  # noqa: E402


class TestExtractDomain(unittest.TestCase):
    """Tests for extract_domain."""

    def test_simple_ascii_domain(self):
        """Query is the second-level domain."""
        url = 'google.com'
        domain = url
        self.assertEqual(domain, extract_domain(url))

    def test_ascii_with_schema_path_and_query(self):
        """Query is a URL."""
        url = 'https://www.google.com/search?q=why+is+domain+whois+such+a+mess'
        domain = 'google.com'
        self.assertEqual(domain, extract_domain(url))

    def test_simple_unicode_domain(self):
        """Query is a URL with a unicode domain with ascii TLD."""
        url = 'http://нарояци.com/'
        domain = 'нарояци.com'
        self.assertEqual(domain, extract_domain(url))

    def test_unicode_domain_and_tld(self):
        """Query is a URL with a unicode domain and TLD in unicode."""
        url = 'http://россия.рф/'
        domain = 'россия.рф'
        self.assertEqual(domain, extract_domain(url))

    def test_ipv6(self):
        """Query is an ipv6, reponse should be the domain of its PTR."""
        url = '2607:f8b0:4006:802::200e'
        domain = '1e100.net'
        # double extract_domain() so we avoid possibly changing hostnames like lga34s12-in-x0e.1e100.net
        self.assertEqual(domain, extract_domain(extract_domain(url)))

    def test_ipv4(self):
        """Query is an ipv4, reponse should be the domain of its PTR."""
        url = '172.217.3.110'
        domain = '1e100.net'
        # double extract_domain() so we avoid possibly changing hostnames like lga34s18-in-f14.1e100.net
        self.assertEqual(domain, extract_domain(extract_domain(url)))

    def test_second_level_domain(self):
        """Query is a TLD which only has second-level domains."""
        url = 'google.co.za'
        domain = url
        self.assertEqual(domain, extract_domain(url))
