# coding=utf-8
"""Test that the NICClient is choosing the right servers."""

from __future__ import unicode_literals
from __future__ import print_function
from __future__ import division
from __future__ import absolute_import
from future import standard_library
standard_library.install_aliases()
from builtins import *  # noqa
import unittest  # noqa: E402
from whois.whois import NICClient  # noqa: E402


class TestNICClient(unittest.TestCase):
    """Integration tests for the NICClient."""

    def setUp(self):
        """Create a new NICClient instance for each test."""
        self.client = NICClient()

    def test_choose_server(self):
        """Whois server choice should correspond to what's expected."""
        domain = 'рнидс.срб'
        chosen = self.client.choose_server(domain)
        suffix = domain.split('.')[-1].encode('idna').decode('utf-8')
        correct = '{}.whois-servers.net'.format(suffix)
        self.assertEqual(chosen, correct)
