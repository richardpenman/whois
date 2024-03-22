# coding=utf-8

from __future__ import unicode_literals
from __future__ import print_function
from __future__ import division
from __future__ import absolute_import
from future import standard_library

standard_library.install_aliases()
from builtins import *
import unittest
from whois.whois import NICClient


class TestNICClient(unittest.TestCase):
    def setUp(self):
        self.client = NICClient()

    def test_choose_server(self):
        domain = "рнидс.срб"
        chosen = self.client.choose_server(domain)
        correct = "whois.rnids.rs"
        self.assertEqual(chosen, correct)
