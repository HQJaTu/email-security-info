#!/usr/bin/env python3

# vim: autoindent tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python

"""Relaxed From-alignment and the DKIM signing domain it is compared against.

See README.md in this directory for how to run these.
"""

import unittest

from support import msi


class TestAligned(unittest.TestCase):
    """Relaxed From-alignment."""

    def test_equal_domains_are_aligned(self):
        self.assertTrue(msi.MessageSecurityInfo._aligned('example.com', 'EXAMPLE.com'))

    def test_subdomain_either_way_is_aligned(self):
        self.assertTrue(msi.MessageSecurityInfo._aligned('example.com', 'mail.example.com'))
        self.assertTrue(msi.MessageSecurityInfo._aligned('mail.example.com', 'example.com'))

    def test_unrelated_domains_are_not_aligned(self):
        self.assertFalse(msi.MessageSecurityInfo._aligned('mailer.net', 'bank.example'))

    def test_a_shared_suffix_is_not_enough(self):
        self.assertFalse(msi.MessageSecurityInfo._aligned('notexample.com', 'example.com'))

    def test_missing_side_is_not_aligned(self):
        self.assertFalse(msi.MessageSecurityInfo._aligned(None, 'example.com'))
        self.assertFalse(msi.MessageSecurityInfo._aligned('example.com', None))
        self.assertFalse(msi.MessageSecurityInfo._aligned('', ''))


class TestSignatureDomain(unittest.TestCase):
    """The d= tag of a raw DKIM-Signature."""

    def test_reads_the_signing_domain(self):
        self.assertEqual(
            msi.MessageSecurityInfo._signature_domain('v=1; a=rsa-sha256; d=Example.COM; s=k1'),
            'example.com')

    def test_tolerates_whitespace_around_the_tag(self):
        self.assertEqual(msi.MessageSecurityInfo._signature_domain('v=1;  d = example.com ; s=k1'),
                         'example.com')

    def test_accepts_the_tag_first(self):
        self.assertEqual(msi.MessageSecurityInfo._signature_domain('d=example.com; v=1'),
                         'example.com')

    def test_is_not_confused_by_other_tags_ending_in_d(self):
        self.assertEqual(msi.MessageSecurityInfo._signature_domain('v=1; bh=abcd=; d=a.test'),
                         'a.test')

    def test_missing_tag_is_none(self):
        self.assertIsNone(msi.MessageSecurityInfo._signature_domain('v=1; a=rsa-sha256; s=k1'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
