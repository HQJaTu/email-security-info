#!/usr/bin/env python3

# vim: autoindent tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python

"""Decoding, sanitizing and displaying the visible sender (the From header).

See README.md in this directory for how to run these.
"""

import unittest

from support import FAIL_EML, PASS_EML, UNALIGNED_EML, headers, info


class TestFromHeader(unittest.TestCase):
    """Decoding, sanitizing and displaying the visible sender."""

    def test_display_name_and_address(self):
        self.assertEqual(info().from_parts(headers(PASS_EML)),
                         {'name': 'Alice Example', 'addr': 'alice@example.com'})
        self.assertEqual(info().from_address(headers(PASS_EML)),
                         'Alice Example <alice@example.com>')
        self.assertEqual(info().from_domain(headers(PASS_EML)), 'example.com')

    def test_encoded_words_are_decoded(self):
        self.assertEqual(info().from_parts(headers(UNALIGNED_EML))['name'], 'Bank Support')

    def test_bidi_override_is_stripped_from_the_name(self):
        parts = info().from_parts(headers(FAIL_EML))
        self.assertEqual(parts, {'name': 'PayPal', 'addr': 'billing@evil.test'})

    def test_address_only_from_has_no_name(self):
        h = headers('From: news@News.Example.com\n\nbody\n')
        self.assertEqual(info().from_parts(h), {'name': '', 'addr': 'news@news.example.com'})
        self.assertEqual(info().from_address(h), 'news@news.example.com')

    def test_a_name_repeating_the_address_is_dropped(self):
        h = headers('From: alice@example.com <alice@example.com>\n\nbody\n')
        self.assertEqual(info().from_parts(h)['name'], '')
        self.assertEqual(info().from_address(h), 'alice@example.com')

    def test_only_the_first_address_is_used(self):
        h = headers('From: Alice <alice@example.com>, Bob <bob@other.test>\n\nbody\n')
        self.assertEqual(info().from_domain(h), 'example.com')

    def test_no_from_header(self):
        h = headers('Subject: x\n\nbody\n')
        self.assertIsNone(info().from_parts(h))
        self.assertIsNone(info().from_address(h))
        self.assertIsNone(info().from_domain(h))

    def test_unparsable_from_is_salvaged_by_regex(self):
        h = headers('From: alice(at)example.com <mangled>\n\nbody\n')
        self.assertIsNone(info().from_domain(h))

    def test_address_without_a_domain_has_no_from_domain(self):
        h = headers('From: undisclosed-recipients:;\n\nbody\n')
        self.assertIsNone(info().from_domain(h))

    def test_raw_utf8_display_name(self):
        h = headers(b'From: J\xc3\xbcrgen M\xc3\xbcller <jm@example.com>\n\nbody\n')
        self.assertEqual(info().from_parts(h)['name'], 'Jürgen Müller')


if __name__ == '__main__':
    unittest.main(verbosity=2)
