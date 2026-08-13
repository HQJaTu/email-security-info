#!/usr/bin/env python3

# vim: autoindent tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python

"""Reading raw message headers: unfolding, repeated values, byte repair.

See README.md in this directory for how to run these.
"""

import unittest

from support import headers, msi


class TestMessageHeaders(unittest.TestCase):
    """Reading, unfolding and repairing raw header values."""

    def test_unfolds_continuation_lines(self):
        h = headers('Authentication-Results: mx.example.org;\n\tdkim=pass\n\nbody\n')
        self.assertEqual(h.get('Authentication-Results'),
                         ['mx.example.org; dkim=pass'])

    def test_returns_every_occurrence_in_order(self):
        h = headers('Received: first\nReceived: second\n\nbody\n')
        self.assertEqual(h.get('Received'), ['first', 'second'])

    def test_lookup_is_case_insensitive(self):
        h = headers('dkim-signature: v=1; d=example.com\n\nbody\n')
        self.assertEqual(h.get('DKIM-Signature'), ['v=1; d=example.com'])

    def test_missing_and_empty_headers_are_dropped(self):
        h = headers('X-Empty:\nX-Blank:   \n\nbody\n')
        self.assertEqual(h.get('X-Empty'), [])
        self.assertEqual(h.get('X-Absent'), [])
        self.assertEqual(h.get('X-Blank'), [])

    def test_first_returns_none_when_absent(self):
        h = headers('From: a@b.test\n\nbody\n')
        self.assertEqual(h.first('From'), 'a@b.test')
        self.assertIsNone(h.first('DKIM-Signature'))

    def test_raw_utf8_bytes_are_recovered(self):
        # Non-ASCII bytes in a header would otherwise stringify to U+FFFD.
        h = headers(b'Subject: caf\xc3\xa9\n\nbody\n')
        self.assertEqual(h.get('Subject'), ['café'])

    def test_undecodable_bytes_stay_printable(self):
        h = headers(b'Subject: caf\xe9\n\nbody\n')
        value = h.first('Subject')
        self.assertEqual(value, 'caf�')
        value.encode('utf-8')  # must not raise

    def test_body_is_not_parsed_as_headers(self):
        h = headers('From: a@b.test\n\nFrom: body@spoof.test\n')
        self.assertEqual(h.get('From'), ['a@b.test'])


class TestHelpers(unittest.TestCase):
    """The small string helpers."""

    def test_unfold_collapses_folding_whitespace_only(self):
        self.assertEqual(msi._unfold('a\r\n\tb\n  c'), 'a b c')
        self.assertEqual(msi._unfold('  a  b  '), 'a  b')

    def test_strip_formatting_removes_control_and_format_chars(self):
        # U+202E right-to-left override, U+200B zero width space, U+0007 bell.
        self.assertEqual(msi._strip_formatting('Pay‮Pal​\x07'), 'PayPal')
        self.assertEqual(msi._strip_formatting('Ünicode ok'), 'Ünicode ok')

    def test_gettext_substitutes_variables(self):
        self.assertEqual(msi.i18n_gettext('notaligned', {'from': 'example.com'}),
                         'does not match From (example.com)')

    def test_gettext_falls_back_to_the_key(self):
        self.assertEqual(msi.i18n_gettext('nosuchlabel'), 'nosuchlabel')


if __name__ == '__main__':
    unittest.main(verbosity=2)
