#!/usr/bin/env python3

# vim: autoindent tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python

"""Rendering the result as a plain-text report, and the colour decision.

See README.md in this directory for how to run these.
"""

import io
import os
import sys
import unittest
from unittest import mock

from support import (FAIL_EML, PASS_EML, UNALIGNED_EML, UNVERIFIED_EML, headers,
                     info, msi)


class TestFormatReport(unittest.TestCase):
    """
    Rendering the result as plain text.
    """

    def report(self, message, color=False, **config):
        return msi.format_report(info(**config).evaluate_headers(headers(message)), color)

    def test_headline_carries_the_status_and_summary(self):
        first = self.report(PASS_EML).splitlines()[0]
        self.assertEqual(first, 'Message Security: ✓ PASS Sender authentication passed.')

    def test_rows_and_raw_headers_are_labelled(self):
        lines = self.report(PASS_EML, extra_headers=['X-Spam-Status']).splitlines()
        self.assertIn('Authentication results:', lines)
        self.assertTrue(any('SPF' in line and 'PASS — example.com' in line for line in lines))
        self.assertTrue(any(line.strip().startswith('X-Spam-Status') for line in lines))

    def test_the_dkim_sentence_matches_the_dkim_verdict(self):
        # One sentence per value the DKIM verdict can take, so a warning never
        # gets described in the words of a failure.
        for message, key in ((PASS_EML, 'frommarkerpass'),
                             (UNALIGNED_EML, 'frommarkerwarn'),
                             (FAIL_EML, 'frommarkerfail'),
                             (UNVERIFIED_EML, 'frommarkerunknown')):
            with self.subTest(key=key):
                self.assertIn(msi.i18n_gettext(key), self.report(message))

    def test_multiline_values_are_aligned_under_the_value_column(self):
        lines = self.report(UNALIGNED_EML).splitlines()
        dkim = next(i for i, line in enumerate(lines) if 'DKIM' in line)
        note = lines[dkim + 1]
        self.assertEqual(note.strip(), 'does not match From (bank.example)')
        self.assertEqual(note.index('does'), lines[dkim].index('PASS'))

    def test_color_is_opt_in(self):
        self.assertNotIn('\033[', self.report(FAIL_EML))
        self.assertIn('\033[31m', self.report(FAIL_EML, color=True))

    def test_color_does_not_shift_the_columns(self):
        plain = self.report(PASS_EML).splitlines()
        colored = self.report(PASS_EML, color=True).splitlines()
        strip = lambda line: line.replace('\033[32m', '').replace('\033[0m', '')  # noqa: E731
        self.assertEqual([strip(line) for line in colored], plain)

    def test_every_mechanism_row_carries_its_own_glyph(self):
        # The reader can follow the headline down to the row that produced it,
        # which only works if each mechanism draws its own verdict's glyph.
        lines = self.report(UNALIGNED_EML).splitlines()
        glyphs = {line.split()[0]: line.split()[1] for line in lines
                  if line.startswith('  ') and line.split()[0] in ('SPF', 'DKIM', 'DMARC')}
        self.assertEqual(glyphs, {'SPF': '!', 'DKIM': '!', 'DMARC': '·'})
        self.assertTrue(lines[0].startswith('Message Security: !'))

    def test_rows_without_a_verdict_align_with_the_ones_that_have_glyphs(self):
        lines = self.report(PASS_EML).splitlines()
        sender = next(line for line in lines if 'Alice' in line)
        spf = next(line for line in lines if 'SPF' in line)
        self.assertEqual(sender.index('Alice'), spf.index('PASS'))


class TestReportRows(unittest.TestCase):
    """The display rows the report is built from, and their order."""

    def rows(self, message, **config):
        return msi.report_rows(info(**config).evaluate_headers(headers(message)))

    def test_the_sender_leads_and_the_transport_trails(self):
        self.assertEqual([label for label, _, _ in self.rows(PASS_EML)],
                         ['From', 'SPF', 'DKIM', 'DMARC', 'Transport (TLS)'])

    def test_disabled_checks_drop_their_rows(self):
        self.assertEqual([label for label, _, _ in
                          self.rows(PASS_EML, check_spf=False, check_dmarc=False,
                                    check_tls=False)],
                         ['From', 'DKIM'])

    def test_every_mechanism_row_carries_its_verdict(self):
        # And only the mechanisms: the sender and the transport are descriptive,
        # not verdicts, so they carry none.
        self.assertEqual([(label, verdict) for label, _, verdict in self.rows(UNALIGNED_EML)],
                         [('From', None), ('SPF', 'warn'), ('DKIM', 'warn'),
                          ('DMARC', 'none'), ('Transport (TLS)', None)])

    def test_values_are_the_displayed_strings(self):
        rows = {label: value for label, value, _ in self.rows(PASS_EML)}
        self.assertEqual(rows['From'], 'Alice Example <alice@example.com>')
        self.assertEqual(rows['SPF'], 'PASS — example.com')
        self.assertEqual(rows['DKIM'], 'PASS — example.com')
        self.assertEqual(rows['Transport (TLS)'], 'Encrypted — TLSv1.3')


class TestUseColor(unittest.TestCase):
    """
    The --color decision.
    """

    def test_explicit_choices(self):
        self.assertTrue(msi._report_use_color('always'))
        self.assertFalse(msi._report_use_color('never'))

    def test_auto_follows_the_tty(self):
        with mock.patch.object(sys, 'stdout', io.StringIO()):
            self.assertFalse(msi._report_use_color('auto'))

    def test_auto_honours_no_color(self):
        stdout = mock.Mock(isatty=lambda: True)
        with mock.patch.object(sys, 'stdout', stdout), \
                mock.patch.dict(os.environ, {'NO_COLOR': '1'}):
            self.assertFalse(msi._report_use_color('auto'))
        with mock.patch.object(sys, 'stdout', stdout), \
                mock.patch.dict(os.environ, {}, clear=True):
            self.assertTrue(msi._report_use_color('auto'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
