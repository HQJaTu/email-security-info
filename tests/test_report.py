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

    def test_the_from_marker_sentence_is_included(self):
        self.assertIn(msi.i18n_gettext('frommarkerpass'), self.report(PASS_EML))
        self.assertIn(msi.i18n_gettext('frommarkernone'), self.report(UNVERIFIED_EML))

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

    def test_the_marker_column_exists_only_when_a_row_has_a_marker(self):
        def value_column(report):
            return next(line.index('Alice') for line in report.splitlines() if 'Alice' in line)

        without = self.report(PASS_EML, check_dkim=False)
        self.assertEqual(value_column(self.report(PASS_EML)) - value_column(without), 2)
        # The glyph in the headline is not part of a row.
        self.assertNotIn('✓', without.split('\n', 1)[1])


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

    def test_only_the_dkim_row_carries_a_marker(self):
        self.assertEqual([(label, marker) for label, _, marker in self.rows(FAIL_EML)
                          if marker],
                         [('DKIM', 'fail')])

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
