#!/usr/bin/env python3

# vim: autoindent tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python

"""Formatting one SPF / DKIM / DMARC / TLS result into its displayed line.

See README.md in this directory for how to run these.
"""

import unittest

from support import info, msi


class TestFormatting(unittest.TestCase):
    """The result lines shown for each method."""

    def test_format_method_with_and_without_a_domain(self):
        self.assertEqual(info().format_method({'result': 'pass', 'domain': 'a.test'}),
                         'PASS — a.test')
        self.assertEqual(info().format_method({'result': 'neutral', 'domain': None}), 'NEUTRAL')

    def test_format_method_without_a_result(self):
        self.assertEqual(info().format_method(None), msi.i18n_gettext('notpresent'))

    def test_format_dkim_aligned_pass_has_no_note(self):
        self.assertEqual(
            info().format_dkim({'result': 'pass', 'domain': 'example.com'}, None, 'example.com'),
            'PASS — example.com')

    def test_format_dkim_unaligned_pass_notes_the_mismatch_on_its_own_line(self):
        self.assertEqual(
            info().format_dkim({'result': 'pass', 'domain': 'mailer.net'}, None, 'bank.example'),
            'PASS — mailer.net\ndoes not match From (bank.example)')

    def test_format_dkim_non_pass_notes_alignment_in_parentheses(self):
        self.assertEqual(
            info().format_dkim({'result': 'fail', 'domain': 'a.test'}, None, 'a.test'),
            'FAIL — a.test (aligned with From)')
        self.assertEqual(
            info().format_dkim({'result': 'fail', 'domain': 'a.test'}, None, 'b.test'),
            'FAIL — a.test (does not match From (b.test))')

    def test_format_dkim_falls_back_to_the_signature_domain(self):
        self.assertEqual(info().format_dkim({'result': 'pass', 'domain': None},
                                            'example.com', 'example.com'),
                         'PASS — example.com')

    def test_format_dkim_reports_an_unverified_signature(self):
        self.assertEqual(info().format_dkim(None, 'news.example.com', 'news.example.com'),
                         msi.i18n_gettext('unverified') + ' — news.example.com')
        self.assertEqual(info().format_dkim(None, None, 'a.test'), msi.i18n_gettext('notpresent'))

    def test_no_alignment_note_without_both_domains(self):
        self.assertEqual(info().dkim_alignment_note('fail', 'a.test', None), '')
        self.assertEqual(info().dkim_alignment_note('fail', None, 'a.test'), '')

    def test_format_tls(self):
        self.assertEqual(msi.MessageSecurityInfo.format_tls(None), msi.i18n_gettext('tlsunknown'))
        self.assertEqual(msi.MessageSecurityInfo.format_tls({'encrypted': False, 'detail': None}),
                         msi.i18n_gettext('tlsplain'))
        self.assertEqual(msi.MessageSecurityInfo.format_tls({'encrypted': True, 'detail': None}),
                         msi.i18n_gettext('tlsencrypted'))
        self.assertEqual(msi.MessageSecurityInfo.format_tls({'encrypted': True,
                                                             'detail': 'TLSv1.3'}),
                         msi.i18n_gettext('tlsencrypted') + ' — TLSv1.3')


if __name__ == '__main__':
    unittest.main(verbosity=2)
