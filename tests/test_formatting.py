#!/usr/bin/env python3

# vim: autoindent tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python

"""Turning one security finding — or the TLS info — into its displayed line.

See README.md in this directory for how to run these.
"""

import unittest

from support import msi


def entry(**fields) -> dict:
    """A security finding carrying the given fields, the rest left neutral."""
    return {'present': True, 'verified': True, 'status': None, 'domain': None,
            'aligned': None, 'verdict': 'unknown', 'marker': None,
            'description': None, **fields}


class TestSecurityLine(unittest.TestCase):
    """The line shown for one SPF / DKIM / DMARC finding."""

    def test_a_result_with_and_without_a_domain(self):
        self.assertEqual(msi.security_line(entry(status='PASS', domain='a.test')),
                         'PASS — a.test')
        self.assertEqual(msi.security_line(entry(status='NEUTRAL')), 'NEUTRAL')

    def test_no_result_at_all(self):
        self.assertEqual(
            msi.security_line(entry(status=None, description=msi.i18n_gettext('notpresent'))),
            msi.i18n_gettext('notpresent'))

    def test_an_unverified_signature_keeps_its_domain(self):
        self.assertEqual(
            msi.security_line(entry(status=None, verified=False, domain='news.example.com',
                                    description=msi.i18n_gettext('unverified'))),
            msi.i18n_gettext('unverified') + ' — news.example.com')

    def test_an_aligned_pass_shows_no_note(self):
        self.assertEqual(
            msi.security_line(entry(status='PASS', domain='example.com', aligned=True,
                                    description=msi.i18n_gettext('aligned'))),
            'PASS — example.com')

    def test_an_unaligned_pass_notes_the_mismatch_on_its_own_line(self):
        self.assertEqual(
            msi.security_line(entry(status='PASS', domain='mailer.net', aligned=False,
                                    description='does not match From (bank.example)')),
            'PASS — mailer.net\ndoes not match From (bank.example)')

    def test_a_non_pass_notes_alignment_in_parentheses(self):
        self.assertEqual(
            msi.security_line(entry(status='FAIL', domain='a.test', aligned=True,
                                    description=msi.i18n_gettext('aligned'))),
            'FAIL — a.test (aligned with From)')
        self.assertEqual(
            msi.security_line(entry(status='FAIL', domain='a.test', aligned=False,
                                    description='does not match From (b.test)')),
            'FAIL — a.test (does not match From (b.test))')

    def test_a_result_without_a_description_stands_alone(self):
        self.assertEqual(msi.security_line(entry(status='SOFTFAIL', domain='a.test')),
                         'SOFTFAIL — a.test')


class TestFormatTls(unittest.TestCase):
    """The transport-encryption line."""

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
